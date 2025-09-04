package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ServerConfig struct {
	ListenAddr    string           `json:"listen_addr"`
	AuthToken     string           `json:"auth_token"`
	AdguardURL    string           `json:"adguard_url"`
	AdguardToken  string           `json:"adguard_token"`
	InternalCIDRs []string         `json:"internal_cidrs"`
	AllowOutPorts []int            `json:"allow_out_ports"`
	DoHHosts      []string         `json:"doh_hosts"`
	LANPolicy     map[string][]int `json:"lan_policy"`
}

type IngestConn struct {
	Proto string `json:"proto"`
	Laddr string `json:"laddr"`
	Lport int    `json:"lport"`
	Raddr string `json:"raddr"`
	Rport int    `json:"rport"`
	Pid   int    `json:"pid"`
	Exe   string `json:"exe"`
}

type IngestPayload struct {
	Host     string       `json:"host"`
	Tags     []string     `json:"tags"`
	TS       int64        `json:"ts"`
	Conns    []IngestConn `json:"conns"`
	IP4      string       `json:"ip4"`
	IP6      string       `json:"ip6"`
	Errors   []string     `json:"errors"`
	Observed []struct {
		Proto   string `json:"proto"`
		Laddr   string `json:"laddr"`
		Lport   int    `json:"lport"`
		Raddr   string `json:"raddr"`
		Rport   int    `json:"rport"`
		Pid     int    `json:"pid"`
		Exe     string `json:"exe"`
		FirstTs int64  `json:"first_ts"` // ms
		LastTs  int64  `json:"last_ts"`  // ms
		Samples int    `json:"samples"`
	} `json:"observed"`
}

type NodeState struct {
	Host   string       `json:"host"`
	Tags   []string     `json:"tags"`
	IP4    string       `json:"ip4"`
	IP6    string       `json:"ip6"`
	LastTS int64        `json:"last_ts"`
	Conns  []IngestConn `json:"conns"`
}

type Event struct {
	TS     int64  `json:"ts"`
	Host   string `json:"host"`
	Level  string `json:"level"`
	Rule   string `json:"rule"`
	Detail string `json:"detail"`
	Dest   string `json:"dest"`
	Exe    string `json:"exe"`
}

type Server struct {
	cfg      ServerConfig
	nodes    map[string]*NodeState
	events   []Event
	intCIDR  []*net.IPNet
	allowOut map[int]bool
	dohHost  map[string]bool

	mu      sync.RWMutex
	uiIndex string // chemin absolu vers index.html si trouvé
}

// ---- config parser (YAML minimal) ----

func parseListStr(val string) []string {
	val = strings.TrimSpace(strings.Trim(val, "[]"))
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.ToLower(strings.TrimSpace(strings.Trim(p, `"'`))))
	}
	return out
}

func parseListInt(val string) []int {
	val = strings.TrimSpace(strings.Trim(val, "[]"))
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if n, e := strconv.Atoi(strings.TrimSpace(p)); e == nil {
			out = append(out, n)
		}
	}
	return out
}

func loadServerConfig(path string) (ServerConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ServerConfig{}, err
	}
	cfg := ServerConfig{
		ListenAddr:    ":8080",
		InternalCIDRs: []string{"127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fd00::/8"},
		AllowOutPorts: []int{80, 443, 853, 22, 123},
		LANPolicy:     map[string][]int{},
	}
	section := ""
	for _, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "lan_policy:") {
			section = "lan_policy"
			continue
		}
		if section == "lan_policy" {
			if strings.Contains(ln, ":") {
				parts := strings.SplitN(ln, ":", 2)
				cfg.LANPolicy[strings.TrimSpace(parts[0])] = parseListInt(parts[1])
				continue
			}
			section = ""
			continue
		}
		if !strings.Contains(ln, ":") {
			continue
		}
		kv := strings.SplitN(ln, ":", 2)
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(strings.Trim(kv[1], `"'`))
		switch key {
		case "listen_addr":
			cfg.ListenAddr = val
		case "auth_token":
			cfg.AuthToken = val
		case "adguard_url":
			cfg.AdguardURL = val
		case "adguard_token":
			cfg.AdguardToken = val
		case "internal_cidrs":
			if x := parseListStr(kv[1]); x != nil {
				cfg.InternalCIDRs = x
			}
		case "allow_out_ports":
			if x := parseListInt(kv[1]); x != nil {
				cfg.AllowOutPorts = x
			}
		case "doh_hosts":
			if x := parseListStr(kv[1]); x != nil {
				cfg.DoHHosts = x
			}
		}
	}
	return cfg, nil
}

func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		cfg:      cfg,
		nodes:    map[string]*NodeState{},
		events:   []Event{},
		allowOut: map[int]bool{},
		dohHost:  map[string]bool{},
	}
	for _, c := range cfg.InternalCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			s.intCIDR = append(s.intCIDR, n)
		}
	}
	for _, p := range cfg.AllowOutPorts {
		s.allowOut[p] = true
	}
	for _, h := range cfg.DoHHosts {
		s.dohHost[strings.ToLower(h)] = true
	}
	s.uiIndex = resolveUIIndex()
	if s.uiIndex != "" {
		log.Println("dashboard index:", s.uiIndex)
	} else {
		log.Println("dashboard index not found; root will show a minimal text page")
	}
	return s
}

func resolveUIIndex() string {
	// 1) override via env
	if p := os.Getenv("CONNWATCH_UI_INDEX"); p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	// 2) chemins relatifs au binaire
	if exe, err := os.Executable(); err == nil {
		d0 := filepath.Dir(exe)                              // .../server/cmd/server
		d1 := filepath.Dir(d0)                               // .../server/cmd
		d2 := filepath.Dir(d1)                               // .../server
		d3 := filepath.Dir(d2)                               // .../
		cands := []string{
			filepath.Join(d2, "web", "static", "index.html"),           // .../server/web/static/index.html
			filepath.Join(d3, "server", "web", "static", "index.html"), // .../server/web/static/index.html (depuis racine)
		}
		for _, p := range cands {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}
	// 3) chemins relatifs au CWD (dev)
	for _, p := range []string{
		filepath.Join("server", "web", "static", "index.html"),
		filepath.Join("web", "static", "index.html"),
	} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func (s *Server) isInternal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	for _, n := range s.intCIDR {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func (s *Server) addEvent(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	if len(s.events) > 4000 {
		s.events = s.events[len(s.events)-4000:]
	}
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if "Bearer "+s.cfg.AuthToken != r.Header.Get("Authorization") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var pl IngestPayload
	if err := json.NewDecoder(r.Body).Decode(&pl); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	// update node state
	s.mu.Lock()
	s.nodes[pl.Host] = &NodeState{
		Host:   pl.Host,
		Tags:   pl.Tags,
		IP4:    pl.IP4,
		IP6:    pl.IP6,
		LastTS: pl.TS,
		Conns:  pl.Conns,
	}
	s.mu.Unlock()

	now := time.Now().Unix()

	// 1) Back-compat: anciens agents (instantané)
	for _, c := range pl.Conns {
		if c.Raddr == "" || c.Raddr == "0.0.0.0" || c.Rport == 0 {
			continue
		}
		dest := fmt.Sprintf("%s:%d", c.Raddr, c.Rport)
		internal := s.isInternal(c.Raddr)

		level := "GREEN"
		rule := "allow.default"
		if !internal && c.Proto == "tcp" && !s.allowOut[c.Rport] {
			level, rule = "ORANGE", "out.port.unexpected"
		}
		if !internal && c.Rport == 853 {
			level, rule = "ORANGE", "dns.override.dot"
		}
		if internal && (c.Rport == 22 || c.Rport == 445 || c.Rport == 3389) {
			level, rule = "RED", "lateral.admin.protocol"
		}
		if level != "GREEN" {
			s.addEvent(Event{
				TS:     now,
				Host:   pl.Host,
				Level:  level,
				Rule:   rule,
				Detail: fmt.Sprintf("%s:%d -> %s", c.Laddr, c.Lport, dest),
				Dest:   dest,
				Exe:    c.Exe,
			})
		}
	}

	// 2) Nouveaux agents: observed[] (zéro-perte)
	for _, o := range pl.Observed {
		if o.Raddr == "" || o.Raddr == "0.0.0.0" || o.Rport == 0 {
			continue
		}
		dest := fmt.Sprintf("%s:%d", o.Raddr, o.Rport)
		internal := s.isInternal(o.Raddr)

		level := "GREEN"
		rule := "allow.default"
		if !internal && o.Proto == "tcp" && !s.allowOut[o.Rport] {
			level, rule = "ORANGE", "out.port.unexpected"
		}
		if !internal && o.Rport == 853 {
			level, rule = "ORANGE", "dns.override.dot"
		}
		if internal && (o.Rport == 22 || o.Rport == 445 || o.Rport == 3389) {
			level, rule = "RED", "lateral.admin.protocol"
		}
		if level != "GREEN" {
			ts := now
			if o.LastTs > 0 {
				ts = o.LastTs / 1000 // ms → s
			}
			dur := int((o.LastTs - o.FirstTs) / 1000)
			s.addEvent(Event{
				TS:     ts,
				Host:   pl.Host,
				Level:  level,
				Rule:   rule,
				Detail: fmt.Sprintf("%s:%d -> %s (durée=%ds, samples=%d)", o.Laddr, o.Lport, dest, dur, o.Samples),
				Dest:   dest,
				Exe:    o.Exe,
			})
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*NodeState, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		since, _ := strconv.ParseInt(sinceStr, 10, 64)
		out := []Event{}
		for _, e := range s.events {
			if e.TS >= since {
				out = append(out, e)
			}
		}
		json.NewEncoder(w).Encode(out)
		return
	}
	json.NewEncoder(w).Encode(s.events)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]any{
		"nodes":  len(s.nodes),
		"events": len(s.events),
		"now":    time.Now().Unix(),
	})
}

type statusRecorder struct{ http.ResponseWriter; code int }

func (sr *statusRecorder) WriteHeader(statusCode int) {
	sr.code = statusCode
	sr.ResponseWriter.WriteHeader(statusCode)
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		t0 := time.Now()
		next.ServeHTTP(rec, r)
		d := time.Since(t0)
		log.Printf("%s %s -> %d %dms", r.Method, r.URL.Path, rec.code, int(math.Round(float64(d.Milliseconds()))))
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if s.uiIndex != "" && (r.URL.Path == "/" || r.URL.Path == "/index.html") {
		http.ServeFile(w, r, s.uiIndex)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "connwatch server up")
	fmt.Fprintln(w, "GET /api/health  /api/nodes  /api/events?since=UNIX_TS")
}

func main() {
	cfgPath := "server/config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	cfg, err := loadServerConfig(cfgPath)
	if err != nil {
		log.Fatal("config error:", err)
	}
	if cfg.AuthToken == "" {
		log.Fatal("auth_token required in server/config.yaml")
	}

	s := NewServer(cfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", s.handleIngest)
	mux.HandleFunc("/api/nodes", s.handleNodes)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/", s.handleRoot)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           logRequest(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Println("connwatch server listening on", cfg.ListenAddr)
	log.Fatal(srv.ListenAndServe())
}
