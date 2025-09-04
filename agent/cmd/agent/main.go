package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AgentConfig struct {
	ServerURL      string   `json:"server_url"`
	AuthToken      string   `json:"auth_token"`
	HostID         string   `json:"host_id"`
	Tags           []string `json:"tags"`
	IntervalSec    int      `json:"interval_sec"` // rétro-compat (si upload_interval_sec absent)
	PreferredIface string   `json:"preferred_iface"`
	SSPath         string   `json:"ss_path"`

	// Zéro-perte
	SampleIntervalMS  int    `json:"sample_interval_ms"`
	UploadIntervalSec int    `json:"upload_interval_sec"`
	StaleGraceMS      int    `json:"stale_grace_ms"`
	SpoolPath         string `json:"spool_path"`
	SpoolMaxMB        int    `json:"spool_max_mb"`
}

// Conn: format instantané (compat, pas utilisé par la voie "observed")
type Conn struct {
	Proto string `json:"proto"`
	Laddr string `json:"laddr"`
	Lport int    `json:"lport"`
	Raddr string `json:"raddr"`
	Rport int    `json:"rport"`
	Pid   int    `json:"pid"`
	Exe   string `json:"exe"`
}

type Payload struct {
	Host   string   `json:"host"`
	Tags   []string `json:"tags"`
	TS     int64    `json:"ts"`
	Conns  []Conn   `json:"conns,omitempty"`
	IP4    string   `json:"ip4"`
	IP6    string   `json:"ip6"`
	Errors []string `json:"errors,omitempty"`

	Observed []Observed `json:"observed,omitempty"`
}

// ---- Observed flows (zéro-perte) ----

type FlowKey struct {
	Proto, Laddr, Raddr string
	Lport, Rport, Pid   int
}

type Observed struct {
	Proto   string `json:"proto"`
	Laddr   string `json:"laddr"`
	Lport   int    `json:"lport"`
	Raddr   string `json:"raddr"`
	Rport   int    `json:"rport"`
	Pid     int    `json:"pid"`
	Exe     string `json:"exe"`
	FirstTs int64  `json:"first_ts"` // ms epoch
	LastTs  int64  `json:"last_ts"`  // ms epoch
	Samples int    `json:"samples"`
}

type liveFlow struct {
	Observed
	lastSeen int64 // ms
	closed   bool
}

// ---- helpers config (parser YAML minimal + suppression commentaires inline) ----

func stripInlineComment(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func parseList(val string) []string {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "[")
	val = strings.TrimSuffix(val, "]")
	if val == "" {
		return []string{}
	}
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.Trim(p, `"'`))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func loadConfig(path string) (AgentConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return AgentConfig{}, err
	}
	cfg := AgentConfig{
		IntervalSec:       15,
		SampleIntervalMS:  1000,
		UploadIntervalSec: 15,
		StaleGraceMS:      1500,
		SpoolMaxMB:        10,
	}
	lines := strings.Split(string(b), "\n")
	for _, raw := range lines {
		ln := strings.TrimSpace(stripInlineComment(raw))
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		kv := strings.SplitN(ln, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
		switch key {
		case "server_url":
			cfg.ServerURL = val
		case "auth_token":
			cfg.AuthToken = val
		case "host_id":
			cfg.HostID = val
		case "tags":
			cfg.Tags = parseList(val)
		case "interval_sec":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.IntervalSec = n
			}
		case "preferred_iface":
			cfg.PreferredIface = val
		case "ss_path":
			cfg.SSPath = val
		case "sample_interval_ms":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.SampleIntervalMS = n
			}
		case "upload_interval_sec":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.UploadIntervalSec = n
			}
		case "stale_grace_ms":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.StaleGraceMS = n
			}
		case "spool_path":
			cfg.SpoolPath = val
		case "spool_max_mb":
			if n, e := strconv.Atoi(val); e == nil {
				cfg.SpoolMaxMB = n
			}
		}
	}
	if cfg.ServerURL == "" || cfg.AuthToken == "" {
		return cfg, errors.New("server_url and auth_token are required")
	}
	if cfg.HostID == "" || cfg.HostID == "auto" {
		if h, _ := os.Hostname(); h != "" {
			cfg.HostID = h
		} else {
			cfg.HostID = "unknown-host"
		}
	}
	return cfg, nil
}

// ---- Parsing robuste de `ss -H -tuapn` ----

var protoRx = regexp.MustCompile(`^(tcp|udp)\b`)
var addrPortAllRx = regexp.MustCompile(`\[(?P<a1>[0-9a-fA-F:%.]+)\]:(?P<p1>[0-9*]+)|(?P<a2>[0-9a-fA-F.*:%]+):(?P<p2>[0-9*]+)`)
var procRx = regexp.MustCompile(`users:\(\((?:"([^"]+)"|([^,]+)),pid=([0-9]+)`)

func extractAddrPort(m []string) (string, int) {
	// indexes: 0 full, 1 [a1], 2 p1, 3 a2, 4 p2
	addr := ""
	pstr := ""
	if m[1] != "" {
		addr = m[1]
		pstr = m[2]
	} else {
		addr = m[3]
		pstr = m[4]
	}
	addr = strings.Trim(addr, "[]")
	addr = strings.TrimPrefix(addr, "::ffff:")
	port := 0
	if pstr != "*" {
		port, _ = strconv.Atoi(pstr)
	}
	return addr, port
}

func parseSS(output []byte) []Conn {
	conns := []Conn{}
	sc := bufio.NewScanner(bytes.NewReader(output))
	for sc.Scan() {
		ln := sc.Text()

		pm := protoRx.FindStringSubmatch(ln)
		if pm == nil {
			continue
		}
		proto := pm[1]

		matches := addrPortAllRx.FindAllStringSubmatch(ln, -1)
		if len(matches) < 2 {
			continue
		}
		laddr, lport := extractAddrPort(matches[0])
		raddr, rport := extractAddrPort(matches[1])

		exe := ""
		pid := 0
		if pm2 := procRx.FindStringSubmatch(ln); pm2 != nil {
			name := pm2[1]
			if name == "" {
				name = pm2[2]
			}
			exe = strings.Trim(name, `"`)
			pid, _ = strconv.Atoi(pm2[3])
		}

		conns = append(conns, Conn{
			Proto: proto, Laddr: laddr, Lport: lport, Raddr: raddr, Rport: rport, Pid: pid, Exe: exe,
		})
	}
	return conns
}

// ---- Agent runtime (sampler + uploader + spool) ----

type Agent struct {
	cfg    AgentConfig
	client *http.Client
	ssBin  string

	mu     sync.Mutex
	flows  map[FlowKey]*liveFlow // vivants + récemment fermés
	outbox []Observed            // à uploader au prochain batch
}

func NewAgent(cfg AgentConfig) *Agent {
	ss := cfg.SSPath
	if ss == "" {
		ss = "ss"
	}
	return &Agent{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		ssBin:  ss,
		flows:  map[FlowKey]*liveFlow{},
		outbox: []Observed{},
	}
}

func (a *Agent) sampleOnce(nowMS int64) []string {
	errs := []string{}
	out, err := exec.Command(a.ssBin, "-H", "-tuapn").Output()
	if err != nil {
		return []string{"ss failed: " + err.Error()}
	}
	conns := parseSS(out)

	seen := map[FlowKey]bool{}
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, c := range conns {
		k := FlowKey{Proto: c.Proto, Laddr: c.Laddr, Lport: c.Lport, Raddr: c.Raddr, Rport: c.Rport, Pid: c.Pid}
		seen[k] = true
		if lf, ok := a.flows[k]; ok {
			lf.LastTs = nowMS
			lf.Samples++
			if lf.Exe == "" && c.Exe != "" {
				lf.Exe = c.Exe
			}
			lf.lastSeen = nowMS
			lf.closed = false
			continue
		}
		a.flows[k] = &liveFlow{
			Observed: Observed{
				Proto: c.Proto, Laddr: c.Laddr, Lport: c.Lport,
				Raddr: c.Raddr, Rport: c.Rport, Pid: c.Pid, Exe: c.Exe,
				FirstTs: nowMS, LastTs: nowMS, Samples: 1,
			},
			lastSeen: nowMS,
		}
	}

	grace := int64(a.cfg.StaleGraceMS)
	if grace < 500 {
		grace = 500
	}
	for k, lf := range a.flows {
		if seen[k] {
			continue
	}
		if !lf.closed && nowMS-lf.lastSeen >= grace {
			lf.closed = true
			a.outbox = append(a.outbox, lf.Observed)
			// on garde lf en mémoire un peu plus longtemps (OK)
		}
	}
	return errs
}

func (a *Agent) samplerLoop() {
	iv := a.cfg.SampleIntervalMS
	if iv < 250 {
		iv = 250
	}
	t := time.NewTicker(time.Duration(iv) * time.Millisecond)
	defer t.Stop()
	for range t.C {
		_ = a.sampleOnce(time.Now().UnixMilli())
	}
}

func (a *Agent) spoolAppend(batch []Observed) {
	if a.cfg.SpoolPath == "" || len(batch) == 0 {
		return
	}
	if a.cfg.SpoolMaxMB <= 0 {
		a.cfg.SpoolMaxMB = 10
	}
	// rotation simple sur taille
	if fi, err := os.Stat(a.cfg.SpoolPath); err == nil && fi.Size() > int64(a.cfg.SpoolMaxMB)*1024*1024 {
		_ = os.WriteFile(a.cfg.SpoolPath, nil, 0600)
	}
	// format gob: [][]Observed (append)
	var batches [][]Observed
	if b, err := os.ReadFile(a.cfg.SpoolPath); err == nil && len(b) > 0 {
		_ = gob.NewDecoder(bytes.NewReader(b)).Decode(&batches)
	}
	batches = append(batches, batch)
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(batches)
	_ = os.WriteFile(a.cfg.SpoolPath, buf.Bytes(), 0600)
}

func (a *Agent) tryReplaySpool() {
	if a.cfg.SpoolPath == "" {
		return
	}
	b, err := os.ReadFile(a.cfg.SpoolPath)
	if err != nil || len(b) == 0 {
		return
	}
	var batches [][]Observed
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&batches); err != nil {
		return
	}
	for _, batch := range batches {
		if ok := a.postObserved(batch); !ok {
			// on s'arrête si ça échoue, on retentera plus tard
			return
		}
	}
	// purge si tout est OK
	_ = os.WriteFile(a.cfg.SpoolPath, nil, 0600)
}

func (a *Agent) postObserved(obs []Observed) bool {
	ip4, ip6 := gatherIPs(a.cfg.PreferredIface)
	pl := map[string]any{
		"host":     a.cfg.HostID,
		"tags":     a.cfg.Tags,
		"ts":       time.Now().Unix(),
		"ip4":      ip4,
		"ip6":      ip6,
		"observed": obs,
	}
	b, _ := json.Marshal(pl)
	req, _ := http.NewRequest("POST", strings.TrimRight(a.cfg.ServerURL, "/")+"/ingest", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.cfg.AuthToken)
	resp, err := a.client.Do(req)
	if err != nil {
		fmt.Println("ingest error:", err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (a *Agent) uploaderLoop() {
	sec := a.cfg.UploadIntervalSec
	if sec <= 0 {
		sec = a.cfg.IntervalSec
		if sec <= 0 {
			sec = 15
		}
	}
	t := time.NewTicker(time.Duration(sec) * time.Second)
	defer t.Stop()
	for range t.C {
		// snapshot & clear
		a.mu.Lock()
		batch := make([]Observed, len(a.outbox))
		copy(batch, a.outbox)
		a.outbox = a.outbox[:0]
		a.mu.Unlock()

		// rejouer d'abord le spool si présent
		a.tryReplaySpool()

		if len(batch) == 0 {
			continue
		}
		if ok := a.postObserved(batch); !ok {
			a.spoolAppend(batch)
		}
	}
}

func gatherIPs(prefer string) (ip4, ip6 string) {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if prefer != "" && iface.Name != prefer {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To4() != nil && ip4 == "" {
				ip4 = ip.String()
			} else if ip.To16() != nil && ip6 == "" {
				ip6 = ip.String()
			}
		}
		if ip4 != "" || ip6 != "" {
			break
		}
	}
	return
}

func main() {
	cfgPath := "/etc/connwatch-agent.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Println("config error:", err)
		os.Exit(1)
	}

	agent := NewAgent(cfg)
	go agent.samplerLoop()
	agent.uploaderLoop()
}

