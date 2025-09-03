package main

import (
	"bufio"
	"bytes"
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
	"time"
)

type AgentConfig struct {
	ServerURL      string   `json:"server_url"`
	AuthToken      string   `json:"auth_token"`
	HostID         string   `json:"host_id"`
	Tags           []string `json:"tags"`
	IntervalSec    int      `json:"interval_sec"`
	PreferredIface string   `json:"preferred_iface"`
	SSPath         string   `json:"ss_path"` // optionnel: chemin absolu vers ss (ex: /usr/local/lib/connwatch/ss)
}

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
	Conns  []Conn   `json:"conns"`
	IP4    string   `json:"ip4"`
	IP6    string   `json:"ip6"`
	Errors []string `json:"errors"`
}

// --- helpers config (parser YAML minimal avec suppression des commentaires inline) ---

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
	cfg := AgentConfig{IntervalSec: 15}
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
		val := strings.TrimSpace(kv[1])
		val = strings.Trim(val, `"'`)
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

// --- Parsing robuste de `ss -H -tuapn` ---
// 1) détecte proto au début (tcp/udp)
// 2) extrait les deux premiers couples addr:port (IPv4/IPv6, [::...], [::ffff:...], *:*)
// 3) extrait le premier process listé dans users:((...))

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

		// 1) proto
		pm := protoRx.FindStringSubmatch(ln)
		if pm == nil {
			continue
		}
		proto := pm[1]

		// 2) addr:port x2
		matches := addrPortAllRx.FindAllStringSubmatch(ln, -1)
		if len(matches) < 2 {
			continue
		}
		laddr, lport := extractAddrPort(matches[0])
		raddr, rport := extractAddrPort(matches[1])

		// 3) process
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

	ssBin := cfg.SSPath
	if ssBin == "" {
		ssBin = "ss"
	}
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		errs := []string{}
		out, err := exec.Command(ssBin, "-H", "-tuapn").Output()
		if err != nil {
			errs = append(errs, "ss failed: "+err.Error())
		}
		conns := parseSS(out)
		ip4, ip6 := gatherIPs(cfg.PreferredIface)

		pl := Payload{
			Host:   cfg.HostID,
			Tags:   cfg.Tags,
			TS:     time.Now().Unix(),
			Conns:  conns,
			IP4:    ip4,
			IP6:    ip6,
			Errors: errs,
		}

		b, _ := json.Marshal(pl)
		req, _ := http.NewRequest("POST", strings.TrimRight(cfg.ServerURL, "/")+"/ingest", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.AuthToken)

		if resp, err := client.Do(req); err != nil {
			fmt.Println("ingest error:", err)
		} else {
			resp.Body.Close()
		}

		interval := cfg.IntervalSec
		if interval < 5 {
			interval = 5
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
}
