package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TraceHop is one TTL step of a route trace.
type TraceHop struct {
	TTL      int      `json:"ttl"`
	Hosts    []string `json:"hosts,omitempty"` // IPs that answered at this TTL
	Name     string   `json:"name,omitempty"`  // reverse DNS of the first host, if known
	Sent     int      `json:"sent"`
	Received int      `json:"received"`
	LossPct  float64  `json:"loss_pct"`
	AvgMs    float64  `json:"avg_ms"`
	BestMs   float64  `json:"best_ms"`
	WorstMs  float64  `json:"worst_ms"`
}

// Responded reports whether any probe at this hop got a reply.
func (h TraceHop) Responded() bool { return h.Received > 0 }

// TraceResult is the full route trace.
type TraceResult struct {
	Tool   string     `json:"tool"`
	Target string     `json:"target"`
	Hops   []TraceHop `json:"hops"`
	Raw    string     `json:"raw,omitempty"`
	Note   string     `json:"note,omitempty"`
}

// TraceTool reports which tracing tool is available, preferring Trippy.
func TraceTool() string {
	if LookPath("trip") != "" {
		return "trip"
	}
	if runtime.GOOS == "windows" {
		if LookPath("tracert") != "" {
			return "tracert"
		}
		return ""
	}
	if LookPath("traceroute") != "" {
		return "traceroute"
	}
	return ""
}

// TraceInstallHint explains how to get a trace tool for this OS.
func TraceInstallHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "install Trippy (brew install trippy) — traceroute ships with macOS"
	case "windows":
		return "install Trippy (winget install trippy) — tracert ships with Windows"
	default:
		return "install Trippy (https://trippy.rs) or traceroute (e.g. apt install traceroute)"
	}
}

// Trace runs Trippy if available (falling back to the OS traceroute if it
// fails, e.g. for lack of privileges) and resolves hop names.
func Trace(ctx context.Context, host string, maxHops int) (TraceResult, error) {
	tool := TraceTool()
	if tool == "" {
		return TraceResult{Target: host}, fmt.Errorf("no route trace tool found; %s", TraceInstallHint())
	}
	var res TraceResult
	var err error
	if tool == "trip" {
		res, err = traceTrippy(ctx, host, maxHops)
		if err != nil && ctx.Err() == nil {
			fallback := "traceroute"
			if runtime.GOOS == "windows" {
				fallback = "tracert"
			}
			if LookPath(fallback) != "" {
				note := "trip failed (" + shortErr(err) + "); used " + fallback
				res, err = traceSystem(ctx, fallback, host, maxHops)
				res.Note = note
			}
		}
	} else {
		res, err = traceSystem(ctx, tool, host, maxHops)
	}
	if err == nil {
		resolveHopNames(ctx, res.Hops)
	}
	return res, err
}

func traceTrippy(ctx context.Context, host string, maxHops int) (TraceResult, error) {
	res := TraceResult{Tool: "trip", Target: host}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{"--mode", "json", "--report-cycles", "5", "--max-ttl", strconv.Itoa(maxHops), "--dns-resolve-method", "system"}
	if runtime.GOOS != "windows" {
		args = append(args, "--unprivileged")
	}
	out, err := RunCommand(cctx, "trip", append(args, host)...)
	res.Raw = out
	if err != nil {
		return res, fmt.Errorf("trip: %v", firstLine(out, err))
	}
	hops, perr := ParseTrippyJSON(out)
	if perr != nil {
		return res, perr
	}
	res.Hops = hops
	return res, nil
}

func traceSystem(ctx context.Context, tool, host string, maxHops int) (TraceResult, error) {
	res := TraceResult{Tool: tool, Target: host}
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var args []string
	if tool == "tracert" {
		args = []string{"-d", "-h", strconv.Itoa(maxHops), "-w", "1000", host}
	} else {
		args = []string{"-n", "-q", "3", "-w", "1", "-m", strconv.Itoa(maxHops), host}
	}
	out, err := RunCommand(cctx, tool, args...)
	res.Raw = out
	var hops []TraceHop
	if tool == "tracert" {
		hops = ParseTracert(out)
	} else {
		hops = ParseTraceroute(out)
	}
	if len(hops) == 0 {
		if err == nil {
			err = fmt.Errorf("no hops in output")
		}
		return res, fmt.Errorf("%s: %v", tool, firstLine(out, err))
	}
	res.Hops = hops
	return res, nil
}

func firstLine(out string, err error) string {
	out = strings.TrimSpace(out)
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	if out == "" {
		return err.Error()
	}
	return out
}

// flexFloat accepts numbers encoded either as JSON numbers or strings
// (Trippy's report writes "12.34").
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	*f = flexFloat(v)
	return nil
}

// ParseTrippyJSON parses `trip --mode json` report output.
func ParseTrippyJSON(out string) ([]TraceHop, error) {
	// Trippy may print warnings before the JSON document.
	if i := strings.IndexByte(out, '{'); i > 0 {
		out = out[i:]
	}
	var doc struct {
		Hops []struct {
			TTL   flexFloat `json:"ttl"`
			Hosts []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
				Name     string `json:"name"`
			} `json:"hosts"`
			LossPct flexFloat `json:"loss_pct"`
			Sent    flexFloat `json:"sent"`
			Recv    flexFloat `json:"recv"`
			Avg     flexFloat `json:"avg"`
			Best    flexFloat `json:"best"`
			Worst   flexFloat `json:"worst"`
		} `json:"hops"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("parsing trip output: %w", err)
	}
	hops := make([]TraceHop, 0, len(doc.Hops))
	for _, h := range doc.Hops {
		hop := TraceHop{
			TTL: int(h.TTL), Sent: int(h.Sent), Received: int(h.Recv),
			LossPct: float64(h.LossPct), AvgMs: float64(h.Avg),
			BestMs: float64(h.Best), WorstMs: float64(h.Worst),
		}
		for _, host := range h.Hosts {
			hop.Hosts = append(hop.Hosts, host.IP)
			name := host.Hostname
			if name == "" {
				name = host.Name
			}
			if hop.Name == "" && name != "" && name != host.IP {
				hop.Name = name
			}
		}
		hops = append(hops, hop)
	}
	return hops, nil
}

var (
	hopLineRe = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
	rttRe     = regexp.MustCompile(`^([\d.]+)$`)
	ipRe      = regexp.MustCompile(`^[0-9a-fA-F:.]+$`)
)

// ParseTraceroute parses Linux/macOS `traceroute -n` output, e.g.
//
//	1  192.168.1.1  1.234 ms  1.100 ms  1.050 ms
//	2  * * *
//	3  10.0.0.1  5.1 ms * 10.0.0.2  6.2 ms
//
// macOS prints extra responders for the same TTL on indented continuation
// lines without a hop number; those are merged into the previous hop.
func ParseTraceroute(out string) []TraceHop {
	var hops []TraceHop
	var rtts []float64
	for _, line := range strings.Split(out, "\n") {
		var rest string
		var hop TraceHop
		if m := hopLineRe.FindStringSubmatch(line); m != nil {
			ttl, _ := strconv.Atoi(m[1])
			hop, rtts, rest = TraceHop{TTL: ttl}, nil, m[2]
		} else if f := strings.Fields(line); len(hops) > 0 && strings.HasPrefix(line, " ") && len(f) > 0 && ipRe.MatchString(f[0]) {
			hop, rest = hops[len(hops)-1], line
			hops = hops[:len(hops)-1]
		} else {
			continue
		}
		fields := strings.Fields(rest)
		for i := 0; i < len(fields); i++ {
			f := fields[i]
			switch {
			case f == "*":
				hop.Sent++
			case rttRe.MatchString(f) && i+1 < len(fields) && fields[i+1] == "ms":
				v, _ := strconv.ParseFloat(f, 64)
				rtts = append(rtts, v)
				hop.Sent++
				i++
			case strings.HasPrefix(f, "!"):
				// annotations like !H, !N — unreachable markers; ignore
			case ipRe.MatchString(f) && strings.ContainsAny(f, ".:"):
				hop.Hosts = appendUnique(hop.Hosts, f)
			case strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")"):
				hop.Hosts = appendUnique(hop.Hosts, strings.Trim(f, "()"))
			}
		}
		fillHopStats(&hop, rtts)
		hops = append(hops, hop)
	}
	return hops
}

var tracertRttRe = regexp.MustCompile(`^<?(\d+)$`)

// ParseTracert parses Windows `tracert -d` output, e.g.
//
//	1    <1 ms    <1 ms    <1 ms  192.168.1.1
//	2     *        *        *     Request timed out.
func ParseTracert(out string) []TraceHop {
	var hops []TraceHop
	for _, line := range strings.Split(out, "\n") {
		m := hopLineRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		fields := strings.Fields(m[2])
		// A hop line has three probe columns ("*" or "N ms") before the host.
		if len(fields) < 3 {
			continue
		}
		ttl, _ := strconv.Atoi(m[1])
		hop := TraceHop{TTL: ttl}
		var rtts []float64
		probes := 0
		i := 0
		for ; i < len(fields) && probes < 3; i++ {
			f := fields[i]
			if f == "*" {
				hop.Sent++
				probes++
				continue
			}
			if mm := tracertRttRe.FindStringSubmatch(f); mm != nil && i+1 < len(fields) && fields[i+1] == "ms" {
				v, _ := strconv.ParseFloat(mm[1], 64)
				if strings.HasPrefix(f, "<") {
					v = 0.5
				}
				rtts = append(rtts, v)
				hop.Sent++
				probes++
				i++
				continue
			}
			break
		}
		if probes < 3 {
			continue
		}
		for _, f := range fields[i:] {
			f = strings.Trim(f, "[]")
			if ipRe.MatchString(f) && strings.ContainsAny(f, ".:") {
				hop.Hosts = appendUnique(hop.Hosts, f)
			}
		}
		fillHopStats(&hop, rtts)
		hops = append(hops, hop)
	}
	return hops
}

func fillHopStats(hop *TraceHop, rtts []float64) {
	hop.Received = len(rtts)
	st := Summarise(hop.Sent, rtts)
	hop.LossPct, hop.AvgMs, hop.BestMs, hop.WorstMs = st.LossPct, st.AvgMs, st.MinMs, st.MaxMs
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// resolveHopNames fills in reverse-DNS names concurrently, bounded by a short
// timeout so a slow resolver never stalls the trace.
func resolveHopNames(ctx context.Context, hops []TraceHop) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range hops {
		if hops[i].Name != "" || len(hops[i].Hosts) == 0 {
			continue
		}
		wg.Add(1)
		go func(h *TraceHop) {
			defer wg.Done()
			names, err := net.DefaultResolver.LookupAddr(ctx, h.Hosts[0])
			if err == nil && len(names) > 0 {
				h.Name = strings.TrimSuffix(names[0], ".")
			}
		}(&hops[i])
	}
	wg.Wait()
}
