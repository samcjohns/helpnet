package probe

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// PingResult is the outcome of pinging one host.
type PingResult struct {
	Host   string       `json:"host"`
	Method string       `json:"method"` // "icmp" (pro-bing) or "system ping"
	Stats  LatencyStats `json:"stats"`
	Note   string       `json:"note,omitempty"`
	Raw    string       `json:"raw,omitempty"`
}

// PingOptions controls a ping run.
type PingOptions struct {
	Count    int
	Interval time.Duration
	Timeout  time.Duration // per-probe reply timeout
	// OnReply, if set, is called with each reply RTT in milliseconds.
	OnReply func(seq int, rttMs float64)
}

// Ping measures RTT to host. It prefers unprivileged in-process ICMP and falls
// back to the system ping binary when the OS does not permit that.
func Ping(ctx context.Context, host string, opt PingOptions) (PingResult, error) {
	if opt.Count <= 0 {
		opt.Count = 10
	}
	if opt.Interval <= 0 {
		opt.Interval = 200 * time.Millisecond
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 3 * time.Second
	}
	if runtime.GOOS != "windows" {
		res, err := pingNative(ctx, host, opt)
		if err == nil {
			return res, nil
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		fb, ferr := pingSystem(ctx, host, opt)
		fb.Note = "unprivileged ICMP unavailable (" + shortErr(err) + "); used system ping"
		return fb, ferr
	}
	return pingSystem(ctx, host, opt)
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 60 {
		return s[i+2:]
	}
	return s
}

func pingNative(ctx context.Context, host string, opt PingOptions) (PingResult, error) {
	res := PingResult{Host: host, Method: "icmp"}
	p, err := probing.NewPinger(host)
	if err != nil {
		return res, err
	}
	p.SetPrivileged(false)
	p.Count = opt.Count
	p.Interval = opt.Interval
	// Overall deadline: all probes sent plus one reply timeout.
	p.Timeout = time.Duration(opt.Count)*opt.Interval + opt.Timeout
	var rtts []float64
	p.OnRecv = func(pkt *probing.Packet) {
		ms := Ms(pkt.Rtt)
		rtts = append(rtts, ms)
		if opt.OnReply != nil {
			opt.OnReply(pkt.Seq, ms)
		}
	}
	done := make(chan error, 1)
	go func() { done <- p.RunWithContext(ctx) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		p.Stop()
		<-done
		return res, ctx.Err()
	}
	if err != nil {
		return res, err
	}
	sent := p.PacketsSent
	if sent == 0 {
		return res, errors.New("no packets sent")
	}
	res.Stats = Summarise(sent, rtts)
	return res, nil
}

func pingSystem(ctx context.Context, host string, opt PingOptions) (PingResult, error) {
	res := PingResult{Host: host, Method: "system ping"}
	name, args := systemPingArgs(runtime.GOOS, host, opt)
	if LookPath(name) == "" {
		return res, fmt.Errorf("%s not found on PATH", name)
	}
	deadline := time.Duration(opt.Count)*(opt.Interval+opt.Timeout) + 2*time.Second
	if runtime.GOOS == "windows" {
		deadline = time.Duration(opt.Count)*(time.Second+opt.Timeout) + 2*time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	out, err := RunCommand(cctx, name, args...)
	res.Raw = out
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	rtts := ParsePingOutput(out)
	for i, v := range rtts {
		if opt.OnReply != nil {
			opt.OnReply(i, v)
		}
	}
	res.Stats = Summarise(opt.Count, rtts)
	// ping exits non-zero when hosts don't reply; that is a result, not an error.
	if err != nil && len(rtts) == 0 && !looksLikePingRan(out) {
		return res, fmt.Errorf("system ping failed: %v", err)
	}
	return res, nil
}

func systemPingArgs(goos, host string, opt PingOptions) (string, []string) {
	count := strconv.Itoa(opt.Count)
	switch goos {
	case "windows":
		return "ping", []string{"-n", count, "-w", strconv.Itoa(int(opt.Timeout.Milliseconds())), host}
	case "darwin", "freebsd", "openbsd", "netbsd":
		return "ping", []string{"-n", "-c", count, "-i", fmtSeconds(opt.Interval), "-W", strconv.Itoa(int(opt.Timeout.Milliseconds())), host}
	default:
		return "ping", []string{"-n", "-c", count, "-i", fmtSeconds(opt.Interval), "-W", strconv.Itoa(max(1, int(opt.Timeout.Seconds()))), host}
	}
}

func fmtSeconds(d time.Duration) string {
	if d < 200*time.Millisecond {
		d = 200 * time.Millisecond // minimum for unprivileged users on Linux/macOS
	}
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64)
}

var (
	// Unix: "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=18.3 ms"
	unixReplyRe = regexp.MustCompile(`(?i)\bttl=\d+.*?\btime[=<]\s*([\d.]+)\s*ms`)
	// Windows: "Reply from 1.1.1.1: bytes=32 time=18ms TTL=57" (also "time<1ms").
	// Localised builds translate "time" but keep "TTL=", so match loosely.
	winReplyRe = regexp.MustCompile(`(?i)[=<]\s*([\d.,]+)\s*ms\b.*\bTTL=\d+`)
)

// ParsePingOutput extracts per-reply RTTs (ms) from system ping output on
// Linux, macOS/BSD or Windows.
func ParsePingOutput(out string) []float64 {
	var rtts []float64
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		var m []string
		if m = unixReplyRe.FindStringSubmatch(line); m == nil {
			m = winReplyRe.FindStringSubmatch(line)
		}
		if m == nil {
			continue
		}
		if v, err := strconv.ParseFloat(strings.ReplaceAll(m[1], ",", "."), 64); err == nil {
			rtts = append(rtts, v)
		}
	}
	return rtts
}

func looksLikePingRan(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "packets transmitted") || strings.Contains(l, "packets: sent") ||
		strings.Contains(l, "request timed out") || strings.Contains(l, "100% packet loss") ||
		strings.Contains(l, "(100% loss)") || strings.Contains(l, "destination host unreachable")
}
