package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"
)

// isRefused detects a TCP RST. Windows reports WSAECONNREFUSED, which does not
// match syscall.ECONNREFUSED, so fall back to the message text.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "refused")
}

// TCPResult is the outcome of repeated TCP connects to one address.
type TCPResult struct {
	Addr      string       `json:"addr"`
	Attempts  int          `json:"attempts"`
	Connected int          `json:"connected"`
	Refused   int          `json:"refused"` // host answered with RST: reachable but port closed
	Stats     LatencyStats `json:"stats"`
	Error     string       `json:"error,omitempty"`
}

// Reachable reports whether the host answered at all (connect or refusal).
func (r TCPResult) Reachable() bool { return r.Connected+r.Refused > 0 }

// TCPConnect dials addr n times and records connect times.
func TCPConnect(ctx context.Context, addr string, n int, timeout time.Duration) TCPResult {
	res := TCPResult{Addr: addr, Attempts: n}
	var rtts []float64
	d := net.Dialer{Timeout: timeout}
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", addr)
		el := time.Since(start)
		if err != nil {
			if isRefused(err) {
				res.Refused++
				rtts = append(rtts, Ms(el))
				continue
			}
			res.Error = err.Error()
			continue
		}
		conn.Close()
		res.Connected++
		rtts = append(rtts, Ms(el))
	}
	res.Stats = Summarise(n, rtts)
	return res
}
