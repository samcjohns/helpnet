package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"
)

// HTTPSample is one timed HTTPS GET, following redirects manually so the
// phase breakdown describes the final hop while Total covers every hop.
type HTTPSample struct {
	URL        string  `json:"url"`
	FinalURL   string  `json:"final_url,omitempty"`
	Redirects  int     `json:"redirects"`
	Status     int     `json:"status,omitempty"`
	Proto      string  `json:"proto,omitempty"`
	TLSVersion string  `json:"tls_version,omitempty"`
	RemoteAddr string  `json:"remote_addr,omitempty"`
	DNSMs      float64 `json:"dns_ms"`
	ConnectMs  float64 `json:"connect_ms"`
	TLSMs      float64 `json:"tls_ms"`
	TTFBMs     float64 `json:"ttfb_ms"`
	TransferMs float64 `json:"transfer_ms"`
	TotalMs    float64 `json:"total_ms"`
	Bytes      int64   `json:"bytes"`
	Error      string  `json:"error,omitempty"`
	TimedOut   bool    `json:"timed_out,omitempty"`
}

// HTTPOptions configures TimeHTTP.
type HTTPOptions struct {
	Timeout time.Duration // whole request, all redirects included
	// Network forces "tcp4" or "tcp6"; empty lets Go pick (Happy Eyeballs).
	Network string
	// UseProxy honours HTTP(S)_PROXY like a browser would.
	UseProxy bool
	// TLSConfig overrides TLS settings (used by tests with self-signed certs).
	TLSConfig *tls.Config
	MaxBody   int64
}

const maxRedirects = 10

// TimeHTTP performs one GET with keep-alives disabled and per-phase timing.
func TimeHTTP(ctx context.Context, rawURL string, opt HTTPOptions) HTTPSample {
	s := HTTPSample{URL: rawURL}
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	if opt.MaxBody <= 0 {
		opt.MaxBody = 5 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	start := time.Now()
	cur := rawURL
	for {
		hop, next, err := timeHop(ctx, cur, opt)
		hop.URL, hop.Redirects = rawURL, s.Redirects
		s = hop
		if err != nil {
			s.Error = err.Error()
			s.TimedOut = errors.Is(err, context.DeadlineExceeded) || isTimeout(err)
			break
		}
		if next == "" {
			s.FinalURL = cur
			break
		}
		s.Redirects++
		if s.Redirects > maxRedirects {
			s.Error = "too many redirects"
			break
		}
		cur = next
	}
	s.TotalMs = Ms(time.Since(start))
	return s
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func timeHop(ctx context.Context, rawURL string, opt HTTPOptions) (HTTPSample, string, error) {
	var s HTTPSample
	// Trace hooks may fire on transport goroutines (notably HTTP/2's
	// request writer), so every timestamp is guarded by mu.
	var mu sync.Mutex
	var dnsStart, connStart, tlsStart, gotConn, wrote, firstByte time.Time
	lock := func(f func()) {
		mu.Lock()
		defer mu.Unlock()
		f()
	}

	network := opt.Network
	if network == "" {
		network = "tcp"
	}
	dialer := &net.Dialer{}
	tr := &http.Transport{
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: opt.Timeout,
		TLSClientConfig:     opt.TLSConfig,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	if opt.UseProxy {
		tr.Proxy = http.ProxyFromEnvironment
	}
	defer tr.CloseIdleConnections()

	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { lock(func() { dnsStart = time.Now() }) },
		DNSDone: func(httptrace.DNSDoneInfo) {
			lock(func() {
				if !dnsStart.IsZero() {
					s.DNSMs = Ms(time.Since(dnsStart))
				}
			})
		},
		ConnectStart: func(_, _ string) {
			lock(func() {
				if connStart.IsZero() {
					connStart = time.Now()
				}
			})
		},
		ConnectDone: func(_, _ string, err error) {
			lock(func() {
				if err == nil && s.ConnectMs == 0 {
					s.ConnectMs = Ms(time.Since(connStart))
				}
			})
		},
		TLSHandshakeStart: func() { lock(func() { tlsStart = time.Now() }) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			lock(func() {
				if err == nil {
					s.TLSMs = Ms(time.Since(tlsStart))
				}
			})
		},
		GotConn: func(info httptrace.GotConnInfo) {
			lock(func() {
				gotConn = time.Now()
				if info.Conn != nil {
					s.RemoteAddr = info.Conn.RemoteAddr().String()
				}
			})
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { lock(func() { wrote = time.Now() }) },
		GotFirstResponseByte: func() { lock(func() { firstByte = time.Now() }) },
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, rawURL, nil)
	if err != nil {
		return s, "", err
	}
	req.Header.Set("User-Agent", "helpnet (network diagnostics)")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		mu.Lock()
		defer mu.Unlock()
		return s, "", err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, opt.MaxBody))
	done := time.Now()

	mu.Lock()
	defer mu.Unlock()
	// TTFB runs from the request being written to the first response byte.
	// If the writer goroutine never reported, measure from GotConn.
	start := wrote
	if start.IsZero() || start.After(firstByte) {
		start = gotConn
	}
	if !start.IsZero() && !firstByte.IsZero() {
		s.TTFBMs = Ms(firstByte.Sub(start))
		s.TransferMs = Ms(done.Sub(firstByte))
	}
	s.Bytes = n
	s.Status = resp.StatusCode
	s.Proto = resp.Proto
	if resp.TLS != nil {
		s.TLSVersion = tls.VersionName(resp.TLS.Version)
	}
	if err != nil {
		return s, "", fmt.Errorf("reading body: %w", err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			base, _ := url.Parse(rawURL)
			next, perr := base.Parse(loc)
			if perr != nil {
				return s, "", fmt.Errorf("bad redirect location %q", loc)
			}
			return s, next.String(), nil
		}
	}
	return s, "", nil
}
