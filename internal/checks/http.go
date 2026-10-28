package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/samcjohns/nethelp/internal/probe"
)

// Layer 4 — HTTP phase timing.
type httpCheck struct{}

func (httpCheck) ID() ID { return HTTP }

const httpSamples = 3

func (httpCheck) Run(ctx context.Context, rc *RunContext) (any, error) {
	target := rc.Opts.Target
	res := &HTTPResult{Target: target, Host: rc.Opts.TargetHost()}
	timeout := max(10*time.Second, 3*rc.Opts.Config.Timeout.Duration)
	if u, _ := url.Parse(target); u != nil {
		if p, _ := http.ProxyFromEnvironment(&http.Request{URL: u}); p != nil {
			res.ViaProxy = true
			rc.Note("requests go through proxy %s", p.Host)
		}
	}
	opt := probe.HTTPOptions{Timeout: timeout, UseProxy: true, TLSConfig: rc.Opts.TLSConfig}

	for i := 0; i < httpSamples && ctx.Err() == nil; i++ {
		rc.Progress("GET %s (%d/%d)", res.Host, i+1, httpSamples)
		s := probe.TimeHTTP(ctx, target, opt)
		res.Samples = append(res.Samples, s)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	aggregateHTTP(res)
	if res.OK == 0 {
		last := res.Samples[len(res.Samples)-1]
		return res, fmt.Errorf("all %d requests failed: %s", len(res.Samples), last.Error)
	}

	// Time one request over each address family to catch a broken IPv6 path,
	// which makes browsers stall before falling back to IPv4.
	if res.ViaProxy {
		res.FamilyNote = "skipped IPv4/IPv6 comparison: requests go through a proxy"
		return res, nil
	}
	if ip := net.ParseIP(res.Host); ip != nil {
		return res, nil
	}
	rctx, cancel := context.WithTimeout(ctx, rc.Opts.Config.Timeout.Duration)
	v4, _ := net.DefaultResolver.LookupNetIP(rctx, "ip4", res.Host)
	v6, _ := net.DefaultResolver.LookupNetIP(rctx, "ip6", res.Host)
	cancel()
	res.HasIPv4, res.HasIPv6 = len(v4) > 0, len(v6) > 0
	if !res.HasIPv4 || !res.HasIPv6 {
		res.FamilyNote = "target is not dual-stack; IPv4/IPv6 comparison not applicable"
		return res, nil
	}
	famOpt := opt
	famOpt.UseProxy = false
	famOpt.Timeout = max(5*time.Second, 2*rc.Opts.Config.Timeout.Duration)
	rc.Progress("comparing IPv4 and IPv6 paths…")
	famOpt.Network = "tcp4"
	s4 := probe.TimeHTTP(ctx, target, famOpt)
	famOpt.Network = "tcp6"
	s6 := probe.TimeHTTP(ctx, target, famOpt)
	res.IPv4, res.IPv6 = &s4, &s6
	return res, nil
}

func aggregateHTTP(res *HTTPResult) {
	var dns, conn, tls, ttfb, xfer, total []float64
	for _, s := range res.Samples {
		if s.Error != "" {
			continue
		}
		res.OK++
		dns = append(dns, s.DNSMs)
		conn = append(conn, s.ConnectMs)
		tls = append(tls, s.TLSMs)
		ttfb = append(ttfb, s.TTFBMs)
		xfer = append(xfer, s.TransferMs)
		total = append(total, s.TotalMs)
		res.Status, res.FinalURL, res.Redirects = s.Status, s.FinalURL, s.Redirects
		res.Proto, res.TLSVersion, res.RemoteAddr = s.Proto, s.TLSVersion, s.RemoteAddr
	}
	res.DNSMs, res.ConnectMs, res.TLSMs = probe.Mean(dns), probe.Mean(conn), probe.Mean(tls)
	res.TTFBMs, res.TransferMs, res.TotalMs = probe.Mean(ttfb), probe.Mean(xfer), probe.Mean(total)
}
