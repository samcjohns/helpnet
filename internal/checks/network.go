package checks

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/samcjohns/nethelp/internal/probe"
	"github.com/samcjohns/nethelp/internal/sysinfo"
)

// Layer 0 — local interface.
type localCheck struct{}

func (localCheck) ID() ID { return Local }

func (localCheck) Run(ctx context.Context, rc *RunContext) (any, error) {
	rc.Progress("detecting interface…")
	detect := rc.Opts.Detect
	if detect == nil {
		detect = sysinfo.Detect
	}
	info, err := detect(ctx)
	if err != nil {
		if errors.Is(err, sysinfo.ErrNoRoute) {
			return &info, err
		}
		return nil, err
	}
	return &info, nil
}

func (rc *RunContext) pingOpts(onReply func(int, float64)) probe.PingOptions {
	interval := rc.Opts.PingInterval
	if interval == 0 {
		interval = 200 * time.Millisecond
	}
	return probe.PingOptions{
		Count:    rc.Opts.Config.Samples,
		Interval: interval,
		Timeout:  rc.Opts.Config.Timeout.Duration,
		OnReply:  onReply,
	}
}

// Layer 1 — gateway.
type gatewayCheck struct{}

func (gatewayCheck) ID() ID { return Gateway }

func (gatewayCheck) Run(ctx context.Context, rc *RunContext) (any, error) {
	local := rc.Results.Local
	if local == nil || local.Gateway == "" {
		return nil, &SkipError{Reason: "no default gateway (point-to-point or VPN-only link)"}
	}
	gw := local.Gateway
	res := &GatewayResult{Address: gw}
	n := rc.Opts.Config.Samples
	got := 0
	ping, err := probe.Ping(ctx, gw, rc.pingOpts(func(_ int, ms float64) {
		got++
		rc.Progress("%s · %.1f ms (%d/%d)", gw, ms, got, n)
	}))
	res.Ping = ping
	if ping.Note != "" {
		rc.Note("%s", ping.Note)
	}
	if err != nil && ctx.Err() == nil {
		rc.Note("ping failed: %v", err)
	}
	res.Reachable = ping.Stats.Received > 0
	if !res.Reachable && ctx.Err() == nil {
		// Some routers ignore ICMP. A TCP answer (even a refusal) proves the
		// gateway is alive.
		rc.Progress("no ping replies; trying TCP…")
		for _, port := range []string{"80", "443", "53"} {
			t := probe.TCPConnect(ctx, net.JoinHostPort(gw, port), 1, time.Second)
			res.TCP = append(res.TCP, t)
			if t.Reachable() {
				res.Reachable, res.ICMPBlocked = true, true
				break
			}
		}
	}
	return res, nil
}

// Layer 2 — internet reachability.
type internetCheck struct{}

func (internetCheck) ID() ID { return Internet }

func (internetCheck) Run(ctx context.Context, rc *RunContext) (any, error) {
	hosts := rc.Opts.Config.Hosts.Internet
	timeout := rc.Opts.Config.Timeout.Duration
	res := &InternetResult{
		Pings: make([]probe.PingResult, len(hosts)),
		TCP:   make([]probe.TCPResult, len(hosts)),
	}
	var mu sync.Mutex
	counts := make([]int, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(2)
		go func() {
			defer wg.Done()
			p, err := probe.Ping(ctx, h, rc.pingOpts(func(_ int, ms float64) {
				mu.Lock()
				counts[i]++
				c := counts[i]
				mu.Unlock()
				rc.Progress("%s · %.0f ms (%d/%d)", h, ms, c, rc.Opts.Config.Samples)
			}))
			mu.Lock()
			defer mu.Unlock()
			res.Pings[i] = p
			if p.Note != "" && i == 0 {
				rc.Note("%s", p.Note)
			}
			if err != nil && ctx.Err() == nil {
				rc.Note("ping %s failed: %v", h, err)
			}
		}()
		go func() {
			defer wg.Done()
			// A TCP connect to 443 keeps an ICMP-blocking network from being
			// misdiagnosed as offline.
			t := probe.TCPConnect(ctx, net.JoinHostPort(h, "443"), 3, timeout)
			mu.Lock()
			res.TCP[i] = t
			mu.Unlock()
		}()
	}
	if url := rc.Opts.Config.Hosts.CaptiveURL; url != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := probe.CheckCaptivePortal(ctx, url, timeout+2*time.Second)
			mu.Lock()
			res.Captive = &c
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	pingOK, tcpOK := false, false
	for i := range hosts {
		pingOK = pingOK || res.Pings[i].Stats.Received > 0
		tcpOK = tcpOK || res.TCP[i].Connected > 0
	}
	res.Reachable = pingOK || tcpOK
	res.ICMPBlocked = !pingOK && tcpOK
	if res.Captive != nil && res.Captive.Error != "" && res.Reachable {
		rc.Note("captive-portal check failed: %s", res.Captive.Error)
	}
	return res, nil
}
