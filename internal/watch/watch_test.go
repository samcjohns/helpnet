package watch

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/samcjohns/helpnet/internal/config"
)

func TestStartStreamsSamplesUntilDuration(t *testing.T) {
	var calls atomic.Int32
	o := Options{
		Duration: 350 * time.Millisecond,
		Interval: 50 * time.Millisecond,
		Gateway:  "192.0.2.1",
		Config:   config.Default(),
		Probe: func(_ context.Context, l Layer) Probe {
			calls.Add(1)
			return Probe{Ran: true, OK: l != DNS, Ms: 3}
		},
	}
	var got []Sample
	for s := range Start(context.Background(), o) {
		got = append(got, s)
	}
	if len(got) < 4 || len(got) > 8 {
		t.Fatalf("got %d samples in 350ms at 50ms", len(got))
	}
	s := got[0]
	if !s.Gateway.OK || !s.Internet.OK || s.DNS.OK || s.At.IsZero() {
		t.Errorf("sample = %+v", s)
	}
	if int(calls.Load()) != 3*len(got) && int(calls.Load()) != 3*(len(got)+1) {
		t.Errorf("%d probe calls for %d samples", calls.Load(), len(got))
	}
}

func TestCancelStopsQuickly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	o := Options{
		Duration: time.Hour,
		Config:   config.Default(),
		Probe: func(ctx context.Context, _ Layer) Probe {
			<-ctx.Done() // a probe that never answers on its own
			return Probe{Ran: true}
		},
	}
	ch := Start(ctx, o)
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()
	for range ch {
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("watch took %v to stop", d)
	}
}

// TestRealProbesOnLoopback runs the real probes: loopback stands in for the
// gateway and the internet, and a local DNS server answers NXDOMAIN.
func TestRealProbesOnLoopback(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetRcode(r, mdns.RcodeNameError)
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	cfg := config.Default()
	cfg.Hosts.Internet = []string{"127.0.0.1"}
	o := Options{
		Duration:       2500 * time.Millisecond,
		Interval:       500 * time.Millisecond,
		Gateway:        "127.0.0.1",
		Config:         cfg,
		SystemResolver: pc.LocalAddr().String(),
	}
	var last Sample
	n := 0
	for s := range Start(context.Background(), o) {
		last, n = s, n+1
	}
	if n < 3 {
		t.Fatalf("only %d samples", n)
	}
	if !last.DNS.OK {
		t.Errorf("DNS probe failed: %+v", last.DNS)
	}
	// ICMP to loopback may be unavailable in a sandbox, so only require
	// that both layers were measured.
	if !last.Gateway.Ran || !last.Internet.Ran {
		t.Errorf("layers not measured: %+v", last)
	}
}

func TestNoGatewayOrHostsIsUnmeasured(t *testing.T) {
	cfg := config.Default()
	cfg.Hosts.Internet, cfg.Hosts.DNSTestDomains = nil, nil
	w := &watcher{o: Options{Config: cfg, Interval: time.Second}, gw: &target{}, internet: map[string]*target{}}
	s := w.sample(context.Background())
	if s.Gateway.Ran || s.Internet.Ran || s.DNS.Ran {
		t.Errorf("sample = %+v", s)
	}
}
