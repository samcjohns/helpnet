// Package watch probes the gateway, the internet and DNS once a second for a
// while, so problems that come and go show up with a timestamp. It only
// measures; interpret.AnalyzeWatch turns the samples into a verdict.
package watch

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/samcjohns/helpnet/internal/config"
	"github.com/samcjohns/helpnet/internal/probe"
)

// Layer is one of the watched layers.
type Layer string

const (
	Gateway  Layer = "gateway"
	Internet Layer = "internet"
	DNS      Layer = "dns"
)

// Layers lists the watched layers from the bottom up.
var Layers = []Layer{Gateway, Internet, DNS}

// Probe is one measurement of one layer.
type Probe struct {
	Ran  bool    `json:"ran"` // false: the layer can't be measured (e.g. no gateway)
	OK   bool    `json:"ok"`  // an answer arrived in time
	Ms   float64 `json:"ms"`  // round trip when OK
	Note string  `json:"note,omitempty"`
}

// Sample is one tick: a probe of every layer, taken in parallel.
type Sample struct {
	At       time.Time `json:"at"`
	Gateway  Probe     `json:"gateway"`
	Internet Probe     `json:"internet"`
	DNS      Probe     `json:"dns"`
	Notes    []string  `json:"notes,omitempty"` // one-off notes, e.g. a switch to TCP
}

// Get returns the probe for layer l.
func (s Sample) Get(l Layer) Probe {
	switch l {
	case Gateway:
		return s.Gateway
	case Internet:
		return s.Internet
	}
	return s.DNS
}

// Options configures a watch.
type Options struct {
	Duration time.Duration
	Interval time.Duration // default 1s
	Gateway  string        // "" leaves the gateway unmeasured
	Config   config.Config
	// SystemResolver, if set, is queried instead of the OS resolver (test hook,
	// mirrors checks.Options.SystemResolver).
	SystemResolver string
	// Probe, if set, replaces the real measurement of a layer (test hook).
	Probe func(ctx context.Context, l Layer) Probe
}

// icmpGrace is how many ticks a target may go unanswered over ICMP before
// TCP is tried instead; some routers and networks drop all ICMP.
const icmpGrace = 3

// Start runs the watch in the background and sends one Sample per tick. The
// channel is closed when the duration is up or ctx is cancelled.
func Start(ctx context.Context, o Options) <-chan Sample {
	if o.Interval <= 0 {
		o.Interval = time.Second
	}
	ch := make(chan Sample, 4)
	w := &watcher{o: o, internet: map[string]*target{}}
	w.gw = &target{host: o.Gateway, ports: []string{"80", "443", "53"}}
	for _, h := range o.Config.Hosts.Internet {
		w.internet[h] = &target{host: h, ports: []string{"443"}}
	}
	go func() {
		defer close(ch)
		ctx, cancel := context.WithTimeout(ctx, o.Duration)
		defer cancel()
		tick := time.NewTicker(o.Interval)
		defer tick.Stop()
		for {
			s := w.sample(ctx)
			if ctx.Err() != nil {
				return
			}
			select {
			case ch <- s:
			case <-ctx.Done():
				return
			}
			select {
			case <-tick.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
}

type watcher struct {
	o        Options
	gw       *target
	internet map[string]*target

	mu    sync.Mutex
	notes []string // collected during the current tick
}

// target tracks whether a host answers ICMP or needs TCP instead.
type target struct {
	host     string
	ports    []string
	tcpPort  string // set once ICMP gave up and a TCP port answered
	answered bool   // ICMP has answered at least once
	misses   int
}

func (w *watcher) sample(ctx context.Context) Sample {
	s := Sample{At: time.Now()}
	var wg sync.WaitGroup
	run := func(l Layer, dst *Probe) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w.o.Probe != nil {
				*dst = w.o.Probe(ctx, l)
				return
			}
			switch l {
			case Gateway:
				*dst = w.probeGateway(ctx)
			case Internet:
				*dst = w.probeInternet(ctx)
			case DNS:
				*dst = w.probeDNS(ctx)
			}
		}()
	}
	run(Gateway, &s.Gateway)
	run(Internet, &s.Internet)
	run(DNS, &s.DNS)
	wg.Wait()
	w.mu.Lock()
	s.Notes, w.notes = w.notes, nil
	w.mu.Unlock()
	return s
}

// budget is the per-probe timeout: just under one tick, so samples don't
// pile up and a late answer counts as lost.
func (w *watcher) budget() time.Duration {
	return w.o.Interval * 9 / 10
}

func (w *watcher) note(format string, a ...any) {
	w.mu.Lock()
	w.notes = append(w.notes, fmt.Sprintf(format, a...))
	w.mu.Unlock()
}

func (w *watcher) probeGateway(ctx context.Context) Probe {
	if w.gw.host == "" {
		return Probe{}
	}
	return w.probeTarget(ctx, w.gw, "gateway")
}

// probeInternet probes every internet host; the internet counts as lost only
// when none of them answered, so one flaky host isn't blamed on the link.
func (w *watcher) probeInternet(ctx context.Context) Probe {
	if len(w.internet) == 0 {
		return Probe{}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	best := Probe{Ran: true}
	for _, t := range w.internet {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := w.probeTarget(ctx, t, t.host)
			mu.Lock()
			defer mu.Unlock()
			if p.OK && (!best.OK || p.Ms < best.Ms) {
				best = p
			}
		}()
	}
	wg.Wait()
	return best
}

func (w *watcher) probeTarget(ctx context.Context, t *target, label string) Probe {
	budget := w.budget()
	if t.tcpPort != "" {
		r := probe.TCPConnect(ctx, net.JoinHostPort(t.host, t.tcpPort), 1, budget)
		if r.Reachable() {
			return Probe{Ran: true, OK: true, Ms: r.Stats.AvgMs}
		}
		return Probe{Ran: true}
	}
	res, _ := probe.Ping(ctx, t.host, probe.PingOptions{Count: 1, Interval: budget / 4, Timeout: budget * 3 / 4})
	if res.Stats.Received > 0 {
		t.answered = true
		return Probe{Ran: true, OK: true, Ms: res.Stats.AvgMs}
	}
	t.misses++
	if !t.answered && t.misses >= icmpGrace && ctx.Err() == nil {
		for _, port := range t.ports {
			if r := probe.TCPConnect(ctx, net.JoinHostPort(t.host, port), 1, budget); r.Reachable() {
				t.tcpPort = port
				w.note("%s doesn't answer pings; watching it over TCP port %s instead", label, port)
				return Probe{Ran: true, OK: true, Ms: r.Stats.AvgMs}
			}
		}
	}
	return Probe{Ran: true}
}

// probeDNS resolves a random name under a test domain. The random label
// defeats resolver caches, so every tick really reaches the DNS server; the
// expected answer is NXDOMAIN, which counts as working DNS.
func (w *watcher) probeDNS(ctx context.Context) Probe {
	domains := w.o.Config.Hosts.DNSTestDomains
	if len(domains) == 0 {
		return Probe{}
	}
	name := fmt.Sprintf("hn-%08x.%s", rand.Uint32(), domains[rand.IntN(len(domains))])
	var q probe.DNSQuery
	if w.o.SystemResolver != "" {
		q = probe.QueryResolver(ctx, w.o.SystemResolver, name, dns.TypeA, w.budget())
	} else {
		q = probe.QuerySystem(ctx, name, dns.TypeA, w.budget())
	}
	if q.Rcode == "NOERROR" || q.Rcode == "NXDOMAIN" {
		return Probe{Ran: true, OK: true, Ms: q.Ms}
	}
	return Probe{Ran: true, Note: q.Rcode}
}
