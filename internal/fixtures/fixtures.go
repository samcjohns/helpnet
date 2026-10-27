// Package fixtures builds synthetic check results for tests.
package fixtures

import (
	"github.com/samcjohns/helpnet/internal/checks"
	"github.com/samcjohns/helpnet/internal/probe"
	"github.com/samcjohns/helpnet/internal/sysinfo"
)

func Ping(host string, sent int, rtts ...float64) probe.PingResult {
	return probe.PingResult{Host: host, Method: "icmp", Stats: probe.Summarise(sent, rtts)}
}

func Repeat(v float64, n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TCP(addr string, ms float64) probe.TCPResult {
	return probe.TCPResult{Addr: addr, Attempts: 3, Connected: 3, Stats: probe.Summarise(3, Repeat(ms, 3))}
}

func Resolver(name string, system bool, avg float64) checks.ResolverStats {
	s := checks.ResolverStats{Name: name, Server: name, System: system}
	if system {
		s.Server = ""
	}
	for _, d := range []string{"example.com", "google.com"} {
		for i := 0; i < 3; i++ {
			s.Queries = append(s.Queries, probe.DNSQuery{Domain: d, Type: "A", Ms: avg, Rcode: "NOERROR", Answers: []string{"93.184.215.14"}})
		}
		s.Queries = append(s.Queries, probe.DNSQuery{Domain: d, Type: "AAAA", Ms: avg, Rcode: "NOERROR"})
	}
	s.Answered = len(s.Queries)
	s.AvgMs, s.MinMs, s.MaxMs, s.P95Ms, s.ColdAvgMs, s.WarmAvgMs = avg, avg, avg, avg, avg, avg
	return s
}

func OK() checks.State { return checks.State{Outcome: checks.OutcomeOK, DurationMs: 100} }

// Healthy returns a complete, healthy run on Wi-Fi.
func Healthy() *checks.Results {
	r := checks.NewResults()
	r.Local = &sysinfo.Info{
		Interface: "wlan0", Type: sysinfo.TypeWiFi, IPv4: []string{"192.168.1.42"},
		Gateway: "192.168.1.1", DNSServers: []string{"192.168.1.1"},
		WiFi: &sysinfo.WiFiInfo{SignalDBm: -55, LinkRateMbps: 433, Source: "iw"},
	}
	r.Gateway = &checks.GatewayResult{Address: "192.168.1.1", Ping: Ping("192.168.1.1", 10, Repeat(3, 10)...), Reachable: true}
	r.Internet = &checks.InternetResult{
		Pings:     []probe.PingResult{Ping("1.1.1.1", 10, Repeat(18, 10)...), Ping("8.8.8.8", 10, Repeat(21, 10)...)},
		TCP:       []probe.TCPResult{TCP("1.1.1.1:443", 19), TCP("8.8.8.8:443", 22)},
		Captive:   &probe.CaptiveResult{URL: "http://connectivitycheck.gstatic.com/generate_204", Status: 204},
		Reachable: true,
	}
	r.DNS = &checks.DNSResult{
		Domains:   []string{"example.com", "google.com"},
		Resolvers: []checks.ResolverStats{Resolver("192.168.1.1", true, 12), Resolver("1.1.1.1", false, 14), Resolver("9.9.9.9", false, 18)},
	}
	sample := probe.HTTPSample{URL: "https://example.com", FinalURL: "https://example.com", Status: 200, Proto: "HTTP/2.0", TLSVersion: "TLS 1.3",
		RemoteAddr: "93.184.215.14:443", DNSMs: 12, ConnectMs: 19, TLSMs: 41, TTFBMs: 112, TransferMs: 20, TotalMs: 204}
	r.HTTP = &checks.HTTPResult{Target: "https://example.com", Host: "example.com", Samples: []probe.HTTPSample{sample, sample, sample}, OK: 3,
		DNSMs: 12, ConnectMs: 19, TLSMs: 41, TTFBMs: 112, TransferMs: 20, TotalMs: 204, Status: 200, FinalURL: "https://example.com",
		Proto: "HTTP/2.0", TLSVersion: "TLS 1.3", RemoteAddr: "93.184.215.14:443"}
	r.Trace = &probe.TraceResult{Tool: "traceroute", Target: "example.com", Hops: []probe.TraceHop{
		Hop(1, "192.168.1.1", 3, 0), Hop(2, "10.0.0.1", 9, 0), Hop(3, "72.14.215.85", 15, 0), Hop(4, "93.184.215.14", 18, 0),
	}}
	for _, id := range []checks.ID{checks.Local, checks.Gateway, checks.Internet, checks.DNS, checks.HTTP, checks.Trace} {
		r.States[id] = OK()
	}
	return r
}

func Hop(ttl int, ip string, avg, loss float64) probe.TraceHop {
	h := probe.TraceHop{TTL: ttl, Sent: 10, LossPct: loss, AvgMs: avg, BestMs: avg, WorstMs: avg}
	h.Received = int(float64(h.Sent) * (1 - loss/100))
	if h.Received > 0 {
		h.Hosts = []string{ip}
	}
	return h
}
