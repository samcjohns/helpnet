package interpret

import (
	"strings"
	"testing"

	"github.com/samcjohns/nethelp/internal/checks"
	"github.com/samcjohns/nethelp/internal/probe"
	"github.com/samcjohns/nethelp/internal/sysinfo"
)

// expect runs Analyze and checks the primary diagnosis rule and severity.
func expect(t *testing.T, r *checks.Results, primaryRule string, sev Severity) []Finding {
	t.Helper()
	fs := Analyze(r, th)
	p, ok := Primary(fs)
	if !ok {
		t.Fatalf("no primary diagnosis; findings: %+v", fs)
	}
	if p.Rule != primaryRule || p.Severity != sev {
		t.Fatalf("primary = %s/%s (%q), want %s/%s\nall findings:\n%s", p.Rule, p.Severity, p.Title, primaryRule, sev, dump(fs))
	}
	return fs
}

func dump(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString("  " + f.Severity.String() + " " + f.Rule + ": " + f.Title + " — " + f.Evidence + "\n")
	}
	return b.String()
}

func TestHealthy(t *testing.T) {
	fs := expect(t, healthy(), RuleHealthy, Info)
	if f := find(fs, RuleHealthy); !strings.Contains(f.Suggestion, "DevTools") {
		t.Errorf("healthy suggestion should mention DevTools: %q", f.Suggestion)
	}
	for _, f := range fs {
		if f.Severity >= Warn {
			t.Errorf("unexpected %s finding %s", f.Severity, f.Rule)
		}
	}
}

func TestGatewayBadMeansLocalNetwork(t *testing.T) {
	r := healthy()
	r.Gateway.Ping = ping("192.168.1.1", 10, 95, 110, 90, 120, 100, 105, 98, 101) // 20% loss, ~100 ms
	// Internet suffers too, as it would through a bad router.
	r.Internet.Pings[0] = ping("1.1.1.1", 10, repeat(120, 8)...)
	r.Internet.Pings[1] = ping("8.8.8.8", 10, repeat(125, 8)...)
	fs := expect(t, r, RuleLocalNetwork, Fail)
	p, _ := Primary(fs)
	if p.Layer != checks.Gateway || !strings.Contains(p.Suggestion, "Ethernet") {
		t.Errorf("local network finding should suggest Ethernet: %+v", p)
	}
	knock := find(fs, RuleInternetKnockOn)
	if knock == nil || knock.Confidence != Low {
		t.Errorf("internet should be reported as a knock-on effect: %+v", knock)
	}
	if find(fs, RuleISP) != nil {
		t.Error("ISP must not be blamed when the gateway is bad")
	}
}

func TestEthernetUsesStricterGatewayLimits(t *testing.T) {
	r := healthy()
	r.Local.Type = sysinfo.TypeEthernet
	r.Local.WiFi = nil
	r.Gateway.Ping = ping("192.168.1.1", 10, repeat(12, 10)...) // fine on Wi-Fi, slow on Ethernet
	r.Internet.Pings[0] = ping("1.1.1.1", 10, repeat(30, 10)...)
	r.Internet.Pings[1] = ping("8.8.8.8", 10, repeat(32, 10)...)
	expect(t, r, RuleLocalNetwork, Warn)
}

func TestGatewayGoodInternetBadMeansISP(t *testing.T) {
	r := healthy()
	r.Internet.Pings[0] = ping("1.1.1.1", 10, repeat(240, 9)...)
	r.Internet.Pings[1] = ping("8.8.8.8", 10, repeat(250, 9)...)
	fs := expect(t, r, RuleISP, Fail)
	if p, _ := Primary(fs); !strings.Contains(p.Suggestion, "ISP") || p.Confidence != High {
		t.Errorf("ISP finding: %+v", p)
	}
}

func TestInternetJitterIsNamedAsJitter(t *testing.T) {
	r := healthy()
	// One spike: low average, no loss, but jitter just over the limit.
	r.Internet.Pings[0] = ping("1.1.1.1", 10, 25, 27, 21, 104, 26, 30, 21, 22, 22, 22)
	r.Internet.Pings[1] = ping("8.8.8.8", 10, 37, 32, 30, 82, 32, 36, 30, 30, 30, 30)
	fs := expect(t, r, RuleISP, Warn)
	p, _ := Primary(fs)
	if !strings.Contains(p.Title, "jitter") || p.Confidence != Low {
		t.Errorf("jitter-only finding should say so with low confidence: %+v", p)
	}
}

func TestICMPBlockedIsNotOffline(t *testing.T) {
	r := healthy()
	r.Gateway.Ping = ping("192.168.1.1", 10)
	r.Gateway.TCP = []probe.TCPResult{{Addr: "192.168.1.1:80", Attempts: 1, Refused: 1}}
	r.Gateway.ICMPBlocked = true
	r.Internet.Pings[0] = ping("1.1.1.1", 10)
	r.Internet.Pings[1] = ping("8.8.8.8", 10)
	r.Internet.ICMPBlocked = true
	fs := expect(t, r, RuleHealthy, Info)
	if find(fs, RuleICMPBlocked) == nil {
		t.Error("expected icmp-blocked finding")
	}
	if find(fs, RuleInternetDown) != nil {
		t.Error("internet must not be reported down when TCP 443 works")
	}
	if s := CheckStatus(checks.Internet, r, fs); s != StatusPass {
		t.Errorf("internet status = %s, want pass", s)
	}
	if rt := Score(r, th); rt.Grade == "Down" {
		t.Errorf("score must not be Down with ICMP blocked: %+v", rt)
	}
}

func TestICMPBlockedButSlowTCPStillFlagged(t *testing.T) {
	r := healthy()
	r.Internet.Pings = []probe.PingResult{ping("1.1.1.1", 10), ping("8.8.8.8", 10)}
	r.Internet.TCP = []probe.TCPResult{tcp("1.1.1.1:443", 260), tcp("8.8.8.8:443", 270)}
	r.Internet.ICMPBlocked = true
	expect(t, r, RuleISP, Fail)
}

func TestSystemDNSSlowPublicFast(t *testing.T) {
	r := healthy()
	r.DNS.Resolvers[0] = resolver("192.168.1.1", true, 412)
	fs := expect(t, r, RuleDNSSystemSlow, Fail)
	p, _ := Primary(fs)
	if !strings.Contains(p.Evidence, "412 ms") || !strings.Contains(p.Evidence, "14 ms") || !strings.Contains(p.Suggestion, "1.1.1.1") {
		t.Errorf("DNS finding should cite both resolvers and suggest switching: %+v", p)
	}
}

func TestAllDNSSlow(t *testing.T) {
	r := healthy()
	r.DNS.Resolvers = []checks.ResolverStats{resolver("192.168.1.1", true, 200), resolver("1.1.1.1", false, 190), resolver("9.9.9.9", false, 210)}
	fs := expect(t, r, RuleDNSAllSlow, Warn)
	if f := find(fs, RuleDNSAllSlow); f.Confidence != Medium {
		t.Errorf("with a healthy network, all-slow DNS should be medium confidence: %+v", f)
	}

	// With a bad network, DNS slowness is attributed to it and capped.
	r.Gateway.Ping = ping("192.168.1.1", 10, repeat(40, 10)...)
	r.Internet.Pings[0] = ping("1.1.1.1", 10, repeat(60, 10)...)
	r.Internet.Pings[1] = ping("8.8.8.8", 10, repeat(60, 10)...)
	r.DNS.Resolvers[0] = resolver("192.168.1.1", true, 400)
	fs = Analyze(r, th)
	f := find(fs, RuleDNSAllSlow)
	if f == nil || f.Confidence != Low || f.Severity != Warn {
		t.Errorf("DNS should defer to network findings: %+v", f)
	}
	if p, _ := Primary(fs); p.Rule != RuleLocalNetwork {
		t.Errorf("primary should be the network, got %s", p.Rule)
	}
}

func TestSystemResolverDown(t *testing.T) {
	r := healthy()
	sys := checks.ResolverStats{Name: "192.168.1.1", System: true}
	for i := 0; i < 2; i++ {
		sys.Queries = append(sys.Queries, probe.DNSQuery{Domain: "example.com", Type: "A", Rcode: "TIMEOUT", Ms: 3000})
	}
	sys.Failures, sys.Timeouts = 2, 2
	r.DNS.Resolvers[0] = sys
	expect(t, r, RuleDNSSystemDown, Fail)
}

func TestDNSAnswersDiffer(t *testing.T) {
	r := healthy()
	r.DNS.Differences = []string{"example.com: system resolver returns 0.0.0.0 (private/blocked address); 1.1.1.1 returns 93.184.215.14"}
	fs := expect(t, r, RuleHealthy, Info) // reported neutrally; not a problem by itself
	f := find(fs, RuleDNSDiffers)
	if f == nil || f.Severity != Info {
		t.Fatalf("expected info dns-differs finding: %+v", f)
	}
	if !strings.Contains(f.Suggestion, "filtering") || !strings.Contains(f.Suggestion, "interception") {
		t.Errorf("should mention possible causes neutrally: %q", f.Suggestion)
	}
}

func TestServerSlow(t *testing.T) {
	r := healthy()
	r.HTTP.TTFBMs = 2600
	fs := expect(t, r, RuleServerSlow, Fail)
	if p, _ := Primary(fs); p.Confidence != High || !strings.Contains(p.Title, "not your connection") {
		t.Errorf("server-slow: %+v", p)
	}
}

func TestTLSSlowTCPFast(t *testing.T) {
	r := healthy()
	r.HTTP.TLSMs = 450
	fs := expect(t, r, RuleTLSInspection, Warn)
	if p, _ := Primary(fs); p.Confidence != Medium || !strings.Contains(p.Suggestion, "inspection") {
		t.Errorf("tls finding: %+v", p)
	}
}

func TestIPv6Broken(t *testing.T) {
	r := healthy()
	r.HTTP.HasIPv4, r.HTTP.HasIPv6 = true, true
	r.HTTP.IPv4 = &probe.HTTPSample{Status: 200, TotalMs: 180}
	r.HTTP.IPv6 = &probe.HTTPSample{Error: "context deadline exceeded", TimedOut: true, TotalMs: 6000}
	fs := expect(t, r, RuleIPv6Broken, Warn)
	if p, _ := Primary(fs); p.Confidence != High || !strings.Contains(p.Suggestion, "IPv6") {
		t.Errorf("ipv6: %+v", p)
	}
	// An immediate failure on a machine with no IPv6 is normal: no finding.
	r.HTTP.IPv6 = &probe.HTTPSample{Error: "connect: network is unreachable", TotalMs: 1}
	if f := find(Analyze(r, th), RuleIPv6Broken); f != nil {
		t.Errorf("no IPv6 address: should not flag, got %+v", f)
	}
}

func TestVPNLatency(t *testing.T) {
	r := healthy()
	r.Local.VPN = sysinfo.VPNInfo{Active: true, DefaultRoute: true, Interfaces: []string{"utun4"}}
	r.Internet.Pings[0] = ping("1.1.1.1", 10, repeat(150, 10)...)
	r.Internet.Pings[1] = ping("8.8.8.8", 10, repeat(160, 10)...)
	fs := expect(t, r, RuleVPNLatency, Warn)
	if find(fs, RuleISP) != nil {
		t.Error("ISP finding should be suppressed when a VPN explains the latency")
	}
	if p, _ := Primary(fs); !strings.Contains(p.Suggestion, "VPN") {
		t.Errorf("vpn suggestion: %q", p.Suggestion)
	}
	// Healthy latency through a VPN is just noted.
	h := healthy()
	h.Local.VPN = sysinfo.VPNInfo{Active: true, DefaultRoute: true, Interfaces: []string{"wg0"}}
	fs = expect(t, h, RuleHealthy, Info)
	if find(fs, RuleVPNActive) == nil {
		t.Error("expected vpn-active info finding")
	}
}

func TestCaptivePortal(t *testing.T) {
	r := healthy()
	r.Internet.Captive = &probe.CaptiveResult{URL: "http://connectivitycheck.gstatic.com/generate_204", Status: 302, Location: "http://login.hotel.example/", Detected: true}
	fs := expect(t, r, RuleCaptivePortal, Fail)
	if p, _ := Primary(fs); !strings.Contains(p.Suggestion, "sign in") || !strings.Contains(p.Evidence, "login.hotel.example") {
		t.Errorf("captive: %+v", p)
	}
}

func TestNoNetwork(t *testing.T) {
	r := checks.NewResults()
	r.Local = &sysinfo.Info{}
	r.States[checks.Local] = checks.State{Outcome: checks.OutcomeError, Error: sysinfo.ErrNoRoute.Error()}
	for _, id := range []checks.ID{checks.Gateway, checks.Internet, checks.DNS, checks.HTTP, checks.Trace} {
		r.States[id] = checks.State{Outcome: checks.OutcomeSkipped, SkipReason: "no network connection"}
	}
	fs := expect(t, r, RuleNoNetwork, Fail)
	p, _ := Primary(fs)
	if !strings.Contains(p.Evidence, "unreachable") || !strings.Contains(p.Evidence, "dns") {
		t.Errorf("should explain downstream checks were skipped: %q", p.Evidence)
	}
	if len(fs) != 1 {
		t.Errorf("only the no-network finding expected, got:\n%s", dump(fs))
	}
	for _, id := range []checks.ID{checks.Gateway, checks.HTTP} {
		if s := CheckStatus(id, r, fs); s != StatusSkipped {
			t.Errorf("%s status = %s, want skipped", id, s)
		}
	}
	if rt := Score(r, th); rt.Grade != "Down" || rt.Score != 0 {
		t.Errorf("rating = %+v", rt)
	}
}

func TestInternetDownGatewayUp(t *testing.T) {
	r := healthy()
	r.Internet = &checks.InternetResult{
		Pings: []probe.PingResult{ping("1.1.1.1", 10), ping("8.8.8.8", 10)},
		TCP:   []probe.TCPResult{{Addr: "1.1.1.1:443", Attempts: 3, Error: "i/o timeout"}},
	}
	r.DNS, r.HTTP, r.Trace = nil, nil, nil
	for _, id := range []checks.ID{checks.DNS, checks.HTTP, checks.Trace} {
		r.States[id] = checks.State{Outcome: checks.OutcomeSkipped, SkipReason: "internet unreachable"}
	}
	fs := expect(t, r, RuleInternetDown, Fail)
	if p, _ := Primary(fs); !strings.Contains(p.Title, "router is reachable") {
		t.Errorf("title should say the router works: %q", p.Title)
	}
}

func TestRouterDeprioritisesPings(t *testing.T) {
	r := healthy()
	// 30% loss and 40 ms to the router, but clean and fast through it.
	r.Gateway.Ping = ping("192.168.1.1", 10, repeat(40, 7)...)
	fs := expect(t, r, RuleHealthy, Info)
	if find(fs, RuleLocalNetwork) != nil {
		t.Error("router ICMP deprioritisation must not be reported as a local network problem")
	}
	if f := find(fs, RuleGatewayNoPing); f == nil || f.Severity != Info {
		t.Errorf("expected info note about the router: %+v", f)
	}
}

func TestGatewayJudgedOnlyAfterInternet(t *testing.T) {
	r := healthy()
	r.Gateway.Ping = ping("192.168.1.1", 10, repeat(40, 7)...)
	r.Internet, r.DNS, r.HTTP, r.Trace = nil, nil, nil, nil
	for _, id := range []checks.ID{checks.Internet, checks.DNS, checks.HTTP, checks.Trace} {
		delete(r.States, id)
	}
	if fs := Analyze(r, th); len(fs) != 0 {
		t.Errorf("gateway findings should wait for internet results, got:\n%s", dump(fs))
	}
}

func TestPartialResultsAfterCancellation(t *testing.T) {
	r := healthy()
	r.DNS, r.HTTP, r.Trace = nil, nil, nil
	for _, id := range []checks.ID{checks.DNS, checks.HTTP, checks.Trace} {
		r.States[id] = checks.State{Outcome: checks.OutcomeSkipped, SkipReason: "cancelled"}
	}
	fs := Analyze(r, th) // must not panic
	for _, f := range fs {
		if f.Severity >= Warn {
			t.Errorf("unexpected problem in partial healthy results: %+v", f)
		}
	}
	rt := Score(r, th)
	if rt.Score != 100 || len(rt.Layers) != 2 {
		t.Errorf("partial rating should cover only measured layers: %+v", rt)
	}
	// Cancelled before anything finished: no conclusion at all.
	empty := checks.NewResults()
	empty.States[checks.Local] = checks.State{Outcome: checks.OutcomeSkipped, SkipReason: "cancelled"}
	if _, ok := Primary(Analyze(empty, th)); ok {
		t.Error("no primary diagnosis expected for an empty run")
	}
}

func TestSlowDownload(t *testing.T) {
	r := healthy()
	r.Local.WiFi.LinkRateMbps = 26
	r.Speed = &probe.SpeedResult{Tool: "librespeed-cli", DownloadMbps: 12, UploadMbps: 4}
	r.States[checks.Speed] = okState()
	fs := expect(t, r, RuleSlowDownload, Warn)
	if p, _ := Primary(fs); !strings.Contains(p.Suggestion, "Wi-Fi") {
		t.Errorf("should blame the slow Wi-Fi link: %q", p.Suggestion)
	}
}

func TestHTTPFailed(t *testing.T) {
	r := healthy()
	r.HTTP = &checks.HTTPResult{Host: "example.com", Samples: []probe.HTTPSample{{Error: "connection refused"}}}
	r.States[checks.HTTP] = checks.State{Outcome: checks.OutcomeError, Error: "all 1 requests failed: connection refused"}
	expect(t, r, RuleHTTPFailed, Fail)
}

func TestWeakWiFi(t *testing.T) {
	r := healthy()
	r.Local.WiFi = &sysinfo.WiFiInfo{SignalDBm: -84, Source: "iw"}
	fs := expect(t, r, RuleWeakWiFi, Warn)
	if find(fs, RuleHealthy) != nil {
		t.Error("healthy must not fire alongside a warning")
	}
}

func TestPrimaryPrefersSeverityThenLowestLayer(t *testing.T) {
	fs := []Finding{
		{Rule: "a", Severity: Warn, Layer: checks.Gateway, Confidence: High},
		{Rule: "b", Severity: Fail, Layer: checks.HTTP, Confidence: Medium},
		{Rule: "c", Severity: Fail, Layer: checks.DNS, Confidence: Low},
		{Rule: "d", Severity: Fail, Layer: checks.DNS, Confidence: High},
	}
	if p, _ := Primary(fs); p.Rule != "d" {
		t.Errorf("primary = %s, want d", p.Rule)
	}
}

func TestTraceRules(t *testing.T) {
	t.Run("latency jump persisting to destination", func(t *testing.T) {
		r := healthy()
		r.Trace.Hops = []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "10.0.0.1", 9, 0), hop(3, "72.14.215.85", 140, 0), hop(4, "93.184.215.14", 145, 0)}
		f := find(Analyze(r, th), RuleTraceJump)
		if f == nil || !strings.Contains(f.Title, "hop 3") || f.Severity != Warn {
			t.Fatalf("expected warn jump at hop 3: %+v", f)
		}
	})
	t.Run("mid-path loss that does not persist is rate limiting", func(t *testing.T) {
		r := healthy()
		r.Trace.Hops = []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "10.0.0.1", 9, 60), hop(3, "72.14.215.85", 15, 0), hop(4, "93.184.215.14", 18, 0)}
		fs := Analyze(r, th)
		if find(fs, RuleTraceLoss) != nil {
			t.Error("non-persistent loss must not be reported as a problem")
		}
		if f := find(fs, RuleTraceRateLimit); f == nil || f.Severity != Info {
			t.Errorf("expected rate-limit info: %+v", f)
		}
		if p, _ := Primary(fs); p.Rule != RuleHealthy {
			t.Errorf("primary = %s", p.Rule)
		}
	})
	t.Run("loss persisting to destination", func(t *testing.T) {
		r := healthy()
		r.Trace.Hops = []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "10.0.0.1", 9, 20), hop(3, "72.14.215.85", 15, 20), hop(4, "93.184.215.14", 18, 30)}
		f := find(Analyze(r, th), RuleTraceLoss)
		if f == nil || !strings.Contains(f.Title, "hop 2") || f.Severity != Fail {
			t.Fatalf("expected loss from hop 2: %+v", f)
		}
	})
	t.Run("silent destination is not loss", func(t *testing.T) {
		hops := []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "10.0.0.1", 9, 30), hop(3, "", 0, 100)}
		ta := AnalyzeTrace(hops)
		if ta.LossHop != 0 || ta.FinalReached {
			t.Errorf("unreached destination can't prove persistence: %+v", ta)
		}
	})
}

func TestCGNAT(t *testing.T) {
	t.Run("hop in shared address space before any public hop", func(t *testing.T) {
		r := healthy()
		r.Trace.Hops = []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "100.72.0.1", 9, 0), hop(3, "203.0.113.1", 15, 0), hop(4, "198.51.100.14", 18, 0)}
		fs := expect(t, r, RuleHealthy, Info)
		f := find(fs, RuleCGNAT)
		if f == nil || f.Layer != checks.Trace || f.Confidence != High || !strings.Contains(f.Evidence, "100.72.0.1") {
			t.Fatalf("expected CGNAT from hop 2: %+v", f)
		}
		if find(fs, RuleDoubleNAT) != nil {
			t.Error("CGNAT should not also be reported as double NAT")
		}
	})
	t.Run("shared address after a public hop is not CGNAT", func(t *testing.T) {
		r := healthy()
		r.Trace.Hops = []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "203.0.113.1", 9, 0), hop(3, "100.100.5.5", 15, 0), hop(4, "198.51.100.14", 18, 0)}
		if f := find(Analyze(r, th), RuleCGNAT); f != nil {
			t.Errorf("transit networks may use 100.64/10 internally: %+v", f)
		}
	})
	t.Run("trace through a VPN says nothing about the local NAT", func(t *testing.T) {
		r := healthy()
		r.Local.VPN = sysinfo.VPNInfo{Active: true, DefaultRoute: true, Interfaces: []string{"tailscale0"}}
		r.Trace.Hops = []probe.TraceHop{hop(1, "100.101.102.103", 20, 0), hop(2, "100.72.0.1", 25, 0), hop(3, "198.51.100.14", 30, 0)}
		if f := find(Analyze(r, th), RuleCGNAT); f != nil {
			t.Errorf("exit node hops are tailnet addresses, not CGNAT: %+v", f)
		}
	})
	t.Run("device address in shared space", func(t *testing.T) {
		r := healthy()
		r.Local.IPv4, r.Local.Gateway = []string{"100.80.3.4"}, "100.80.0.1"
		r.Local.VPN.Interfaces = []string{"tailscale0"}
		fs := Analyze(r, th)
		f := find(fs, RuleCGNAT)
		if f == nil || f.Layer != checks.Local || !strings.Contains(f.Evidence, "100.80.3.4") || !strings.Contains(f.Evidence, "Tailscale") {
			t.Fatalf("expected local CGNAT mentioning the Tailscale clash: %+v", f)
		}
		n := 0
		for _, f := range fs {
			if f.Rule == RuleCGNAT {
				n++
			}
		}
		if n != 1 {
			t.Errorf("CGNAT reported %d times:\n%s", n, dump(fs))
		}
	})
	t.Run("netcheck says the NAT is easy", func(t *testing.T) {
		r := healthy()
		r.Trace.Hops = []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "100.72.0.1", 9, 0), hop(3, "198.51.100.14", 18, 0)}
		withTailscale(r, 2, 2, 0, &probe.TailscaleNetcheck{UDP: true, IPv4: true, HardNAT: boolp(false)})
		f := find(Analyze(r, th), RuleCGNAT)
		if f == nil || !strings.Contains(f.Evidence, "direct Tailscale connections should still work") {
			t.Fatalf("CGNAT finding should relay netcheck's verdict: %+v", f)
		}
	})
}

func TestDoubleNAT(t *testing.T) {
	r := healthy()
	r.Trace.Hops = []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "192.168.0.1", 4, 0), hop(3, "203.0.113.1", 12, 0), hop(4, "198.51.100.14", 18, 0)}
	fs := expect(t, r, RuleHealthy, Info)
	if f := find(fs, RuleDoubleNAT); f == nil || f.Severity != Info || f.Confidence != Low || !strings.Contains(f.Evidence, "192.168.0.1") {
		t.Fatalf("expected possible double NAT at hop 2: %+v", f)
	}
	// The healthy fixture's private hop 2 is 6 ms past the router: the
	// ISP's own router, not a second one at home.
	if f := find(Analyze(healthy(), th), RuleDoubleNAT); f != nil {
		t.Errorf("distant private hop is not double NAT: %+v", f)
	}
}

func boolp(b bool) *bool { return &b }

// withTailscale adds a running Tailscale result with active peers split
// into direct and DERP-relayed.
func withTailscale(r *checks.Results, active, direct, relayed int, n *probe.TailscaleNetcheck) {
	s := probe.TailscaleStatus{BackendState: "Running", HomeRelay: "nyc", Peers: active + 2, Online: active + 1, Active: active, Direct: direct, Relayed: relayed}
	if relayed > 0 {
		s.RelayRegions = []string{"iad"}
	}
	r.Tailscale = &probe.TailscaleResult{Status: s, Netcheck: n}
	r.States[checks.Tailscale] = okState()
}

func TestTailscaleRules(t *testing.T) {
	t.Run("all direct", func(t *testing.T) {
		r := healthy()
		withTailscale(r, 3, 3, 0, &probe.TailscaleNetcheck{UDP: true, IPv4: true, HardNAT: boolp(false)})
		fs := expect(t, r, RuleHealthy, Info)
		if f := find(fs, RuleTailscaleDirect); f == nil || !strings.Contains(f.Evidence, "3 of 3") {
			t.Errorf("expected direct-connection info: %+v", f)
		}
	})
	t.Run("UDP blocked", func(t *testing.T) {
		r := healthy()
		withTailscale(r, 2, 0, 2, &probe.TailscaleNetcheck{IPv4: true, DERPLatencyMs: 22})
		fs := expect(t, r, RuleTailscaleNoUDP, Warn)
		f := find(fs, RuleTailscaleNoUDP)
		if !strings.Contains(f.Evidence, "home relay nyc, 22 ms away") || !strings.Contains(f.Evidence, "2 of 2 active peers") {
			t.Errorf("evidence %q", f.Evidence)
		}
		if find(fs, RuleTailscaleRelayed) != nil {
			t.Error("relayed peers are explained by the UDP finding")
		}
	})
	t.Run("hard NAT behind CGNAT with relayed peers", func(t *testing.T) {
		r := healthy()
		r.Trace.Hops = []probe.TraceHop{hop(1, "192.168.1.1", 3, 0), hop(2, "100.72.0.1", 9, 0), hop(3, "198.51.100.14", 18, 0)}
		withTailscale(r, 3, 1, 2, &probe.TailscaleNetcheck{UDP: true, IPv4: true, IPv6: true, HardNAT: boolp(true)})
		fs := expect(t, r, RuleTailscaleHardNAT, Warn)
		f := find(fs, RuleTailscaleHardNAT)
		for _, want := range []string{"carrier-grade NAT", "2 of 3 active peers", "IPv6 works"} {
			if !strings.Contains(f.Evidence, want) {
				t.Errorf("evidence missing %q: %s", want, f.Evidence)
			}
		}
		if !strings.Contains(f.Suggestion, "ISP") {
			t.Errorf("behind CGNAT, router settings won't help: %s", f.Suggestion)
		}
	})
	t.Run("hard NAT without relayed peers is only info", func(t *testing.T) {
		r := healthy()
		withTailscale(r, 0, 0, 0, &probe.TailscaleNetcheck{UDP: true, IPv4: true, HardNAT: boolp(true)})
		fs := expect(t, r, RuleHealthy, Info)
		if f := find(fs, RuleTailscaleHardNAT); f == nil || f.Severity != Info || !strings.Contains(f.Suggestion, "UPnP") {
			t.Errorf("expected hard NAT info suggesting UPnP: %+v", f)
		}
	})
	t.Run("relayed peers on an easy NAT blame the other side", func(t *testing.T) {
		r := healthy()
		withTailscale(r, 2, 1, 1, &probe.TailscaleNetcheck{UDP: true, IPv4: true, HardNAT: boolp(false)})
		f := find(Analyze(r, th), RuleTailscaleRelayed)
		if f == nil || f.Severity != Info || !strings.Contains(f.Evidence, "other devices' networks") {
			t.Errorf("expected relayed info: %+v", f)
		}
	})
	t.Run("not connected and health warnings", func(t *testing.T) {
		r := healthy()
		withTailscale(r, 0, 0, 0, nil)
		r.Tailscale.Status.BackendState = "NeedsLogin"
		r.Tailscale.Status.Health = []string{"You are logged out"}
		fs := expect(t, r, RuleTailscaleHealth, Warn)
		if f := find(fs, RuleTailscaleDown); f == nil || !strings.Contains(f.Evidence, "NeedsLogin") {
			t.Errorf("expected not-connected info: %+v", f)
		}
		if f := find(fs, RuleTailscaleHealth); f.Evidence != "You are logged out." {
			t.Errorf("health evidence %q", f.Evidence)
		}
	})
}
