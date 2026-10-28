package interpret

import (
	"strings"
	"testing"

	"github.com/samcjohns/nethelp/internal/checks"
	"github.com/samcjohns/nethelp/internal/probe"
	"github.com/samcjohns/nethelp/internal/sysinfo"
)

// explainOne analyses r and expects exactly one explanation, for rule.
func explainOne(t *testing.T, r *checks.Results, rule, goos string) Explanation {
	t.Helper()
	es := Explain(r, Analyze(r, th), goos)
	if len(es) != 1 || es[0].Rule != rule {
		t.Fatalf("want one %s explanation, got %+v", rule, es)
	}
	return es[0]
}

func containsAll(t *testing.T, what, s string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("%s missing %q:\n%s", what, w, s)
		}
	}
}

func TestExplainHealthyHasNothing(t *testing.T) {
	if es := Explain(healthy(), Analyze(healthy(), th), "linux"); len(es) != 0 {
		t.Errorf("healthy run should have nothing to explain: %+v", es)
	}
	if es := Explain(checks.NewResults(), nil, "linux"); len(es) != 0 {
		t.Errorf("empty run should have nothing to explain: %+v", es)
	}
}

func TestExplainDNSSlow(t *testing.T) {
	r := healthy()
	r.DNS.Resolvers[0] = resolver("192.168.1.1", true, 180)
	r.DNS.Resolvers[1] = resolver("1.1.1.1", false, 15)
	e := explainOne(t, r, RuleDNSSystemSlow, "windows")
	containsAll(t, "what", e.What, "example.com and google.com", "Your router (192.168.1.1) answered in 180 ms", "12× slower", "Cloudflare's DNS server (1.1.1.1) at 15 ms")
	containsAll(t, "fix", e.Fix, "Cloudflare", "1.1.1.1", "1.0.0.1")
	steps := strings.Join(e.Steps, "\n")
	containsAll(t, "windows steps", steps, "Network & internet → Wi-Fi", "Preferred DNS", "router's admin page")

	// The steps follow the OS.
	mac := explainOne(t, r, RuleDNSSystemSlow, "darwin")
	containsAll(t, "mac steps", strings.Join(mac.Steps, "\n"), "System Settings → Network → Wi-Fi", "1.1.1.1 and 1.0.0.1")
	linux := explainOne(t, r, RuleDNSSystemSlow, "linux")
	containsAll(t, "linux steps", strings.Join(linux.Steps, "\n"), "IPv4 tab", `ipv4.dns "1.1.1.1 1.0.0.1"`)

	// The fastest public resolver is the one recommended.
	r.DNS.Resolvers[2] = resolver("9.9.9.9", false, 8)
	e = explainOne(t, r, RuleDNSSystemSlow, "linux")
	containsAll(t, "quad9", e.Fix+e.What, "Quad9", "9.9.9.9", "149.112.112.112", "22× slower")

	// A resolver that isn't the router is named as a DNS server.
	r.Local.DNSServers = []string{"198.51.100.53"}
	r.DNS.Resolvers[0].Name = "198.51.100.53"
	e = explainOne(t, r, RuleDNSSystemSlow, "linux")
	containsAll(t, "non-router", e.What, "Your DNS server (198.51.100.53)")
}

func TestExplainDNSSkippedWhenNotObvious(t *testing.T) {
	r := healthy()
	r.DNS.Resolvers[0] = resolver("192.168.1.1", true, 180)
	r.Local.VPN = sysinfo.VPNInfo{Active: true, Interfaces: []string{"wg0"}, DefaultRoute: true}
	if es := Explain(r, Analyze(r, th), "linux"); len(es) != 0 {
		t.Errorf("a VPN's resolver may be needed; no DNS explanation expected: %+v", es)
	}

	r = healthy()
	r.DNS.Resolvers[0] = resolver("192.168.1.1", true, 180)
	r.DNS.Differences = []string{"ads.example: system resolver returns 0.0.0.0 (private/blocked address); 1.1.1.1 returns 203.0.113.9"}
	if es := Explain(r, Analyze(r, th), "linux"); len(es) != 0 {
		t.Errorf("a filtering resolver is intentional; no DNS explanation expected: %+v", es)
	}
}

func TestExplainDNSDown(t *testing.T) {
	r := healthy()
	sys := resolver("192.168.1.1", true, 0)
	for i := range sys.Queries {
		sys.Queries[i].Rcode = "TIMEOUT"
	}
	sys.Answered, sys.Failures, sys.Timeouts = 0, len(sys.Queries), len(sys.Queries)
	r.DNS.Resolvers[0] = sys
	e := explainOne(t, r, RuleDNSSystemDown, "linux")
	containsAll(t, "what", e.What, "asked your router (192.168.1.1)", "8 times", "no answer", "Cloudflare's DNS server (1.1.1.1) answered", "14 ms")
	containsAll(t, "steps", strings.Join(e.Steps, "\n"), "Restarting the router")
}

func TestExplainCaptivePortal(t *testing.T) {
	r := healthy()
	r.Internet.Captive = &probe.CaptiveResult{URL: "http://connectivitycheck.gstatic.com/generate_204", Status: 302, Location: "http://login.hotel.example/portal?session=abc", Detected: true}
	es := Explain(r, Analyze(r, th), "linux")
	if len(es) == 0 || es[0].Rule != RuleCaptivePortal {
		t.Fatalf("want a captive portal explanation first, got %+v", es)
	}
	e := es[0]
	containsAll(t, "what", e.What, "generate_204", "HTTP 204", "HTTP 302", "login.hotel.example")
	containsAll(t, "steps", strings.Join(e.Steps, "\n"), "http://login.hotel.example", "neverssl.com")
	if strings.Contains(e.What+strings.Join(e.Steps, ""), "session=abc") {
		t.Error("only the portal's host should be shown, not its query string")
	}
}

func TestExplainWeakWiFi(t *testing.T) {
	r := healthy()
	r.Local.WiFi = &sysinfo.WiFiInfo{SignalDBm: -84, LinkRateMbps: 26, Source: "iw"}
	e := explainOne(t, r, RuleWeakWiFi, "linux")
	containsAll(t, "what", e.What, "-84 dBm (about 32%)", "26 Mbps", "Pings to your router averaged 3.0 ms with 0% loss")
	containsAll(t, "fix", e.Fix, "Ethernet")
}

func TestExplainWiFiLimitsSpeed(t *testing.T) {
	r := healthy()
	r.Local.WiFi.LinkRateMbps = 26
	r.Speed = &probe.SpeedResult{Tool: "librespeed-cli", DownloadMbps: 12, UploadMbps: 4}
	r.States[checks.Speed] = okState()
	e := explainOne(t, r, RuleSlowDownload, "linux")
	containsAll(t, "what", e.What, "12.0 Mbps", "26 Mbps", "roughly 13 Mbps")
	containsAll(t, "steps", strings.Join(e.Steps, "\n"), "yours is -55 dBm", "5GHz", "/speed")

	// Slow download on a fast Wi-Fi link has no obvious local fix.
	r.Local.WiFi.LinkRateMbps = 866
	if es := Explain(r, Analyze(r, th), "linux"); len(es) != 0 {
		t.Errorf("Wi-Fi isn't the limit; no explanation expected: %+v", es)
	}
}
