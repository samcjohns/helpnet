package interpret

import (
	"fmt"
	"math"
	"strings"

	"github.com/samcjohns/nethelp/internal/checks"
	"github.com/samcjohns/nethelp/internal/config"
	"github.com/samcjohns/nethelp/internal/probe"
	"github.com/samcjohns/nethelp/internal/sysinfo"
)

// Rule identifiers, one per kind of finding.
const (
	RuleNoNetwork        = "no-network"
	RuleWeakWiFi         = "weak-wifi"
	RuleProxy            = "proxy"
	RuleVPNLatency       = "vpn-latency"
	RuleVPNActive        = "vpn-active"
	RuleGatewayDown      = "gateway-unreachable"
	RuleGatewayNoPing    = "gateway-no-ping"
	RuleLocalNetwork     = "local-network"
	RuleCaptivePortal    = "captive-portal"
	RuleInternetDown     = "internet-down"
	RuleICMPBlocked      = "icmp-blocked"
	RuleISP              = "isp"
	RuleInternetKnockOn  = "internet-knock-on"
	RuleSingleHost       = "single-host"
	RuleDNSDown          = "dns-down"
	RuleDNSSystemDown    = "dns-system-down"
	RuleDNSSystemSlow    = "dns-system-slow"
	RuleDNSAllSlow       = "dns-all-slow"
	RuleDNSFailures      = "dns-failures"
	RuleDNSDiffers       = "dns-differs"
	RuleDNSPublicBlocked = "dns-public-blocked"
	RuleHTTPFailed       = "http-failed"
	RuleHTTPPartial      = "http-partial"
	RuleHTTPStatus       = "http-status"
	RuleTCPSlow          = "tcp-slow"
	RuleTLSInspection    = "tls-slow"
	RuleServerSlow       = "server-slow"
	RuleIPv6Broken       = "ipv6-broken"
	RuleIPv6Slow         = "ipv6-slow"
	RuleTraceJump        = "trace-latency-jump"
	RuleTraceLoss        = "trace-loss"
	RuleTraceRateLimit   = "trace-rate-limit"
	RuleSlowDownload     = "slow-download"
	RuleCGNAT            = "cgnat"
	RuleDoubleNAT        = "double-nat"
	RuleTailscaleDown    = "tailscale-not-connected"
	RuleTailscaleHealth  = "tailscale-health"
	RuleTailscaleNoUDP   = "tailscale-no-udp"
	RuleTailscaleHardNAT = "tailscale-hard-nat"
	RuleTailscaleRelayed = "tailscale-relayed"
	RuleTailscaleDirect  = "tailscale-direct"
	RuleHealthy          = "healthy"
)

// grade returns the severity of v where larger is worse.
func grade(v, warn, fail float64) Severity {
	switch {
	case v > fail:
		return Fail
	case v > warn:
		return Warn
	}
	return Info
}

// gradeLow returns the severity of v where smaller is worse.
func gradeLow(v, warn, fail float64) Severity {
	switch {
	case v < fail:
		return Fail
	case v < warn:
		return Warn
	}
	return Info
}

func maxSev(s ...Severity) Severity {
	m := Info
	for _, v := range s {
		if v > m {
			m = v
		}
	}
	return m
}

func minSev(a, b Severity) Severity {
	if a < b {
		return a
	}
	return b
}

func ms(v float64) string {
	if v >= 10 {
		return fmt.Sprintf("%.0f ms", v)
	}
	return fmt.Sprintf("%.1f ms", v)
}

func pct(v float64) string {
	if v == math.Trunc(v) {
		return fmt.Sprintf("%.0f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}

// analysis carries cross-layer facts so rules can reason beyond one metric.
type analysis struct {
	r   *checks.Results
	th  config.Thresholds
	out []Finding

	wifi    bool
	gwSev   Severity // gateway latency/loss/jitter severity
	inetSev Severity // internet latency/loss/jitter severity
	dnsSev  Severity // system resolver severity

	cgnat bool // a CGNAT finding was added
}

func (a *analysis) add(f Finding) { a.out = append(a.out, f) }

// netSev is the worst network-level severity below DNS.
func (a *analysis) netSev() Severity { return maxSev(a.gwSev, a.inetSev) }

// Analyze runs every rule over the results and returns findings ordered by
// layer. It can be called on partial results; rules fire only once the data
// they need is present, which lets findings stream in during a run.
func Analyze(r *checks.Results, th config.Thresholds) []Finding {
	a := &analysis{r: r, th: th}
	if r.Local != nil {
		a.wifi = r.Local.Type == sysinfo.TypeWiFi
	}
	a.gwSev = a.gatewayMetricSev()
	a.inetSev = a.internetMetricSev()
	a.dnsSev = a.dnsMetricSev()

	a.localRules()
	a.gatewayRules()
	a.internetRules()
	a.dnsRules()
	a.httpRules()
	a.traceRules()
	a.speedRules()
	a.tailscaleRules()
	a.healthyRule()
	sortFindings(a.out)
	return a.out
}

// ---- Layer 0: local --------------------------------------------------------

func (a *analysis) localRules() {
	st, ok := a.r.States[checks.Local]
	if ok && st.Outcome == checks.OutcomeError {
		var skipped []string
		for _, id := range checks.Order[1:] {
			if s, ok := a.r.States[id]; ok && s.Outcome == checks.OutcomeSkipped {
				skipped = append(skipped, strings.ToLower(id.Title()))
			}
		}
		ev := "No default route: this machine is not connected to any network."
		if st.Error != "" && !strings.Contains(st.Error, "default route") {
			ev = "Could not detect a network interface: " + st.Error
		}
		if len(skipped) > 0 {
			ev += " Everything beyond this point is unreachable (skipped: " + strings.Join(skipped, ", ") + ")."
		}
		a.add(Finding{Rule: RuleNoNetwork, Severity: Fail, Layer: checks.Local, Confidence: High,
			Title:      "No network connection",
			Evidence:   ev,
			Suggestion: "Check that Wi-Fi is turned on and connected, or that the Ethernet cable is plugged in. Then run nethelp again.",
		})
		return
	}
	l := a.r.Local
	if l == nil || !a.r.Ran(checks.Local) {
		return
	}
	if w := l.WiFi; w != nil && w.Quality() > 0 && w.Quality() < 40 {
		sev := Warn
		ev := fmt.Sprintf("Wi-Fi signal quality is %d%%", w.Quality())
		if w.SignalDBm != 0 {
			ev = fmt.Sprintf("Wi-Fi signal is %d dBm (≈%d%%)", w.SignalDBm, w.Quality())
		}
		if w.LinkRateMbps > 0 {
			ev += fmt.Sprintf(", link rate %.0f Mbps", w.LinkRateMbps)
		}
		a.add(Finding{Rule: RuleWeakWiFi, Severity: sev, Layer: checks.Local, Confidence: Medium,
			Title:      "Weak Wi-Fi signal",
			Evidence:   ev + ".",
			Suggestion: "Move closer to the router, remove obstructions, or use Ethernet.",
		})
	}
	if l.Proxy.Detected {
		a.add(Finding{Rule: RuleProxy, Severity: Info, Layer: checks.Local, Confidence: Medium,
			Title:      "Web traffic goes through a proxy",
			Evidence:   strings.Join(l.Proxy.Sources, "; ") + ".",
			Suggestion: "If pages are slow, the proxy may be the bottleneck; compare with the proxy disabled if you can.",
		})
	}
	if l.VPN.DefaultRoute {
		latencyUp := a.inetSev >= Warn && a.gwSev < Warn
		if h := a.r.HTTP; h != nil && h.OK > 0 {
			latencyUp = latencyUp || grade(h.ConnectMs, a.th.TCPWarnMs, a.th.TCPFailMs) >= Warn
		}
		names := strings.Join(l.VPN.Interfaces, ", ")
		if names == "" {
			names = "a VPN tunnel"
		}
		if latencyUp {
			a.add(Finding{Rule: RuleVPNLatency, Severity: Warn, Layer: checks.Local, Confidence: Medium,
				Title:      "Your VPN may be adding latency",
				Evidence:   fmt.Sprintf("Internet traffic is routed through %s and latency beyond your router is elevated%s.", names, a.internetEvidenceSuffix()),
				Suggestion: "Run nethelp again with the VPN disconnected to compare, or pick a closer VPN server.",
			})
		} else {
			a.add(Finding{Rule: RuleVPNActive, Severity: Info, Layer: checks.Local, Confidence: High,
				Title:    "Traffic goes through a VPN",
				Evidence: fmt.Sprintf("The default route uses %s. Latency looks fine through it.", names),
			})
		}
	}
	a.localCGNAT()
}

func (a *analysis) internetEvidenceSuffix() string {
	if in := a.r.Internet; in != nil {
		if p := in.BestPing(); p != nil {
			return fmt.Sprintf(" (%s avg to %s)", ms(p.Stats.AvgMs), p.Host)
		}
	}
	return ""
}

// ---- Layer 1: gateway ------------------------------------------------------

func (a *analysis) gatewayLatencyLimits() (warn, fail float64) {
	if a.r.Local != nil && a.r.Local.Type == sysinfo.TypeEthernet {
		return a.th.GatewayEthernetWarnMs, a.th.GatewayEthernetFailMs
	}
	// Wi-Fi, and anything we can't classify, gets the more lenient limits.
	return a.th.GatewayWiFiWarnMs, a.th.GatewayWiFiFailMs
}

// gatewayDeprioritized reports whether the router answers pings to itself
// worse than it forwards traffic: loss/latency to the gateway that does not
// show up on the path through it to the internet. Many routers rate-limit
// or deprioritise ICMP addressed to themselves, which is harmless.
func (a *analysis) gatewayDeprioritized() (loss, latency bool) {
	g, in := a.r.Gateway, a.r.Internet
	if g == nil || in == nil || !a.r.Ran(checks.Internet) || in.ICMPBlocked || !in.Reachable {
		return false, false
	}
	best := bestInternetStats(in)
	if best == nil {
		return false, false
	}
	gs, is := g.Ping.Stats, best.Stats
	loss = gs.LossPct > a.th.GatewayLossWarnPct && is.LossPct <= a.th.InternetLossWarnPct
	w, _ := a.gatewayLatencyLimits()
	latency = gs.AvgMs > w && is.AvgMs < gs.AvgMs
	return loss, latency
}

// gatewayReady reports whether gateway quality can be judged: it needs the
// internet results too, to tell real problems from ICMP deprioritisation.
func (a *analysis) gatewayReady() bool {
	g := a.r.Gateway
	if g == nil || !a.r.Ran(checks.Gateway) || g.Ping.Stats.Received == 0 {
		return false
	}
	_, internetDone := a.r.States[checks.Internet]
	return internetDone
}

// gatewaySevs grades the gateway metrics, ignoring any the router merely
// deprioritises.
func (a *analysis) gatewaySevs() (lat, loss, jitter Severity) {
	s := a.r.Gateway.Ping.Stats
	w, f := a.gatewayLatencyLimits()
	lat = grade(s.AvgMs, w, f)
	loss = grade(s.LossPct, a.th.GatewayLossWarnPct, a.th.GatewayLossFailPct)
	jitter = grade(s.JitterMs, a.th.JitterWarnMs, a.th.JitterFailMs)
	dLoss, dLat := a.gatewayDeprioritized()
	if dLoss {
		loss = Info
	}
	if dLat {
		lat, jitter = Info, Info
	}
	return lat, loss, jitter
}

func (a *analysis) gatewayMetricSev() Severity {
	if !a.gatewayReady() {
		return Info
	}
	return maxSev(a.gatewaySevs())
}

func (a *analysis) gatewayRules() {
	g := a.r.Gateway
	if g == nil || !a.r.Ran(checks.Gateway) {
		return
	}
	inetUp := a.r.Internet != nil && a.r.Internet.Reachable
	if !g.Reachable {
		if a.r.Internet != nil && !inetUp {
			a.add(Finding{Rule: RuleGatewayDown, Severity: Fail, Layer: checks.Gateway, Confidence: High,
				Title:      "Can't reach your router",
				Evidence:   fmt.Sprintf("The gateway %s did not answer ping or TCP, and the internet is unreachable.", g.Address),
				Suggestion: "Reconnect to Wi-Fi (or reseat the cable), then restart the router if that doesn't help.",
			})
		} else if inetUp {
			a.add(Finding{Rule: RuleGatewayNoPing, Severity: Info, Layer: checks.Gateway, Confidence: Medium,
				Title:    "Your router doesn't answer pings",
				Evidence: fmt.Sprintf("%s ignored ping and TCP probes, but the internet is reachable, so this is just how the router is configured.", g.Address),
			})
		}
		return
	}
	if g.ICMPBlocked {
		a.add(Finding{Rule: RuleGatewayNoPing, Severity: Info, Layer: checks.Gateway, Confidence: High,
			Title:    "Your router doesn't answer pings",
			Evidence: fmt.Sprintf("%s ignored ping but answered on TCP, so it is up; latency to it could not be measured.", g.Address),
		})
		return
	}
	if !a.gatewayReady() {
		return
	}
	s := g.Ping.Stats
	if dLoss, dLat := a.gatewayDeprioritized(); dLoss || dLat {
		var what []string
		if dLoss {
			what = append(what, fmt.Sprintf("%s loss", pct(s.LossPct)))
		}
		if dLat {
			what = append(what, fmt.Sprintf("avg %s", ms(s.AvgMs)))
		}
		a.add(Finding{Rule: RuleGatewayNoPing, Severity: Info, Layer: checks.Gateway, Confidence: Medium,
			Title:    "Your router deprioritises pings to itself (harmless)",
			Evidence: fmt.Sprintf("Pings to %s show %s, but traffic through it to the internet is better%s, so this is the router rate-limiting replies, not a network problem.", g.Address, strings.Join(what, " and "), a.internetEvidenceSuffix()),
		})
	}
	if a.gwSev < Warn {
		return
	}
	latSev, lossSev, _ := a.gatewaySevs()
	var title string
	conf := High
	switch {
	case lossSev >= latSev && lossSev >= Warn:
		title = "Packet loss on your local network"
	case latSev >= Warn:
		title = "Slow connection to your router"
	default:
		title = "Unstable connection to your router"
		conf = Medium
	}
	link := "your router"
	if a.r.Local != nil && a.r.Local.Type != "" {
		link = "your router over " + a.r.Local.Type
	}
	ev := fmt.Sprintf("Ping to %s (%s): avg %s, p95 %s, jitter %s, %s loss.",
		link, g.Address, ms(s.AvgMs), ms(s.P95Ms), ms(s.JitterMs), pct(s.LossPct))
	sugg := "Restart the router, and check the cable and router for faults."
	if a.wifi {
		sugg = "The problem is on your local network. Move closer to the router, reduce interference (microwaves, thick walls, crowded channels), or use Ethernet; restarting the router can help."
		if a.r.Local.WiFi != nil && a.r.Local.WiFi.Quality() > 0 && a.r.Local.WiFi.Quality() < 40 {
			ev += fmt.Sprintf(" Wi-Fi signal is weak (%d%%).", a.r.Local.WiFi.Quality())
		}
	}
	a.add(Finding{Rule: RuleLocalNetwork, Severity: a.gwSev, Layer: checks.Gateway, Confidence: conf,
		Title: title, Evidence: ev, Suggestion: sugg})
}

// ---- Layer 2: internet -----------------------------------------------------

// bestInternetStats picks the host with the least loss (then lowest latency):
// one bad public host shouldn't condemn your whole connection.
func bestInternetStats(in *checks.InternetResult) *probe.PingResult {
	var best *probe.PingResult
	for i := range in.Pings {
		p := &in.Pings[i]
		if p.Stats.Received == 0 {
			continue
		}
		if best == nil || p.Stats.LossPct < best.Stats.LossPct ||
			p.Stats.LossPct == best.Stats.LossPct && p.Stats.AvgMs < best.Stats.AvgMs {
			best = p
		}
	}
	return best
}

func (a *analysis) internetMetricSev() Severity {
	in := a.r.Internet
	if in == nil || !a.r.Ran(checks.Internet) || !in.Reachable {
		return Info
	}
	if in.ICMPBlocked {
		if t := in.BestTCP(); t != nil {
			return grade(t.Stats.AvgMs, a.th.InternetWarnMs, a.th.InternetFailMs)
		}
		return Info
	}
	p := bestInternetStats(in)
	if p == nil {
		return Info
	}
	s := p.Stats
	return maxSev(
		grade(s.AvgMs, a.th.InternetWarnMs, a.th.InternetFailMs),
		grade(s.LossPct, a.th.InternetLossWarnPct, a.th.InternetLossFailPct),
		grade(s.JitterMs, a.th.JitterWarnMs, a.th.JitterFailMs),
	)
}

func (a *analysis) internetRules() {
	in := a.r.Internet
	if in == nil || !a.r.Ran(checks.Internet) {
		return
	}
	if c := in.Captive; c != nil && c.Detected {
		ev := fmt.Sprintf("The connectivity check %s returned HTTP %d", c.URL, c.Status)
		if c.Location != "" {
			ev += " redirecting to " + c.Location
		} else if c.BodySample != "" {
			ev += " with an unexpected page instead of an empty reply"
		}
		a.add(Finding{Rule: RuleCaptivePortal, Severity: Fail, Layer: checks.Internet, Confidence: High,
			Title:      "You're behind a login page (captive portal)",
			Evidence:   ev + ".",
			Suggestion: "Open a browser to any http:// site and sign in or accept the network's terms (common on hotel, airport and café Wi-Fi).",
		})
	}
	if !in.Reachable {
		if in.Captive != nil && in.Captive.Detected {
			return
		}
		ev := "No replies to ping or TCP 443 from " + strings.Join(hostsOf(in), ", ") + "."
		sugg := "Restart your modem and router. If that doesn't help, check your ISP's status page or contact them."
		title := "No internet connection"
		if g := a.r.Gateway; g != nil && g.Reachable {
			title = "Your router is reachable, but the internet isn't"
			ev = fmt.Sprintf("Router %s answers, but %s", g.Address, strings.ToLower(ev[:1])+ev[1:])
		}
		a.add(Finding{Rule: RuleInternetDown, Severity: Fail, Layer: checks.Internet, Confidence: High,
			Title: title, Evidence: ev, Suggestion: sugg})
		return
	}
	if in.ICMPBlocked {
		ev := "No ping replies from " + strings.Join(hostsOf(in), ", ")
		if t := in.BestTCP(); t != nil {
			ev += fmt.Sprintf(", but TCP connects to %s in %s", t.Addr, ms(t.Stats.AvgMs))
		}
		a.add(Finding{Rule: RuleICMPBlocked, Severity: Info, Layer: checks.Internet, Confidence: High,
			Title:    "Ping is blocked on this network (not a problem)",
			Evidence: ev + ". Latency is measured with TCP instead.",
		})
	}

	// One public host misbehaving while another is fine.
	if !in.ICMPBlocked && len(in.Pings) > 1 {
		best := bestInternetStats(in)
		for _, p := range in.Pings {
			if best == nil || p.Host == best.Host {
				continue
			}
			if p.Stats.LossPct > a.th.InternetLossFailPct && best.Stats.LossPct <= a.th.InternetLossWarnPct {
				a.add(Finding{Rule: RuleSingleHost, Severity: Info, Layer: checks.Internet, Confidence: Low,
					Title:    fmt.Sprintf("%s is dropping pings, but %s is fine", p.Host, best.Host),
					Evidence: fmt.Sprintf("%s: %s loss; %s: %s loss. This points at that host or its route, not your connection.", p.Host, pct(p.Stats.LossPct), best.Host, pct(best.Stats.LossPct)),
				})
			}
		}
	}

	if a.inetSev < Warn {
		return
	}
	ev := a.internetEvidence()
	switch {
	case a.gwSev >= Warn:
		// Downstream symptom of a local problem: never outrank the cause.
		a.add(Finding{Rule: RuleInternetKnockOn, Severity: minSev(a.inetSev, a.gwSev), Layer: checks.Internet, Confidence: Low,
			Title:    "Internet performance is also affected",
			Evidence: ev + " This is likely a knock-on effect of the local network problem above.",
		})
	case a.r.Local != nil && a.r.Local.VPN.DefaultRoute:
		// Explained by the VPN finding at layer 0.
	default:
		// Name the metric that actually fired.
		var latSev, lossSev Severity
		if in.ICMPBlocked {
			latSev = a.inetSev
		} else if p := bestInternetStats(in); p != nil {
			latSev = grade(p.Stats.AvgMs, a.th.InternetWarnMs, a.th.InternetFailMs)
			lossSev = grade(p.Stats.LossPct, a.th.InternetLossWarnPct, a.th.InternetLossFailPct)
		}
		title := "Unstable latency (jitter) between your router and the internet"
		conf := Low
		sugg := "Jitter usually comes from congestion: other devices streaming or uploading, or a busy ISP link. If it persists, restart the modem and contact your ISP with this report."
		switch {
		case lossSev >= Warn:
			title, conf = "Packet loss between your router and the internet", High
		case latSev >= Warn:
			title, conf = "High latency between your router and the internet", Medium
		}
		if conf != Low {
			sugg = "This is likely your ISP or modem. Restart the modem; if it persists, contact your ISP and share this report."
		}
		gwEv := ""
		if g := a.r.Gateway; g != nil && g.Ping.Stats.Received > 0 {
			gwEv = fmt.Sprintf("Your router responds fine (%s, %s loss), but ", ms(g.Ping.Stats.AvgMs), pct(g.Ping.Stats.LossPct))
			ev = strings.ToLower(ev[:1]) + ev[1:]
		}
		a.add(Finding{Rule: RuleISP, Severity: a.inetSev, Layer: checks.Internet, Confidence: conf,
			Title:      title,
			Evidence:   gwEv + ev,
			Suggestion: sugg,
		})
	}
}

func hostsOf(in *checks.InternetResult) []string {
	var hs []string
	for _, p := range in.Pings {
		hs = append(hs, p.Host)
	}
	return hs
}

func (a *analysis) internetEvidence() string {
	in := a.r.Internet
	if in.ICMPBlocked {
		if t := in.BestTCP(); t != nil {
			return fmt.Sprintf("TCP connect to %s averages %s.", t.Addr, ms(t.Stats.AvgMs))
		}
		return ""
	}
	p := bestInternetStats(in)
	if p == nil {
		return ""
	}
	s := p.Stats
	return fmt.Sprintf("Ping to %s: avg %s, p95 %s, jitter %s, %s loss.", p.Host, ms(s.AvgMs), ms(s.P95Ms), ms(s.JitterMs), pct(s.LossPct))
}

// ---- Layer 3: DNS ----------------------------------------------------------

func (a *analysis) dnsMetricSev() Severity {
	d := a.r.DNS
	if d == nil {
		return Info
	}
	sys := d.System()
	if sys == nil {
		return Info
	}
	if sys.Unreachable() {
		return Fail
	}
	return maxSev(grade(sys.AvgMs, a.th.DNSWarnMs, a.th.DNSFailMs), a.dnsFailureSev(sys))
}

func (a *analysis) dnsFailureSev(s *checks.ResolverStats) Severity {
	if len(s.Queries) == 0 {
		return Info
	}
	frac := float64(s.Failures) / float64(len(s.Queries))
	switch {
	case frac > 0.3:
		return Fail
	case frac > 0.1:
		return Warn
	}
	return Info
}

func (a *analysis) dnsRules() {
	d := a.r.DNS
	if d == nil {
		return
	}
	sys, pub := d.System(), d.BestPublic()
	if sys == nil {
		return
	}
	sysLabel := "your DNS resolver"
	if sys.Name != "" && sys.Name != "system" {
		sysLabel = "your DNS resolver (" + sys.Name + ")"
	}

	if sys.Unreachable() {
		if pub != nil {
			a.add(Finding{Rule: RuleDNSSystemDown, Severity: Fail, Layer: checks.DNS, Confidence: High,
				Title:      "Your DNS resolver isn't answering",
				Evidence:   fmt.Sprintf("All %d lookups via %s failed, but %s answered in %s.", len(sys.Queries), sysLabel, pub.Name, ms(pub.AvgMs)),
				Suggestion: "Set your DNS server to 1.1.1.1 or 9.9.9.9 (in your OS network settings or on the router), or restart the router.",
			})
		} else {
			a.add(Finding{Rule: RuleDNSDown, Severity: Fail, Layer: checks.DNS, Confidence: Medium,
				Title:      "DNS isn't working",
				Evidence:   "Neither your resolver nor public resolvers answered any lookup.",
				Suggestion: "Websites can't be found by name. Check the network findings above; a firewall or VPN may be blocking DNS.",
			})
		}
		return
	}

	pubOK := false
	for _, s := range d.Resolvers {
		if !s.System && s.Answered > 0 {
			pubOK = true
		}
	}
	if !pubOK && sys.Answered > 0 && len(d.Resolvers) > 1 {
		a.add(Finding{Rule: RuleDNSPublicBlocked, Severity: Info, Layer: checks.DNS, Confidence: Low,
			Title:    "Public DNS servers are blocked on this network",
			Evidence: "Direct queries to public resolvers got no reply, though your own resolver works. Many corporate and guest networks block outside DNS.",
		})
	}

	latSev := grade(sys.AvgMs, a.th.DNSWarnMs, a.th.DNSFailMs)
	if latSev >= Warn {
		pubFast := pub != nil && grade(pub.AvgMs, a.th.DNSWarnMs, a.th.DNSFailMs) == Info && pub.AvgMs*2 < sys.AvgMs
		switch {
		case pubFast:
			a.add(Finding{Rule: RuleDNSSystemSlow, Severity: latSev, Layer: checks.DNS, Confidence: High,
				Title:      "DNS lookups are slow",
				Evidence:   fmt.Sprintf("Lookups via %s average %s (first lookup %s); %s answered in %s.", sysLabel, ms(sys.AvgMs), ms(sys.ColdAvgMs), pub.Name, ms(pub.AvgMs)),
				Suggestion: fmt.Sprintf("Your configured DNS resolver is the bottleneck. Switch your DNS server to %s or 9.9.9.9 in your OS or router settings.", firstNonEmpty(pub.Server, "1.1.1.1")),
			})
		case a.netSev() >= Warn:
			a.add(Finding{Rule: RuleDNSAllSlow, Severity: minSev(latSev, a.netSev()), Layer: checks.DNS, Confidence: Low,
				Title:      "DNS is slow on every resolver",
				Evidence:   fmt.Sprintf("Lookups average %s via %s%s. General latency or packet loss is affecting DNS.", ms(sys.AvgMs), sysLabel, pubEvidence(pub)),
				Suggestion: "Fix the network findings above first; DNS should recover with them.",
			})
		default:
			a.add(Finding{Rule: RuleDNSAllSlow, Severity: latSev, Layer: checks.DNS, Confidence: Medium,
				Title:      "DNS is slow on every resolver",
				Evidence:   fmt.Sprintf("Lookups average %s via %s%s, although ping latency looks normal.", ms(sys.AvgMs), sysLabel, pubEvidence(pub)),
				Suggestion: "Something on the path may be delaying DNS packets (firewall, security software, VPN). Try another network to compare.",
			})
		}
	}

	if fs := a.dnsFailureSev(sys); fs >= Warn {
		parts := []string{}
		if sys.Timeouts > 0 {
			parts = append(parts, fmt.Sprintf("%d timed out", sys.Timeouts))
		}
		if sys.ServFail > 0 {
			parts = append(parts, fmt.Sprintf("%d SERVFAIL", sys.ServFail))
		}
		if other := sys.Failures - sys.Timeouts - sys.ServFail; other > 0 {
			parts = append(parts, fmt.Sprintf("%d errors", other))
		}
		a.add(Finding{Rule: RuleDNSFailures, Severity: fs, Layer: checks.DNS, Confidence: High,
			Title:      "Some DNS lookups fail",
			Evidence:   fmt.Sprintf("%d of %d lookups via %s failed (%s).", sys.Failures, len(sys.Queries), sysLabel, strings.Join(parts, ", ")),
			Suggestion: "Failed lookups make pages hang before loading. Switch to 1.1.1.1 or 9.9.9.9, or restart the router.",
		})
	}

	if len(d.Differences) > 0 {
		ev := d.Differences[0]
		if len(d.Differences) > 1 {
			ev += fmt.Sprintf(" (and %d more)", len(d.Differences)-1)
		}
		a.add(Finding{Rule: RuleDNSDiffers, Severity: Info, Layer: checks.DNS, Confidence: Medium,
			Title:      "Your resolver returns different answers than public DNS",
			Evidence:   ev + ".",
			Suggestion: "This may be intentional filtering (parental controls, ad blocking, workplace policy), or DNS interception. If a site won't load, compare using 1.1.1.1.",
		})
	}
}

func pubEvidence(pub *checks.ResolverStats) string {
	if pub == nil {
		return ""
	}
	return fmt.Sprintf(" and %s via %s", ms(pub.AvgMs), pub.Name)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---- Layer 4: HTTP ---------------------------------------------------------

func (a *analysis) httpRules() {
	st, ran := a.r.States[checks.HTTP]
	h := a.r.HTTP
	if !ran || h == nil {
		return
	}
	if st.Outcome == checks.OutcomeError || h.OK == 0 {
		inetUp := a.r.Internet == nil || a.r.Internet.Reachable
		if inetUp {
			a.add(Finding{Rule: RuleHTTPFailed, Severity: Fail, Layer: checks.HTTP, Confidence: Medium,
				Title:      "Couldn't load " + h.Host,
				Evidence:   firstNonEmpty(st.Error, "all requests failed") + ".",
				Suggestion: "The site may be down or blocked on this network. Try another site to confirm your connection works.",
			})
		}
		return
	}
	if failed := len(h.Samples) - h.OK; failed > 0 {
		var errMsg string
		for _, s := range h.Samples {
			if s.Error != "" {
				errMsg = s.Error
				break
			}
		}
		a.add(Finding{Rule: RuleHTTPPartial, Severity: Warn, Layer: checks.HTTP, Confidence: Medium,
			Title:      "Intermittent failures loading " + h.Host,
			Evidence:   fmt.Sprintf("%d of %d requests failed: %s.", failed, len(h.Samples), errMsg),
			Suggestion: "Intermittent failures usually come from packet loss or an overloaded server; see other findings.",
		})
	}
	if h.Status >= 400 {
		a.add(Finding{Rule: RuleHTTPStatus, Severity: Info, Layer: checks.HTTP, Confidence: High,
			Title:    fmt.Sprintf("%s returned HTTP %d", h.Host, h.Status),
			Evidence: "The connection worked, but the server answered with an error status.",
		})
	}

	netGood := a.netSev() < Warn
	tcpSev := grade(h.ConnectMs, a.th.TCPWarnMs, a.th.TCPFailMs)
	tlsSev := grade(h.TLSMs, a.th.TLSWarnMs, a.th.TLSFailMs)
	ttfbSev := grade(h.TTFBMs, a.th.TTFBWarnMs, a.th.TTFBFailMs)

	if tcpSev >= Warn {
		if netGood {
			a.add(Finding{Rule: RuleTCPSlow, Severity: tcpSev, Layer: checks.HTTP, Confidence: Medium,
				Title:      "Slow connection setup to " + h.Host,
				Evidence:   fmt.Sprintf("TCP connect averages %s while general internet latency is normal. The server may be far away or overloaded.", ms(h.ConnectMs)),
				Suggestion: "Try another site; if only this one is slow, the issue is on its side.",
			})
		} else {
			a.add(Finding{Rule: RuleTCPSlow, Severity: minSev(tcpSev, a.netSev()), Layer: checks.HTTP, Confidence: Low,
				Title:    "Slow connection setup to " + h.Host,
				Evidence: fmt.Sprintf("TCP connect averages %s, consistent with the network problems above.", ms(h.ConnectMs)),
			})
		}
	}
	if tlsSev >= Warn {
		if tcpSev < Warn && h.TLSMs > 3*h.ConnectMs {
			a.add(Finding{Rule: RuleTLSInspection, Severity: tlsSev, Layer: checks.HTTP, Confidence: Medium,
				Title:      "TLS handshakes are slow",
				Evidence:   fmt.Sprintf("TLS takes %s although TCP connects in %s.", ms(h.TLSMs), ms(h.ConnectMs)),
				Suggestion: "This often means TLS inspection by antivirus/security software, a corporate proxy, or a VPN. Try with those disabled to compare.",
			})
		} else {
			a.add(Finding{Rule: RuleTLSInspection, Severity: minSev(tlsSev, maxSev(tcpSev, a.netSev())), Layer: checks.HTTP, Confidence: Low,
				Title:    "TLS handshakes are slow",
				Evidence: fmt.Sprintf("TLS takes %s, in line with slow round trips (TCP connect %s).", ms(h.TLSMs), ms(h.ConnectMs)),
			})
		}
	}
	if ttfbSev >= Warn {
		if netGood && a.dnsSev < Warn {
			a.add(Finding{Rule: RuleServerSlow, Severity: ttfbSev, Layer: checks.HTTP, Confidence: High,
				Title:      "The website is slow, not your connection",
				Evidence:   fmt.Sprintf("%s takes %s to send its first byte, while your network and DNS look healthy (TCP connect %s).", h.Host, ms(h.TTFBMs), ms(h.ConnectMs)),
				Suggestion: "Try another site to confirm. There's nothing to fix on your side; the server is slow to respond.",
			})
		} else {
			a.add(Finding{Rule: RuleServerSlow, Severity: minSev(ttfbSev, maxSev(a.netSev(), a.dnsSev)), Layer: checks.HTTP, Confidence: Low,
				Title:    "Slow response from " + h.Host,
				Evidence: fmt.Sprintf("Time to first byte averages %s; network issues above likely contribute.", ms(h.TTFBMs)),
			})
		}
	}

	if h.IPv4 != nil && h.IPv6 != nil && h.IPv4.Error == "" {
		v4, v6 := h.IPv4, h.IPv6
		hasV6 := a.r.Local != nil && a.r.Local.HasGlobalIPv6()
		switch {
		case v6.Error != "" && v6.TimedOut:
			a.add(Finding{Rule: RuleIPv6Broken, Severity: Warn, Layer: checks.HTTP, Confidence: High,
				Title:      "IPv6 connections hang",
				Evidence:   fmt.Sprintf("Over IPv6, %s timed out after %s; over IPv4 it loaded in %s. Browsers wait on the broken IPv6 path before falling back.", h.Host, ms(v6.TotalMs), ms(v4.TotalMs)),
				Suggestion: "Check your router's IPv6 settings or ask your ISP; as a workaround, temporarily disable IPv6 on this device.",
			})
		case v6.Error != "" && hasV6:
			a.add(Finding{Rule: RuleIPv6Broken, Severity: Warn, Layer: checks.HTTP, Confidence: Medium,
				Title:      "IPv6 connections fail",
				Evidence:   fmt.Sprintf("You have an IPv6 address, but connecting to %s over IPv6 failed (%s); IPv4 works (%s).", h.Host, v6.Error, ms(v4.TotalMs)),
				Suggestion: "Check your router's IPv6 settings or temporarily disable IPv6 on this device.",
			})
		case v6.Error == "" && v6.TotalMs > 2*v4.TotalMs+200:
			a.add(Finding{Rule: RuleIPv6Slow, Severity: Info, Layer: checks.HTTP, Confidence: Low,
				Title:    "IPv6 is slower than IPv4",
				Evidence: fmt.Sprintf("%s loaded in %s over IPv6 vs %s over IPv4.", h.Host, ms(v6.TotalMs), ms(v4.TotalMs)),
			})
		}
	}
}

// ---- Layer 5: trace --------------------------------------------------------

// TraceAnalysis is what the trace rules found; exported for the report.
type TraceAnalysis struct {
	LossHop      int // TTL where persistent loss begins, 0 if none
	JumpHop      int // TTL where a persistent latency jump begins, 0 if none
	JumpFromMs   float64
	JumpToMs     float64
	RateLimited  []int // TTLs with loss that does not persist downstream
	FinalReached bool
}

// AnalyzeTrace finds where loss or latency starts and persists to the
// destination. Loss at a middle hop that clears up downstream is ICMP
// rate-limiting on that router, not a real problem.
func AnalyzeTrace(hops []probe.TraceHop) TraceAnalysis {
	var ta TraceAnalysis
	var resp []probe.TraceHop
	for _, h := range hops {
		if h.Responded() {
			resp = append(resp, h)
		}
	}
	if len(resp) == 0 {
		return ta
	}
	last := resp[len(resp)-1]
	ta.FinalReached = len(hops) > 0 && hops[len(hops)-1].Responded()

	// Loss: first responding hop with loss such that every later responding
	// hop (through the final one) also loses packets.
	for i, h := range resp {
		if h.LossPct <= 0 {
			continue
		}
		persists := ta.FinalReached
		for _, d := range resp[i+1:] {
			if d.LossPct <= 0 {
				persists = false
				break
			}
		}
		if persists {
			ta.LossHop = h.TTL
			break
		}
		ta.RateLimited = append(ta.RateLimited, h.TTL)
	}

	// Latency jump: the largest step up that every later hop stays above.
	var bestJump float64
	for i := 1; i < len(resp); i++ {
		base := resp[i-1].AvgMs
		jump := resp[i].AvgMs - base
		if jump < 40 || resp[i].AvgMs < 1.5*base {
			continue
		}
		persists := true
		for _, d := range resp[i+1:] {
			if d.AvgMs < base+0.7*jump {
				persists = false
				break
			}
		}
		if persists && last.AvgMs >= base+0.7*jump && jump > bestJump {
			bestJump = jump
			ta.JumpHop, ta.JumpFromMs, ta.JumpToMs = resp[i].TTL, base, resp[i].AvgMs
		}
	}
	return ta
}

func hopLabel(hops []probe.TraceHop, ttl int) string {
	for _, h := range hops {
		if h.TTL != ttl {
			continue
		}
		label := fmt.Sprintf("hop %d", ttl)
		switch {
		case h.Name != "" && len(h.Hosts) > 0:
			return fmt.Sprintf("%s (%s, %s)", label, h.Name, h.Hosts[0])
		case len(h.Hosts) > 0:
			return fmt.Sprintf("%s (%s)", label, h.Hosts[0])
		}
		return label
	}
	return fmt.Sprintf("hop %d", ttl)
}

func (a *analysis) traceRules() {
	t := a.r.Trace
	if t == nil || !a.r.Ran(checks.Trace) || len(t.Hops) == 0 {
		return
	}
	ta := AnalyzeTrace(t.Hops)
	last := t.Hops[len(t.Hops)-1]
	if ta.LossHop > 0 {
		sev := grade(last.LossPct, a.th.InternetLossWarnPct, a.th.InternetLossFailPct)
		if sev == Info {
			sev = Warn
		}
		a.add(Finding{Rule: RuleTraceLoss, Severity: sev, Layer: checks.Trace, Confidence: Medium,
			Title:      fmt.Sprintf("Packet loss starts at %s", hopLabel(t.Hops, ta.LossHop)),
			Evidence:   fmt.Sprintf("Loss begins at hop %d and persists to the destination (%s at the last hop).", ta.LossHop, pct(last.LossPct)),
			Suggestion: hopSuggestion(ta.LossHop),
		})
	}
	if ta.JumpHop > 0 {
		sev := Info
		if a.inetSev >= Warn || ta.JumpToMs > a.th.InternetWarnMs {
			sev = Warn
		}
		a.add(Finding{Rule: RuleTraceJump, Severity: sev, Layer: checks.Trace, Confidence: Medium,
			Title:      fmt.Sprintf("Delay is introduced at %s", hopLabel(t.Hops, ta.JumpHop)),
			Evidence:   fmt.Sprintf("Latency rises from %s to %s at hop %d and stays high to the destination. Long-distance links legitimately add delay; a jump inside your ISP's network is more suspicious.", ms(ta.JumpFromMs), ms(ta.JumpToMs), ta.JumpHop),
			Suggestion: hopSuggestion(ta.JumpHop),
		})
	}
	a.traceNAT()
	if len(ta.RateLimited) > 0 && ta.LossHop == 0 {
		hops := make([]string, len(ta.RateLimited))
		for i, ttl := range ta.RateLimited {
			hops[i] = fmt.Sprint(ttl)
		}
		a.add(Finding{Rule: RuleTraceRateLimit, Severity: Info, Layer: checks.Trace, Confidence: High,
			Title:    "Some routers drop trace probes (harmless)",
			Evidence: fmt.Sprintf("Hop(s) %s show loss that does not continue to later hops: those routers rate-limit replies, which is not a real problem.", strings.Join(hops, ", ")),
		})
	}
}

func hopSuggestion(ttl int) string {
	switch {
	case ttl <= 1:
		return "That's your own router; restart it and check your local network."
	case ttl <= 3:
		return "That's close to you, likely your modem or ISP's first routers. Restart the modem; if it persists, report it to your ISP with this trace."
	}
	return "That's further out on the internet path. If it's within your ISP's network, report it to them with this trace; otherwise it's outside your control."
}

// ---- Layer 6: bandwidth ----------------------------------------------------

func (a *analysis) speedRules() {
	s := a.r.Speed
	if s == nil || !a.r.Ran(checks.Speed) {
		return
	}
	sev := gradeLow(s.DownloadMbps, a.th.DownloadWarnMbps, a.th.DownloadFailMbps)
	if sev < Warn {
		return
	}
	ev := fmt.Sprintf("Download %.1f Mbps, upload %.1f Mbps (via %s).", s.DownloadMbps, s.UploadMbps, firstNonEmpty(s.Server, s.Tool))
	sugg := "Check what speed your plan includes and whether other devices are using the connection; contact your ISP if it's well below your plan."
	if wifiLimitsSpeed(a.r) {
		ev += fmt.Sprintf(" Your Wi-Fi link rate is only %.0f Mbps.", a.r.Local.WiFi.LinkRateMbps)
		sugg = "Your Wi-Fi link is limiting speed. Move closer to the router, use the 5 GHz band, or use Ethernet."
	}
	a.add(Finding{Rule: RuleSlowDownload, Severity: sev, Layer: checks.Speed, Confidence: High,
		Title: "Download speed is low", Evidence: ev, Suggestion: sugg})
}

// wifiLimitsSpeed reports whether the Wi-Fi link rate is low enough to
// explain the measured download speed. Real throughput is roughly half the
// link rate, so a link under about twice the download speed is the ceiling.
func wifiLimitsSpeed(r *checks.Results) bool {
	l, s := r.Local, r.Speed
	return l != nil && s != nil && l.WiFi != nil && l.WiFi.LinkRateMbps > 0 && l.WiFi.LinkRateMbps < 2*s.DownloadMbps+50
}

// ---- NAT -------------------------------------------------------------------

// natHop is a trace hop that reveals NAT beyond your router.
type natHop struct {
	TTL  int
	Addr string
}

// findTraceNAT looks past your router (hop 1) for more NAT before the route
// reaches a public address: a hop in the CGNAT range (RFC 6598), or a
// private hop 2 that answers about as fast as hop 1, i.e. a second router on
// the same premises. A private hop 2 further away is usually just the ISP
// numbering its own routers privately, so it is not reported.
func findTraceNAT(hops []probe.TraceHop) (cgnat, private natHop) {
	var first *probe.TraceHop
	for i, h := range hops {
		if !h.Responded() || len(h.Hosts) == 0 {
			continue
		}
		if h.TTL <= 1 {
			first = &hops[i]
			continue
		}
		addr := h.Hosts[0]
		switch {
		case probe.IsCGNAT(addr):
			return natHop{h.TTL, addr}, private
		case probe.IsPublicAddr(addr):
			return cgnat, private
		case probe.IsPrivateAddr(addr) && h.TTL == 2 && first != nil && bestMs(h) <= bestMs(*first)+2:
			private = natHop{h.TTL, addr}
		}
	}
	return cgnat, private
}

func bestMs(h probe.TraceHop) float64 {
	if h.BestMs > 0 {
		return h.BestMs
	}
	return h.AvgMs
}

// localCGNAT spots CGNAT from this device's own address or its gateway,
// e.g. a phone hotspot or an ISP modem in bridge mode.
func (a *analysis) localCGNAT() {
	l := a.r.Local
	if l.Type == sysinfo.TypeVPN {
		return
	}
	var ev string
	for _, ip := range l.IPv4 {
		if probe.IsCGNAT(ip) {
			ev = fmt.Sprintf("This device's address %s is", ip)
			break
		}
	}
	if ev == "" && probe.IsCGNAT(l.Gateway) {
		ev = fmt.Sprintf("Your gateway %s is", l.Gateway)
	}
	if ev == "" {
		return
	}
	ev += " in 100.64.0.0/10, the range reserved for carrier-grade NAT (RFC 6598)."
	if a.tailscaleInUse() {
		ev += " Tailscale numbers its devices from the same range, so addresses on this network can clash with tailnet routes."
	}
	a.addCGNAT(checks.Local, Medium, ev)
}

// traceNAT reports NAT the route trace reveals beyond your router. A VPN
// default route hides the real path, so the trace says nothing about it.
func (a *analysis) traceNAT() {
	if a.cgnat || a.r.Local == nil || a.r.Local.VPN.DefaultRoute {
		return
	}
	cgnat, private := findTraceNAT(a.r.Trace.Hops)
	if cgnat.TTL > 0 {
		a.addCGNAT(checks.Trace, High, fmt.Sprintf("Hop %d (%s) is in 100.64.0.0/10, the range reserved for carrier-grade NAT (RFC 6598), and comes before any public address: your ISP shares one public IPv4 address between your router and other customers.", cgnat.TTL, cgnat.Addr))
		return
	}
	if private.TTL > 0 {
		a.add(Finding{Rule: RuleDoubleNAT, Severity: Info, Layer: checks.Trace, Confidence: Low,
			Title:      "There may be a second router between yours and the internet",
			Evidence:   fmt.Sprintf("Hop %d (%s) has a private address and answers almost as fast as your router, so traffic likely crosses a second router on your premises (for example an ISP modem/router in front of your own). It could also be your ISP numbering a very close router privately.", private.TTL, private.Addr),
			Suggestion: "If you have two routers, put one in bridge or access-point mode. Double NAT breaks port forwarding and makes peer-to-peer connections (Tailscale, games, video calls) harder.",
		})
	}
}

func (a *analysis) addCGNAT(layer checks.ID, conf Confidence, ev string) {
	a.cgnat = true
	if n := a.tailscaleNetcheck(); n != nil && n.UDP && n.HardNAT != nil && !*n.HardNAT {
		ev += " Tailscale's netcheck finds this NAT easy to traverse, so direct Tailscale connections should still work."
	}
	a.add(Finding{Rule: RuleCGNAT, Severity: Info, Layer: layer, Confidence: conf,
		Title:      "You're behind carrier-grade NAT (CGNAT)",
		Evidence:   ev,
		Suggestion: "Nothing is broken, but devices on the internet can't connect in to you: port forwarding won't work, and peer-to-peer apps (Tailscale, games, video calls) may fall back to relays. If you need inbound connections, ask your ISP for a public IPv4 address or use IPv6.",
	})
}

// ---- Tailscale -------------------------------------------------------------

func (a *analysis) tailscaleNetcheck() *probe.TailscaleNetcheck {
	if t := a.r.Tailscale; t != nil && a.r.Ran(checks.Tailscale) {
		return t.Netcheck
	}
	return nil
}

// tailscaleInUse reports whether this device runs Tailscale, judged by the
// Tailscale check or, before it has run, a tailscale interface.
func (a *analysis) tailscaleInUse() bool {
	if a.r.Tailscale != nil {
		return true
	}
	if l := a.r.Local; l != nil {
		for _, name := range l.VPN.Interfaces {
			if strings.HasPrefix(strings.ToLower(name), "tailscale") {
				return true
			}
		}
	}
	return false
}

func (a *analysis) tailscaleRules() {
	t := a.r.Tailscale
	if t == nil || !a.r.Ran(checks.Tailscale) {
		return
	}
	s, n := t.Status, t.Netcheck
	if !s.Running() {
		a.add(Finding{Rule: RuleTailscaleDown, Severity: Info, Layer: checks.Tailscale, Confidence: High,
			Title:      "Tailscale isn't connected",
			Evidence:   fmt.Sprintf("tailscaled reports state %q, so this device isn't on your tailnet.", s.BackendState),
			Suggestion: "Run tailscale up, or sign in from the Tailscale app.",
		})
	}
	if len(s.Health) > 0 {
		ev := strings.Join(s.Health, " ")
		if !strings.HasSuffix(ev, ".") {
			ev += "."
		}
		a.add(Finding{Rule: RuleTailscaleHealth, Severity: Warn, Layer: checks.Tailscale, Confidence: Medium,
			Title:      "Tailscale reports a problem",
			Evidence:   ev,
			Suggestion: "Run tailscale status for details; restarting Tailscale often clears transient warnings.",
		})
	}

	relayedEv := ""
	if s.Relayed > 0 {
		relayedEv = fmt.Sprintf(" %d of %d active peers are relayed through DERP (%s).", s.Relayed, s.Active, firstNonEmpty(strings.Join(s.RelayRegions, ", "), "unknown region"))
	}
	explained := false
	switch {
	case n == nil:
	case !n.UDP:
		explained = true
		a.add(Finding{Rule: RuleTailscaleNoUDP, Severity: Warn, Layer: checks.Tailscale, Confidence: High,
			Title:      "Tailscale can't use UDP on this network",
			Evidence:   "netcheck got no UDP replies from Tailscale's servers, so every connection goes through a DERP relay over HTTPS" + homeRelay(s, n) + "." + relayedEv,
			Suggestion: "Expect lower throughput and higher latency between your devices. A firewall is probably blocking outbound UDP; allow UDP to ports 41641 and 3478, or try another network.",
		})
	case n.HardNAT != nil && *n.HardNAT:
		explained = true
		sev, title := Info, "This network's NAT makes direct Tailscale connections harder"
		if s.Relayed > 0 {
			sev, title = Warn, "This network's NAT is forcing Tailscale through relays"
		}
		ev := "Your NAT gives each destination a different public port (a \"hard\" NAT), so peers can't predict where to reach you and need a relay unless their own side is easy to reach."
		if a.cgnat {
			ev += " This is typical of carrier-grade NAT, which this network is behind."
		}
		ev += relayedEv
		if n.IPv6 {
			ev += " IPv6 works, so peers that also have IPv6 can still connect directly."
		}
		sugg := "If this is your router, enable UPnP or NAT-PMP so Tailscale can open a port, and check for a second router (double NAT). Otherwise, run a Tailscale peer relay on a node with a public address."
		if a.cgnat {
			sugg = "The NAT belongs to your ISP, so router settings won't help. Ask your ISP for a public IPv4 address, make sure IPv6 works on your devices, or run a Tailscale peer relay on a node with a public address."
		}
		a.add(Finding{Rule: RuleTailscaleHardNAT, Severity: sev, Layer: checks.Tailscale, Confidence: High,
			Title: title, Evidence: ev, Suggestion: sugg})
	}

	switch {
	case s.Relayed > 0 && !explained:
		ev := strings.TrimSpace(relayedEv)
		if n != nil && n.UDP && n.HardNAT != nil && !*n.HardNAT {
			ev += " This network's NAT is easy to traverse, so the other devices' networks are the likely cause."
		}
		a.add(Finding{Rule: RuleTailscaleRelayed, Severity: Info, Layer: checks.Tailscale, Confidence: Medium,
			Title:      fmt.Sprintf("%d active Tailscale peer(s) relayed through DERP", s.Relayed),
			Evidence:   ev,
			Suggestion: "Run tailscale status to see which peers are relayed, and tailscale netcheck on those devices.",
		})
	case s.Active > 0 && s.Relayed == 0:
		ev := fmt.Sprintf("%d of %d active peers connect directly", s.Direct, s.Active)
		if s.PeerRelayed > 0 {
			ev += fmt.Sprintf(" and %d through a Tailscale peer relay", s.PeerRelayed)
		}
		a.add(Finding{Rule: RuleTailscaleDirect, Severity: Info, Layer: checks.Tailscale, Confidence: High,
			Title:    "No Tailscale peers are relayed through DERP",
			Evidence: ev + ".",
		})
	}
}

// homeRelay describes the DERP region traffic falls back to.
func homeRelay(s probe.TailscaleStatus, n *probe.TailscaleNetcheck) string {
	if s.HomeRelay == "" {
		return ""
	}
	if n != nil && n.DERPLatencyMs > 0 {
		return fmt.Sprintf(" (home relay %s, %s away)", s.HomeRelay, ms(n.DERPLatencyMs))
	}
	return " (home relay " + s.HomeRelay + ")"
}

// ---- Healthy ---------------------------------------------------------------

func (a *analysis) healthyRule() {
	for _, id := range []checks.ID{checks.Local, checks.Gateway, checks.Internet, checks.DNS, checks.HTTP} {
		if _, done := a.r.States[id]; !done {
			return // not finished yet
		}
	}
	for _, f := range a.out {
		if f.Severity >= Warn {
			return
		}
	}
	ev := "Your router, internet connection, DNS and the test site all responded within normal limits"
	if h := a.r.HTTP; h != nil && h.OK > 0 {
		ev += fmt.Sprintf(" (%s loaded in %s)", h.Host, ms(h.TotalMs))
	}
	a.add(Finding{Rule: RuleHealthy, Severity: Info, Layer: checks.HTTP, Confidence: High,
		Title:      "Your connection looks healthy right now",
		Evidence:   ev + ".",
		Suggestion: "If browsing is still slow, the cause is likely the browser itself (extensions, cache) or a specific site. Open DevTools → Network to see which requests are slow.",
	})
}
