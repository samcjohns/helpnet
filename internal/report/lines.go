package report

import (
	"fmt"
	"strings"

	"github.com/samcjohns/helpnet/internal/checks"
	"github.com/samcjohns/helpnet/internal/interpret"
	"github.com/samcjohns/helpnet/internal/probe"
)

// Line is the one-line result shown next to a finished check.
func Line(id checks.ID, r *checks.Results) string {
	st, ok := r.States[id]
	if !ok {
		return ""
	}
	switch st.Outcome {
	case checks.OutcomeSkipped:
		if st.Hint != "" {
			return st.SkipReason + " — " + st.Hint
		}
		return st.SkipReason
	case checks.OutcomeError:
		if id == checks.Local && r.Local != nil {
			return "not connected"
		}
		return firstLine(st.Error)
	}
	switch id {
	case checks.Local:
		l := r.Local
		parts := []string{l.Interface, l.Type}
		if len(l.IPv4) > 0 {
			parts = append(parts, l.IPv4[0])
		}
		if l.VPN.DefaultRoute {
			parts = append(parts, "VPN")
		}
		if l.Proxy.Detected {
			parts = append(parts, "proxy")
		}
		return strings.Join(nonEmpty(parts), " · ")
	case checks.Gateway:
		g := r.Gateway
		if g.ICMPBlocked {
			return g.Address + " · ignores ping, answers TCP"
		}
		if !g.Reachable {
			return g.Address + " · no reply"
		}
		return fmt.Sprintf("%s · %s · %s loss", g.Address, fmtMs(g.Ping.Stats.AvgMs), fmtPct(g.Ping.Stats.LossPct))
	case checks.Internet:
		in := r.Internet
		switch {
		case in.Captive != nil && in.Captive.Detected:
			return "captive portal detected"
		case !in.Reachable:
			return "unreachable"
		case in.ICMPBlocked:
			if t := in.BestTCP(); t != nil {
				return fmt.Sprintf("ping blocked · TCP %s %s", t.Addr, fmtMs(t.Stats.AvgMs))
			}
			return "ping blocked"
		}
		var parts []string
		for _, p := range in.Pings {
			if p.Stats.Received == 0 {
				parts = append(parts, p.Host+" no reply")
				continue
			}
			parts = append(parts, fmt.Sprintf("%s %s %s loss", p.Host, fmtMs(p.Stats.AvgMs), fmtPct(p.Stats.LossPct)))
		}
		return strings.Join(parts, " · ")
	case checks.DNS:
		var parts []string
		for _, s := range r.DNS.Resolvers {
			name := s.Name
			if s.System {
				name = "system"
			}
			if s.Unreachable() {
				parts = append(parts, name+" no answer")
				continue
			}
			parts = append(parts, fmt.Sprintf("%s %s", name, fmtMs(s.AvgMs)))
		}
		return strings.Join(parts, " · ")
	case checks.HTTP:
		h := r.HTTP
		return fmt.Sprintf("%s · TTFB %s · total %s", h.Host, fmtMs(h.TTFBMs), fmtMs(h.TotalMs))
	case checks.Trace:
		t := r.Trace
		s := fmt.Sprintf("%d hops via %s", len(t.Hops), t.Tool)
		if n := len(t.Hops); n > 0 && t.Hops[n-1].Responded() {
			s += " · " + fmtMs(t.Hops[n-1].AvgMs) + " to destination"
		} else {
			s += " · destination didn't reply"
		}
		return s
	case checks.Speed:
		s := r.Speed
		return fmt.Sprintf("↓ %.0f Mbps · ↑ %.0f Mbps · ping %s", s.DownloadMbps, s.UploadMbps, fmtMs(s.PingMs))
	case checks.Tailscale:
		return tailscaleLine(r.Tailscale)
	}
	return ""
}

func tailscaleLine(t *probe.TailscaleResult) string {
	s, n := t.Status, t.Netcheck
	if !s.Running() {
		return strings.ToLower(orDash(s.BackendState))
	}
	var parts []string
	switch {
	case s.Active == 0:
		parts = append(parts, "no active peers")
	case s.Relayed == 0:
		parts = append(parts, fmt.Sprintf("%d/%d active peers direct", s.Direct, s.Active))
	default:
		parts = append(parts, fmt.Sprintf("%d/%d active peers relayed", s.Relayed, s.Active))
	}
	if n != nil {
		switch {
		case !n.UDP:
			parts = append(parts, "UDP blocked")
		case n.HardNAT != nil && *n.HardNAT:
			parts = append(parts, "hard NAT")
		case n.HardNAT != nil:
			parts = append(parts, "easy NAT")
		}
	}
	if s.HomeRelay != "" {
		relay := "DERP " + s.HomeRelay
		if n != nil && n.DERPLatencyMs > 0 {
			relay += " " + fmtMs(n.DERPLatencyMs)
		}
		parts = append(parts, relay)
	}
	return strings.Join(parts, " · ")
}

func tailscaleDetails(t *probe.TailscaleResult) []string {
	s, n := t.Status, t.Netcheck
	d := []string{fmt.Sprintf("tailscale %s · state %s · MagicDNS %s · exit node %s", orDash(s.Version), orDash(s.BackendState), onOff(s.MagicDNS), yesNo(s.ExitNode))}
	d = append(d, fmt.Sprintf("peers: %d total · %d online · %d active (%d direct, %d via DERP, %d via peer relay)",
		s.Peers, s.Online, s.Active, s.Direct, s.Relayed, s.PeerRelayed))
	if len(s.RelayRegions) > 0 {
		d = append(d, "DERP regions carrying relayed peers: "+strings.Join(s.RelayRegions, ", "))
	}
	if n != nil {
		d = append(d, fmt.Sprintf("netcheck: UDP %s · IPv4 %s · IPv6 %s · NAT mapping varies by destination %s · hairpinning %s",
			yesNo(n.UDP), yesNo(n.IPv4), yesNo(n.IPv6), optYesNo(n.HardNAT), optYesNo(n.HairPinning)))
		d = append(d, fmt.Sprintf("port mapping: UPnP %s · NAT-PMP %s · PCP %s", optYesNo(n.UPnP), optYesNo(n.PMP), optYesNo(n.PCP)))
		relay := fmt.Sprintf("home DERP %s", orDash(s.HomeRelay))
		if n.DERPLatencyMs > 0 {
			relay += " · " + fmtMs(n.DERPLatencyMs)
		}
		d = append(d, relay)
	}
	for _, h := range s.Health {
		d = append(d, "health: "+h)
	}
	return d
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func optYesNo(b *bool) string {
	if b == nil {
		return "unknown"
	}
	return yesNo(*b)
}

// Details are the expanded per-check lines (per-sample timings etc.).
func Details(id checks.ID, r *checks.Results) []string {
	st := r.States[id]
	var d []string
	switch id {
	case checks.Local:
		if l := r.Local; l != nil && st.Outcome == checks.OutcomeOK {
			d = append(d, fmt.Sprintf("interface %s (%s)", l.Interface, l.Type))
			if len(l.IPv4) > 0 {
				d = append(d, "IPv4 "+strings.Join(l.IPv4, ", "))
			}
			if len(l.IPv6) > 0 {
				d = append(d, "IPv6 "+strings.Join(l.IPv6, ", "))
			}
			d = append(d, "gateway "+orDash(l.Gateway))
			dns := orDash(strings.Join(l.DNSServers, ", "))
			if l.DNSNote != "" {
				dns += " (" + l.DNSNote + ")"
			}
			d = append(d, "DNS servers "+dns)
			if w := l.WiFi; w != nil {
				s := fmt.Sprintf("Wi-Fi signal %d%%", w.Quality())
				if w.SignalDBm != 0 {
					s += fmt.Sprintf(" (%d dBm)", w.SignalDBm)
				}
				if w.LinkRateMbps > 0 {
					s += fmt.Sprintf(", link rate %.0f Mbps", w.LinkRateMbps)
				}
				d = append(d, s+" [via "+w.Source+"]")
			}
			switch {
			case l.VPN.DefaultRoute:
				d = append(d, "VPN carries internet traffic: "+orDash(strings.Join(l.VPN.Interfaces, ", ")))
			case len(l.VPN.Interfaces) > 0:
				d = append(d, "VPN/tunnel interfaces present (not default route): "+strings.Join(l.VPN.Interfaces, ", "))
			default:
				d = append(d, "no VPN detected")
			}
			if l.Proxy.Detected {
				d = append(d, "proxy: "+strings.Join(l.Proxy.Sources, "; "))
			} else {
				d = append(d, "no proxy configured")
			}
			d = append(d, l.Notes...)
		}
	case checks.Gateway:
		if g := r.Gateway; g != nil {
			d = append(d, pingDetail(g.Ping)...)
			for _, t := range g.TCP {
				d = append(d, tcpDetail(t))
			}
		}
	case checks.Internet:
		if in := r.Internet; in != nil {
			for _, p := range in.Pings {
				d = append(d, pingDetail(p)...)
			}
			for _, t := range in.TCP {
				d = append(d, tcpDetail(t))
			}
			if c := in.Captive; c != nil {
				switch {
				case c.Error != "":
					d = append(d, "captive-portal check: error: "+c.Error)
				case c.Detected:
					d = append(d, fmt.Sprintf("captive-portal check: HTTP %d %s — portal detected", c.Status, c.Location))
				default:
					d = append(d, fmt.Sprintf("captive-portal check: HTTP %d — no portal", c.Status))
				}
			}
		}
	case checks.DNS:
		if dr := r.DNS; dr != nil {
			d = append(d, "domains: "+strings.Join(dr.Domains, ", "))
			for _, s := range dr.Resolvers {
				label := s.Name
				if s.System {
					label = "system (" + s.Name + ")"
				}
				d = append(d, fmt.Sprintf("%s: avg %s · min %s · max %s · first lookups %s · repeats %s · %d failed · %d NXDOMAIN · %d AAAA answers",
					label, fmtMs(s.AvgMs), fmtMs(s.MinMs), fmtMs(s.MaxMs), fmtMs(s.ColdAvgMs), fmtMs(s.WarmAvgMs), s.Failures, s.NXDomain, s.AAAA))
			}
			d = append(d, dr.Differences...)
			if dr.CDNDiffers > 0 {
				d = append(d, fmt.Sprintf("%d domain(s) resolve to different public IPs per resolver — normal for CDNs", dr.CDNDiffers))
			}
		}
	case checks.HTTP:
		if h := r.HTTP; h != nil {
			for i, s := range h.Samples {
				d = append(d, fmt.Sprintf("#%d %s", i+1, sampleDetail(s)))
			}
			if h.OK > 0 {
				d = append(d, fmt.Sprintf("status %d · %s · %s · connected to %s · %d redirect(s) → %s",
					h.Status, h.Proto, orDash(h.TLSVersion), orDash(h.RemoteAddr), h.Redirects, orDash(h.FinalURL)))
			}
			if h.IPv4 != nil {
				d = append(d, "IPv4 "+sampleDetail(*h.IPv4))
			}
			if h.IPv6 != nil {
				d = append(d, "IPv6 "+sampleDetail(*h.IPv6))
			}
			if h.FamilyNote != "" {
				d = append(d, h.FamilyNote)
			}
		}
	case checks.Trace:
		if t := r.Trace; t != nil {
			for _, h := range t.Hops {
				d = append(d, hopDetail(h))
			}
		}
	case checks.Speed:
		if s := r.Speed; s != nil {
			d = append(d, fmt.Sprintf("server %s · download %.1f Mbps · upload %.1f Mbps · ping %s · jitter %s",
				orDash(s.Server), s.DownloadMbps, s.UploadMbps, fmtMs(s.PingMs), fmtMs(s.JitterMs)))
		}
	case checks.Tailscale:
		if t := r.Tailscale; t != nil {
			d = append(d, tailscaleDetails(t)...)
		}
	}
	if st.Hint != "" {
		d = append(d, "hint: "+st.Hint)
	}
	for _, n := range st.Notes {
		d = append(d, "note: "+n)
	}
	if st.DurationMs > 0 {
		d = append(d, fmt.Sprintf("took %.1fs", st.DurationMs/1000))
	}
	return d
}

// Raw returns raw tool output captured by a check, if any.
func Raw(id checks.ID, r *checks.Results) string {
	var parts []string
	switch id {
	case checks.Gateway:
		if r.Gateway != nil && r.Gateway.Ping.Raw != "" {
			parts = append(parts, r.Gateway.Ping.Raw)
		}
	case checks.Internet:
		if r.Internet != nil {
			for _, p := range r.Internet.Pings {
				if p.Raw != "" {
					parts = append(parts, p.Raw)
				}
			}
		}
	case checks.Trace:
		if r.Trace != nil {
			parts = append(parts, r.Trace.Raw)
		}
	case checks.Speed:
		if r.Speed != nil {
			parts = append(parts, r.Speed.Raw)
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func pingDetail(p probe.PingResult) []string {
	s := p.Stats
	if s.Received == 0 {
		return []string{fmt.Sprintf("%s: no replies (%d sent, %s)", p.Host, s.Sent, p.Method)}
	}
	samples := make([]string, len(s.Samples))
	for i, v := range s.Samples {
		samples[i] = fmt.Sprintf("%.1f", v)
	}
	return []string{
		fmt.Sprintf("%s: min %s · avg %s · max %s · p95 %s · jitter %s · %s loss (%d/%d, %s)",
			p.Host, fmtMs(s.MinMs), fmtMs(s.AvgMs), fmtMs(s.MaxMs), fmtMs(s.P95Ms), fmtMs(s.JitterMs), fmtPct(s.LossPct), s.Received, s.Sent, p.Method),
		"  samples (ms): " + strings.Join(samples, " "),
	}
}

func tcpDetail(t probe.TCPResult) string {
	switch {
	case t.Connected > 0:
		return fmt.Sprintf("TCP %s: %d/%d connected, avg %s", t.Addr, t.Connected, t.Attempts, fmtMs(t.Stats.AvgMs))
	case t.Refused > 0:
		return fmt.Sprintf("TCP %s: refused (host is up), %s", t.Addr, fmtMs(t.Stats.AvgMs))
	}
	return fmt.Sprintf("TCP %s: no answer (%s)", t.Addr, orDash(t.Error))
}

func sampleDetail(s probe.HTTPSample) string {
	if s.Error != "" {
		return fmt.Sprintf("failed after %s: %s", fmtMs(s.TotalMs), s.Error)
	}
	return fmt.Sprintf("DNS %s · TCP %s · TLS %s · TTFB %s · transfer %s · total %s · HTTP %d via %s",
		fmtMs(s.DNSMs), fmtMs(s.ConnectMs), fmtMs(s.TLSMs), fmtMs(s.TTFBMs), fmtMs(s.TransferMs), fmtMs(s.TotalMs), s.Status, orDash(s.RemoteAddr))
}

func hopDetail(h probe.TraceHop) string {
	host := "*"
	if len(h.Hosts) > 0 {
		host = strings.Join(h.Hosts, ", ")
		if h.Name != "" {
			host = h.Name + " (" + host + ")"
		}
	}
	if !h.Responded() {
		return fmt.Sprintf("%2d  *", h.TTL)
	}
	return fmt.Sprintf("%2d  %s  avg %s  best %s  worst %s  loss %s", h.TTL, host, fmtMs(h.AvgMs), fmtMs(h.BestMs), fmtMs(h.WorstMs), fmtPct(h.LossPct))
}

// Statistics builds the compact per-layer table.
func Statistics(r *checks.Results, fs []interpret.Finding) []StatRow {
	var rows []StatRow
	status := func(id checks.ID) interpret.Status { return interpret.CheckStatus(id, r, fs) }
	pingRow := func(layer string, p probe.PingResult, st interpret.Status) StatRow {
		s := p.Stats
		if s.Received == 0 {
			return StatRow{Layer: layer, Target: p.Host, Loss: fmtPct(s.LossPct), Status: st}
		}
		return StatRow{Layer: layer, Target: p.Host, Avg: fmtMs(s.AvgMs), P95: fmtMs(s.P95Ms), Jitter: fmtMs(s.JitterMs), Loss: fmtPct(s.LossPct), Status: st}
	}
	if g := r.Gateway; g != nil && r.Ran(checks.Gateway) {
		rows = append(rows, pingRow("Gateway", g.Ping, status(checks.Gateway)))
	}
	if in := r.Internet; in != nil && r.Ran(checks.Internet) {
		for _, p := range in.Pings {
			rows = append(rows, pingRow("Internet", p, status(checks.Internet)))
		}
		if in.ICMPBlocked {
			if t := in.BestTCP(); t != nil {
				rows = append(rows, StatRow{Layer: "Internet", Target: "TCP " + t.Addr, Avg: fmtMs(t.Stats.AvgMs), P95: fmtMs(t.Stats.P95Ms), Jitter: fmtMs(t.Stats.JitterMs), Status: status(checks.Internet)})
			}
		}
	}
	if d := r.DNS; d != nil && r.Ran(checks.DNS) {
		for _, s := range d.Resolvers {
			layer, st := "DNS (public)", interpret.StatusPass
			if s.System {
				layer, st = "DNS (system)", status(checks.DNS)
			} else if s.Unreachable() {
				st = interpret.StatusFail
			}
			row := StatRow{Layer: layer, Target: shortList(s.Name), Loss: fmt.Sprintf("%d fail", s.Failures), Status: st}
			if !s.Unreachable() {
				row.Avg, row.P95 = fmtMs(s.AvgMs), fmtMs(s.P95Ms)
			}
			rows = append(rows, row)
		}
	}
	if h := r.HTTP; h != nil {
		row := StatRow{Layer: "HTTP", Target: h.Host, Status: status(checks.HTTP)}
		if h.OK > 0 {
			row.Wide = fmt.Sprintf("DNS %.0f · TCP %.0f · TLS %.0f · TTFB %.0f · total %.0f ms", h.DNSMs, h.ConnectMs, h.TLSMs, h.TTFBMs, h.TotalMs)
		} else {
			row.Wide = "failed"
		}
		rows = append(rows, row)
	}
	if t := r.Trace; t != nil && r.Ran(checks.Trace) && len(t.Hops) > 0 {
		last := t.Hops[len(t.Hops)-1]
		row := StatRow{Layer: "Trace", Target: t.Target, Status: status(checks.Trace)}
		row.Wide = fmt.Sprintf("%d hops", len(t.Hops))
		if last.Responded() {
			row.Wide += fmt.Sprintf(" · %s to destination · %s loss", fmtMs(last.AvgMs), fmtPct(last.LossPct))
		}
		rows = append(rows, row)
	}
	if s := r.Speed; s != nil && r.Ran(checks.Speed) {
		rows = append(rows, StatRow{Layer: "Bandwidth", Target: s.Tool, Wide: fmt.Sprintf("↓ %.0f Mbps  ↑ %.0f Mbps", s.DownloadMbps, s.UploadMbps), Status: status(checks.Speed)})
	}
	if t := r.Tailscale; t != nil && r.Ran(checks.Tailscale) {
		rows = append(rows, StatRow{Layer: "Tailscale", Target: "tailnet", Wide: tailscaleLine(t), Status: status(checks.Tailscale)})
	}
	return rows
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// shortList turns "a, b, c" into "a +2" to keep table columns narrow.
func shortList(s string) string {
	parts := strings.Split(s, ", ")
	if len(parts) == 1 {
		return s
	}
	return fmt.Sprintf("%s +%d", parts[0], len(parts)-1)
}
