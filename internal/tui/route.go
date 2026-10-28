package tui

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/samcjohns/helpnet/internal/checks"
	"github.com/samcjohns/helpnet/internal/interpret"
	"github.com/samcjohns/helpnet/internal/report"
)

const routeBarWidth = 12

// openRoute switches the pane to the route map, remembering where the main
// pane was scrolled to.
func (m *model) openRoute() {
	if !m.showRoute && !m.showWatch {
		m.routeReturn = m.vp.YOffset
	}
	m.showRoute, m.showWatch = true, false
	m.refresh()
	m.vp.GotoTop()
}

func (m *model) closeRoute() {
	m.showRoute = false
	m.refresh()
	m.vp.SetYOffset(m.routeReturn)
}

// routeLines renders the route map: one stop per hop from this device to the
// destination, each with a guess at who runs it.
func (m *model) routeLines(w int) []string {
	t := m.theme
	r := m.results
	host := m.routeHost
	if r.Trace != nil && r.Trace.Target != "" {
		host = r.Trace.Target
	}
	lines := []string{m.rule("Route to "+host, w), ""}
	add := func(s ...string) { lines = append(lines, s...) }
	footer := func() {
		add("", t.dim.Render("  esc back · /route <host> trace another host · R re-run"))
	}

	st, done := r.States[checks.Trace]
	switch {
	case m.running[checks.Trace] || (!done && m.active && slices.Contains(m.runPlan, checks.Trace)):
		prog := m.progress[checks.Trace]
		if prog == "" {
			prog = "starting route trace…"
		}
		add("  "+t.accentS.Render(m.spin.View())+" "+t.fg(t.text).Render(prog),
			"", t.dim.Render("  The map appears when the trace finishes (up to ~30s)."))
		footer()
		return lines
	case !done:
		add(t.dim.Render("  No route trace yet. Type /route [host] to run one."))
		footer()
		return lines
	case st.Outcome != checks.OutcomeOK || r.Trace == nil || len(r.Trace.Hops) == 0:
		add("  " + t.fg(t.warn).Render(report.Line(checks.Trace, r)))
		if st.Hint != "" {
			add(t.dim.Render("  hint: " + st.Hint))
		}
		footer()
		return lines
	}

	rm := interpret.MapRoute(r.Trace, r.Local)
	maxMs := 0.0
	for _, h := range rm.Hops {
		maxMs = math.Max(maxMs, h.AvgMs)
	}

	pipe := t.fg(t.subtle).Render("│")
	dots := t.fg(t.subtle).Render("┆")

	// This device.
	dev := "  " + t.accentS.Render("◉") + "        " + t.bold.Render("This device")
	if l := r.Local; l != nil {
		var bits []string
		if l.Type != "" {
			bits = append(bits, l.Type)
		}
		if len(l.IPv4) > 0 {
			bits = append(bits, l.IPv4[0])
		}
		if len(bits) > 0 {
			dev += t.dim.Render(" · " + strings.Join(bits, " · "))
		}
	}
	add(dev, "  "+pipe)

	for i, h := range rm.Hops {
		silent := h.Role == interpret.RoleSilent
		conn := pipe
		if silent || (i+1 < len(rm.Hops) && rm.Hops[i+1].Role == interpret.RoleSilent) {
			conn = dots
		}
		add(m.routeHopLine(h, maxMs, w))
		trailing := i == len(rm.Hops)-1 && !rm.Reached
		for _, d := range m.routeHopDetails(h, rm, trailing) {
			add("  " + conn + "        " + ansi.Truncate(d, max(0, w-11), "…"))
		}
		if i < len(rm.Hops)-1 {
			add("  " + conn)
		}
	}

	add("")
	if last := rm.Hops[len(rm.Hops)-1]; rm.Reached {
		add("  " + t.fg(t.pass).Render("✓") + t.fg(t.text).Render(fmt.Sprintf(" Reached %s in %d hops · %s round trip · via %s", host, last.TTL, fmtRouteMs(last.AvgMs), rm.Tool)))
	} else {
		add("  "+t.fg(t.warn).Render("!")+t.fg(t.text).Render(fmt.Sprintf(" %s didn't answer the trace (via %s).", host, rm.Tool)),
			t.dim.Render("    Many servers and firewalls drop trace probes, so this alone doesn't mean it's unreachable."))
	}
	if rm.VPN {
		add(t.dim.Render("    Your traffic goes through a VPN, so the hops after the tunnel are the VPN provider's path, not your ISP's."))
	}
	add(t.dim.Render("    Hop roles, operators and places are guesses from addresses and reverse DNS names."))
	footer()
	return lines
}

func (m *model) routeHopLine(h interpret.RouteHop, maxMs float64, w int) string {
	t := m.theme
	col := m.roleColor(h.Role)
	dot := "●"
	switch {
	case h.Role == interpret.RoleSilent:
		dot = "○"
	case h.Role == interpret.RoleDest:
		dot = "◎"
	}
	switch {
	case h.Loss:
		col = t.fail
	case h.Jump:
		col = t.warn
	}
	ttl := fmt.Sprint(h.TTL)
	if h.LastTTL > h.TTL {
		ttl = fmt.Sprintf("%d–%d", h.TTL, h.LastTTL)
	}
	left := "  " + t.fg(col).Render(dot) + "  " + t.dim.Render(fmt.Sprintf("%-5s", ttl)) + " "

	label := t.fg(col).Bold(true).Render(h.Label)
	var extra []string
	if h.Org != "" {
		extra = append(extra, h.Org)
	}
	if h.Place != "" {
		extra = append(extra, h.Place+"?")
	}
	if h.Role == interpret.RoleSilent {
		n := h.LastTTL - h.TTL + 1
		extra = append(extra, fmt.Sprintf("%d hop%s didn't answer", n, plural(n)))
	}
	if len(extra) > 0 {
		label += t.fg(t.text).Render(" · " + strings.Join(extra, " · "))
	}

	right := ""
	if h.Responded() {
		delta := ""
		if h.DeltaMs >= 1 {
			delta = fmt.Sprintf("+%.0f", h.DeltaMs)
		}
		filled := 0
		if maxMs > 0 {
			filled = max(1, int(math.Round(h.AvgMs/maxMs*routeBarWidth)))
		}
		bar := t.fg(col).Render(strings.Repeat("▬", filled)) + t.fg(t.subtle).Render(strings.Repeat("·", routeBarWidth-filled))
		right = t.fg(t.text).Render(fmt.Sprintf("%8s", fmtRouteMs(h.AvgMs))) + t.dim.Render(fmt.Sprintf(" %5s ", delta)) + bar
	}
	avail := w - lipgloss.Width(left) - lipgloss.Width(right) - 1
	if right == "" {
		avail = w - lipgloss.Width(left)
	}
	label = ansi.Truncate(label, max(0, avail), "…")
	gap := max(1, w-lipgloss.Width(left)-lipgloss.Width(label)-lipgloss.Width(right))
	if right == "" {
		gap = 0
	}
	return left + label + strings.Repeat(" ", gap) + right
}

// routeHopDetails returns the dim address line and any warnings for a hop.
func (m *model) routeHopDetails(h interpret.RouteHop, rm interpret.RouteMap, trailing bool) []string {
	t := m.theme
	var out []string
	if len(h.Hosts) > 0 {
		addr := strings.Join(h.Hosts, ", ")
		// systemd-resolved answers "_gateway" for the router; it's not a real name.
		if h.Name != "" && !strings.HasPrefix(h.Name, "_") {
			addr = h.Name + " (" + addr + ")"
		}
		if h.LossPct > 0 {
			addr += fmt.Sprintf(" · %.0f%% loss", h.LossPct)
		}
		out = append(out, t.dim.Render(addr))
	}
	switch {
	case h.Loss:
		out = append(out, t.fg(t.fail).Render("✗ packet loss starts here and continues to the destination"))
	case h.Jump:
		out = append(out, t.fg(t.warn).Render(fmt.Sprintf("! delay jumps here (%s → %s) and stays high", fmtRouteMs(rm.Analysis.JumpFromMs), fmtRouteMs(rm.Analysis.JumpToMs))))
	case h.RateLimit:
		out = append(out, t.dim.Render("drops some trace probes, but later hops are fine (harmless)"))
	case h.Role == interpret.RoleSilent && trailing:
		out = append(out, t.dim.Render("the trace gave up here"))
	case h.Role == interpret.RoleSilent:
		out = append(out, t.dim.Render("routers that ignore trace probes; traffic still passes through"))
	}
	return out
}

func (m *model) roleColor(r interpret.HopRole) lipgloss.TerminalColor {
	t := m.theme
	switch r {
	case interpret.RoleRouter, interpret.RoleLocalRouter, interpret.RoleVPN:
		return t.accent
	case interpret.RoleISP, interpret.RoleCGNAT:
		return t.info
	case interpret.RoleDest, interpret.RoleDestNet:
		return t.pass
	case interpret.RoleSilent:
		return t.muted
	}
	return t.text
}

func fmtRouteMs(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.1f ms", v)
	}
	return fmt.Sprintf("%.0f ms", v)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
