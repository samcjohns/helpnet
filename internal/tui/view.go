package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/samcjohns/helpnet/internal/checks"
	"github.com/samcjohns/helpnet/internal/interpret"
	"github.com/samcjohns/helpnet/internal/report"
)

const (
	nameWidth = 18
	gutter    = 2 // left/right padding of the main pane
)

// layout sizes the viewport and input to the window.
func (m *model) layout() {
	if !m.ready {
		return
	}
	popup := 0
	if len(m.sugg) > 0 && m.input.Focused() {
		popup = len(m.sugg) + 2
	}
	// header (1) + blank (1) + input box (3) + status line (1)
	h := m.height - 6 - popup
	m.vp.Width = m.width
	m.vp.Height = max(3, h)
	m.input.Width = max(10, m.width-6-lipgloss.Width(m.hint()))
}

func (m *model) contentWidth() int { return max(20, m.width-2*gutter) }

// refresh rebuilds the scrolling pane: check blocks, findings, summary.
func (m *model) refresh() {
	if !m.ready {
		return
	}
	t := m.theme
	w := m.contentWidth()
	var lines []string
	add := func(s ...string) { lines = append(lines, s...) }
	m.blockLines = map[checks.ID][2]int{}

	for i, id := range m.visibleIDs() {
		start := len(lines)
		add(m.blockLine(id, i == m.selected, w))
		if m.expanded[id] || m.showRaw {
			for _, d := range report.Details(id, m.results) {
				add(t.dim.Render("      " + ansi.Truncate(d, w-6, "…")))
			}
			if m.showRaw {
				if raw := report.Raw(id, m.results); raw != "" {
					for _, r := range strings.Split(raw, "\n") {
						add(t.dim.Render("      │ " + ansi.Truncate(r, w-8, "…")))
					}
				}
			}
		}
		m.blockLines[id] = [2]int{start, len(lines) - 1}
	}

	add("", m.rule("Findings", w))
	visible := 0
	for _, f := range m.findings {
		if f.Rule == interpret.RuleHealthy && m.active {
			continue
		}
		visible++
		add(m.findingLines(f, w)...)
	}
	if visible == 0 {
		if m.active {
			add(t.dim.Render("  Findings appear here as soon as they can be determined…"))
		} else {
			add(t.dim.Render("  No findings."))
		}
	}

	m.summaryAt = len(lines)
	if m.report != nil && !m.active {
		add("", m.rule("Summary", w))
		add(m.summaryLines(*m.report, w)...)
	}
	add("")

	pad := strings.Repeat(" ", gutter)
	for i, l := range lines {
		lines[i] = pad + ansi.Truncate(l, w, "…")
	}
	atBottom := m.vp.AtBottom()
	m.vp.SetContent(strings.Join(lines, "\n"))
	if m.follow && m.active && atBottom {
		m.vp.GotoBottom()
	}
}

func (m *model) rule(title string, w int) string {
	t := m.theme
	label := "── " + title + " "
	return t.dim.Render(label + strings.Repeat("─", max(0, w-lipgloss.Width(label))))
}

// status reports the display status of a check, including "running".
func (m *model) status(id checks.ID) interpret.Status {
	if m.running[id] {
		return interpret.StatusRunning
	}
	return interpret.CheckStatus(id, m.results, m.findings)
}

func (m *model) blockLine(id checks.ID, selected bool, w int) string {
	t := m.theme
	st := m.status(id)
	col := t.statusColor(st)

	dot := "●"
	switch st {
	case interpret.StatusRunning:
		dot = m.spin.View()
	case interpret.StatusPending:
		dot = "○"
	case interpret.StatusSkipped:
		dot = "–"
	}

	var line string
	lineStyle := t.fg(t.text)
	switch st {
	case interpret.StatusRunning:
		line, lineStyle = m.progress[id], t.dim
		if line == "" {
			line = "running…"
		}
	case interpret.StatusPending:
		lineStyle = t.dim
		line = m.pendingText(id)
	case interpret.StatusSkipped:
		line, lineStyle = report.Line(id, m.results), t.dim
	default:
		line = report.Line(id, m.results)
	}

	cursor := "  "
	if selected {
		cursor = t.accentS.Render("▌ ")
	}
	icon := ""
	if st != interpret.StatusRunning && st != interpret.StatusPending {
		icon = report.Icon(st)
	}
	name := lipgloss.NewStyle().Width(nameWidth).Render(id.Title())
	if selected {
		name = t.bold.Width(nameWidth).Render(id.Title())
	}
	left := cursor + t.fg(col).Render(dot) + " " + name + " "
	avail := w - lipgloss.Width(left) - 3
	body := lineStyle.Render(ansi.Truncate(line, max(0, avail), "…"))
	gap := max(1, w-lipgloss.Width(left)-lipgloss.Width(body)-lipgloss.Width(icon))
	return left + body + strings.Repeat(" ", gap) + t.fg(col).Render(icon)
}

func (m *model) pendingText(id checks.ID) string {
	inPlan := false
	for _, p := range m.runPlan {
		if p == id {
			inPlan = true
		}
	}
	switch {
	case inPlan && m.active:
		return "pending"
	case id == checks.Speed:
		return "optional · /speed to run"
	case id == checks.Trace:
		return "not run in quick mode · /trace to run"
	}
	return "not run"
}

func (m *model) findingLines(f interpret.Finding, w int) []string {
	t := m.theme
	col := t.severityColor(f.Severity)
	icon := report.SeverityIcon(f.Severity)
	if f.Rule == interpret.RuleHealthy {
		col, icon = t.pass, "✓"
	}
	title := t.fg(col).Render(icon) + " " + lipgloss.NewStyle().Bold(true).Foreground(col).Render(f.Title) +
		t.dim.Render(fmt.Sprintf("  %s · %s confidence", f.Layer.Title(), f.Confidence))
	out := []string{"", title}
	wrap := lipgloss.NewStyle().Width(max(10, w-4))
	for _, l := range strings.Split(wrap.Render(f.Evidence), "\n") {
		out = append(out, "    "+t.dim.Render(l))
	}
	if f.Suggestion != "" {
		for i, l := range strings.Split(lipgloss.NewStyle().Width(max(10, w-6)).Render(f.Suggestion), "\n") {
			prefix := "      "
			if i == 0 {
				prefix = "    " + t.accentS.Render("→") + " "
			}
			out = append(out, prefix+t.fg(t.text).Render(l))
		}
	}
	return out
}

func (m *model) summaryLines(r report.Report, w int) []string {
	t := m.theme
	var out []string
	col := t.severityColor(r.Conclusion.Severity)
	if r.Primary != nil && r.Primary.Rule == interpret.RuleHealthy {
		col = t.pass
	}
	head := lipgloss.NewStyle().Bold(true).Foreground(col).Render(r.Conclusion.Headline)
	out = append(out, "")
	wrapped := lipgloss.NewStyle().Width(w - 2).Render(r.Conclusion.Headline + " " + r.Conclusion.Text)
	// Re-style the headline portion of the first wrapped line.
	for i, l := range strings.Split(wrapped, "\n") {
		if i == 0 && strings.HasPrefix(l, r.Conclusion.Headline) {
			l = head + t.fg(t.text).Render(strings.TrimPrefix(l, r.Conclusion.Headline))
		} else {
			l = t.fg(t.text).Render(l)
		}
		out = append(out, "  "+l)
	}

	out = append(out, "", t.bold.Render("  Statistics"))
	table := report.StatsTable(r.Statistics, report.Colors{Enabled: !t.noColor}, "  ")
	out = append(out, strings.Split(strings.TrimRight(table, "\n"), "\n")...)

	out = append(out, "", t.bold.Render("  Performance rating"))
	gradeCol := t.pass
	switch r.Rating.Grade {
	case "Fair":
		gradeCol = t.warn
	case "Poor", "Down":
		gradeCol = t.fail
	}
	out = append(out, "  "+lipgloss.NewStyle().Bold(true).Foreground(gradeCol).Render(fmt.Sprintf("%d/100 · %s", r.Rating.Score, r.Rating.Grade)))
	for _, l := range r.Rating.Layers {
		out = append(out, fmt.Sprintf("  %s %s %s %s",
			lipgloss.NewStyle().Width(12).Render(l.Layer.Title()),
			m.bar(l.Score, 20),
			lipgloss.NewStyle().Width(4).Align(lipgloss.Right).Render(fmt.Sprint(l.Score)),
			t.dim.Render(fmt.Sprintf("weight %.0f · %s", l.Weight, l.Basis))))
	}
	out = append(out, "", t.dim.Render("  c copy summary · /export save report · r run again"))
	return out
}

func (m *model) bar(score, width int) string {
	t := m.theme
	filled := score * width / 100
	col := t.pass
	switch {
	case score < 50:
		col = t.fail
	case score < 75:
		col = t.warn
	}
	return t.fg(col).Render(strings.Repeat("█", filled)) + t.fg(t.subtle).Render(strings.Repeat("░", width-filled))
}

func (m *model) hint() string { return "/help · ctrl+c quit" }

func (m *model) View() string {
	if !m.ready {
		return "\n  starting helpnet…"
	}
	t := m.theme
	header := m.headerView()
	var main string
	if m.showHelp {
		main = lipgloss.Place(m.width, m.vp.Height, lipgloss.Center, lipgloss.Center, m.helpView())
	} else {
		main = m.vp.View()
	}
	parts := []string{header, "", main}
	if len(m.sugg) > 0 && m.input.Focused() {
		parts = append(parts, m.popupView())
	}
	box := t.border
	if m.input.Focused() {
		box = t.borderFocus
	}
	prompt := t.accentS.Render("> ")
	inner := m.width - 4
	left := prompt + m.input.View()
	hint := t.dim.Render(m.hint())
	gap := max(1, inner-lipgloss.Width(left)-lipgloss.Width(hint))
	parts = append(parts, box.Width(m.width-2).Render(left+strings.Repeat(" ", gap)+hint))
	parts = append(parts, m.statusView())
	// Clamp every line so nothing wraps and breaks the layout.
	out := strings.Split(strings.Join(parts, "\n"), "\n")
	for i, l := range out {
		out[i] = ansi.Truncate(l, m.width, "")
	}
	return strings.Join(out, "\n")
}

func (m *model) headerView() string {
	t := m.theme
	left := " " + t.headerTag.Render("helpnet") + t.dim.Render("  why is my browser slow?")
	ver := m.opts.Version
	if ver != "" && ver[0] >= '0' && ver[0] <= '9' {
		ver = "v" + ver
	}
	right := t.dim.Render(ver) + " "
	gap := max(1, m.width-lipgloss.Width(left)-lipgloss.Width(right))
	return left + strings.Repeat(" ", gap) + right
}

func (m *model) statusView() string {
	t := m.theme
	elapsed := m.runEnd.Sub(m.runStart)
	if m.active {
		elapsed = time.Since(m.runStart)
	}
	done := 0
	for _, id := range m.runPlan {
		if _, ok := m.results.States[id]; ok && !m.running[id] {
			done++
		}
	}
	host := m.base.Opts.TargetHost()
	left := fmt.Sprintf(" target: %s · elapsed %.1fs · checks %d/%d", host, elapsed.Seconds(), done, len(m.runPlan))
	if m.active {
		left = " " + t.accentS.Render(m.spin.View()) + left
	}
	right := m.tools + " "
	style := t.dim
	if m.toast != "" {
		right, style = m.toast+" ", t.accentS
	}
	if lipgloss.Width(left)+lipgloss.Width(right) > m.width {
		if m.toast == "" {
			right = "" // tool list is optional; drop it on narrow terminals
		} else {
			left = ""
		}
	}
	gap := max(1, m.width-lipgloss.Width(left)-lipgloss.Width(right))
	return t.dim.Render(left) + strings.Repeat(" ", gap) + style.Render(right)
}

func (m *model) popupView() string {
	t := m.theme
	nameW := 0
	for _, c := range m.sugg {
		nameW = max(nameW, lipgloss.Width(c.name+" "+c.args))
	}
	var rows []string
	inner := m.width - 4
	for i, c := range m.sugg {
		name := lipgloss.NewStyle().Width(nameW + 3).Render(c.name + " " + c.args)
		row := ansi.Truncate(name+c.desc, inner, "…")
		row = lipgloss.NewStyle().Width(inner).Render(row)
		if i == m.suggIdx {
			row = t.selected.Foreground(t.accent).Bold(true).Render(row)
		} else {
			row = t.dim.Render(row)
		}
		rows = append(rows, row)
	}
	return t.border.Width(m.width - 2).Render(strings.Join(rows, "\n"))
}

func (m *model) helpView() string {
	t := m.theme
	var b strings.Builder
	b.WriteString(t.bold.Render("Keys") + "\n")
	for _, k := range keyHelp {
		b.WriteString(t.accentS.Render(lipgloss.NewStyle().Width(14).Render(k[0])) + t.fg(t.text).Render(k[1]) + "\n")
	}
	b.WriteString("\n" + t.bold.Render("Commands") + "\n")
	for _, c := range commands {
		b.WriteString(t.accentS.Render(lipgloss.NewStyle().Width(18).Render(c.name+" "+c.args)) + t.fg(t.text).Render(c.desc) + "\n")
	}
	b.WriteString("\n" + t.dim.Render("Typing a URL in the command bar is the same as /target <url>.\nesc or ? to close"))
	return t.borderFocus.Padding(1, 3).Render(b.String())
}
