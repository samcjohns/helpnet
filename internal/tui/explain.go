package tui

import (
	"fmt"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/samcjohns/nethelp/internal/interpret"
)

// openExplain switches the pane to /explain, remembering where the main pane
// was scrolled to.
func (m *model) openExplain() {
	switch {
	case m.showRoute:
		m.explainReturn = m.routeReturn
	case m.showWatch:
		m.explainReturn = m.watchReturn
	case !m.showExplain:
		m.explainReturn = m.vp.YOffset
	}
	m.showRoute, m.showWatch, m.showExplain = false, false, true
	m.refresh()
	m.vp.GotoTop()
}

func (m *model) closeExplain() {
	m.showExplain = false
	m.refresh()
	m.vp.SetYOffset(m.explainReturn)
}

func (m *model) handleExplainKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "esc":
		m.closeExplain()
		return nil, true
	case "up", "k":
		m.vp.ScrollUp(1)
		return nil, true
	case "down", "j":
		m.vp.ScrollDown(1)
		return nil, true
	case "c":
		return m.copyExplain(), true
	case "r":
		m.closeExplain() // leave the pane and let the normal handler run
		return nil, false
	case "R", "enter", " ", "s":
		return nil, true
	}
	return nil, false
}

func (m *model) explanations() []interpret.Explanation {
	return interpret.Explain(m.results, m.findings, runtime.GOOS)
}

// explainLines renders /explain: each clear-cut problem in plain words, with
// the measured numbers, the fix and how to apply it.
func (m *model) explainLines(w int) []string {
	t := m.theme
	lines := []string{m.rule("Explain", w)}
	add := func(s ...string) { lines = append(lines, s...) }
	es := m.explanations()
	if len(es) == 0 {
		add("")
		if m.active {
			add("  "+t.accentS.Render(m.spin.View())+" "+t.fg(t.text).Render("Checks are still running…"),
				"", t.dim.Render("  Explanations appear here as soon as a problem with a clear fix shows up."))
		} else {
			add("  " + t.fg(t.pass).Render("✓") + " " + t.fg(t.text).Render("Nothing here needs explaining."))
			topics := "/explain covers problems with a clear fix: " + strings.Join(interpret.ExplainTopics, ", ") +
				". None of them showed up in this run; see the findings for everything else."
			add("")
			add(wrapLines(topics, w, "  ", "  ", t.dim)...)
		}
	}
	for _, e := range es {
		col := t.severityColor(e.Severity)
		add("", t.fg(col).Render("●")+" "+lipgloss.NewStyle().Bold(true).Foreground(col).Render(e.Title))
		add(wrapLines(e.What, w, "    ", "    ", t.fg(t.text))...)
		add("")
		add(wrapLines("Fix: "+e.Fix, w, "    "+t.accentS.Render("→")+" ", "      ", t.bold)...)
		for i, s := range e.Steps {
			n := fmt.Sprintf("%d. ", i+1)
			add(wrapLines(s, w, "      "+t.dim.Render(n), "      "+strings.Repeat(" ", len(n)), t.fg(t.text))...)
		}
	}
	add("", t.dim.Render("  esc back · c copy · r run again"))
	return lines
}

// wrapLines word-wraps s to width w after the given prefixes; the prefixes'
// visible widths must match so continuation lines align.
func wrapLines(s string, w int, first, rest string, style lipgloss.Style) []string {
	inner := max(10, w-lipgloss.Width(first))
	var out []string
	for i, l := range strings.Split(lipgloss.NewStyle().Width(inner).Render(s), "\n") {
		prefix := rest
		if i == 0 {
			prefix = first
		}
		out = append(out, prefix+style.Render(strings.TrimRight(l, " ")))
	}
	return out
}

// explainText is /explain as plain text for the clipboard.
func explainText(es []interpret.Explanation) string {
	var b strings.Builder
	for i, e := range es {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s\n%s\nFix: %s\n", e.Title, e.What, e.Fix)
		for j, s := range e.Steps {
			fmt.Fprintf(&b, "  %d. %s\n", j+1, s)
		}
	}
	return b.String()
}

func (m *model) copyExplain() tea.Cmd {
	es := m.explanations()
	if len(es) == 0 {
		return m.flash("Nothing to copy — no explanations for this run")
	}
	return m.copyText(explainText(es), "Explanations")
}
