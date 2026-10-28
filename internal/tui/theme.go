package tui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/samcjohns/nethelp/internal/interpret"
)

// theme holds the palette and styles. Colours adapt to light and dark
// terminals; "dark"/"light" in the config force one variant, and NO_COLOR
// disables colour entirely.
type theme struct {
	accent, text, muted, subtle, pass, warn, fail, info, selBg lipgloss.TerminalColor

	header, headerTag, dim, bold, accentS, selected, border, borderFocus lipgloss.Style
	noColor                                                              bool
}

func c(light, dark string) lipgloss.AdaptiveColor {
	return lipgloss.AdaptiveColor{Light: light, Dark: dark}
}

func newTheme(mode string) theme {
	noColor := os.Getenv("NO_COLOR") != ""
	switch {
	case noColor:
		lipgloss.SetColorProfile(termenv.Ascii)
	case mode == "dark":
		lipgloss.SetHasDarkBackground(true)
	case mode == "light":
		lipgloss.SetHasDarkBackground(false)
	}
	t := theme{
		accent:  c("#B4561F", "#FAB283"),
		text:    c("#1A1A1A", "#EEEEEE"),
		muted:   c("#6E6E6E", "#8A8A8A"),
		subtle:  c("#C8C8C8", "#3C3C3C"),
		pass:    c("#2E8B3E", "#7FD88F"),
		warn:    c("#A86A00", "#F5C542"),
		fail:    c("#C0362C", "#E06C75"),
		info:    c("#1F7A8C", "#56B6C2"),
		selBg:   c("#ECE6DF", "#2A2622"),
		noColor: noColor,
	}
	t.dim = lipgloss.NewStyle().Foreground(t.muted)
	t.bold = lipgloss.NewStyle().Bold(true).Foreground(t.text)
	t.accentS = lipgloss.NewStyle().Foreground(t.accent)
	t.header = lipgloss.NewStyle().Foreground(t.muted)
	t.headerTag = lipgloss.NewStyle().Bold(true).Foreground(c("#FFFFFF", "#1A1A1A")).Background(t.accent).Padding(0, 1)
	t.selected = lipgloss.NewStyle().Background(t.selBg)
	t.border = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(t.subtle)
	t.borderFocus = t.border.BorderForeground(t.accent)
	return t
}

func (t theme) statusColor(s interpret.Status) lipgloss.TerminalColor {
	switch s {
	case interpret.StatusPass:
		return t.pass
	case interpret.StatusWarn:
		return t.warn
	case interpret.StatusFail:
		return t.fail
	case interpret.StatusRunning:
		return t.accent
	}
	return t.muted
}

func (t theme) severityColor(s interpret.Severity) lipgloss.TerminalColor {
	switch s {
	case interpret.Fail:
		return t.fail
	case interpret.Warn:
		return t.warn
	}
	return t.info
}

func (t theme) fg(col lipgloss.TerminalColor) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(col)
}
