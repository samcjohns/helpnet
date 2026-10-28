package tui

import (
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/samcjohns/nethelp/internal/checks"
	"github.com/samcjohns/nethelp/internal/interpret"
)

// XTWINOPS title stack: save the terminal's title before nethelp changes it
// and restore it on exit. Terminals without a title stack ignore these.
const (
	pushTitle = "\x1b[22;0t"
	popTitle  = "\x1b[23;0t"
)

func saveTitle(w io.Writer)    { fmt.Fprint(w, pushTitle) }
func restoreTitle(w io.Writer) { fmt.Fprint(w, popTitle) }

// windowTitle is the terminal tab title for the current state: the check in
// progress while running, then the outcome. It deliberately does not include
// the spinner frame, so it changes only when the state does.
func (m *model) windowTitle() string {
	if m.active {
		for _, id := range checks.Order {
			if m.running[id] {
				return "nethelp · " + id.Title() + "…"
			}
		}
		return "nethelp · running…"
	}
	r := m.report
	if r == nil {
		return "nethelp"
	}
	if !r.Complete {
		return "nethelp · stopped"
	}
	if r.Primary == nil {
		return "nethelp · " + r.Rating.Grade
	}
	switch r.Primary.Severity {
	case interpret.Fail:
		return fmt.Sprintf("✗ nethelp · %s · %d/100", r.Primary.Layer.Title(), r.Rating.Score)
	case interpret.Warn:
		return fmt.Sprintf("⚠ nethelp · %s · %d/100", r.Primary.Layer.Title(), r.Rating.Score)
	}
	return fmt.Sprintf("✓ nethelp · %d/100", r.Rating.Score)
}

// titleCmd returns a command that updates the terminal title if it changed.
func (m *model) titleCmd() tea.Cmd {
	t := m.windowTitle()
	if t == m.title {
		return nil
	}
	m.title = t
	return tea.SetWindowTitle(t)
}
