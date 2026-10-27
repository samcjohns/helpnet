package tui

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/helpnet/helpnet/internal/checks"
	"github.com/helpnet/helpnet/internal/config"
	"github.com/helpnet/helpnet/internal/fixtures"
	"github.com/helpnet/helpnet/internal/interpret"
	"github.com/helpnet/helpnet/internal/session"
)

const termW, termH = 100, 40

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func typeText(m *model, s string) {
	for _, r := range s {
		m.Update(key(string(r)))
	}
}

func baseParams() session.Params {
	cfg := config.Default()
	return session.Params{
		Version: "0.1.0",
		Plan:    checks.Plan(false, false),
		Opts:    checks.Options{Config: cfg, Target: "https://example.com"},
	}
}

// fixtureModel returns a model that has "run" the healthy fixture without
// touching the network, by feeding it the updates a real run would send.
func fixtureModel(t *testing.T, r *checks.Results) *model {
	t.Helper()
	os.Setenv("NO_COLOR", "1") // stable output
	t.Cleanup(func() { os.Unsetenv("NO_COLOR") })
	m := newModel(Options{Params: baseParams(), Version: "0.1.0"})
	m.Update(tea.WindowSizeMsg{Width: termW, Height: termH})
	m.runID, m.active, m.runPlan, m.runStart = 1, true, checks.Plan(false, false), time.Now()
	th := config.DefaultThresholds()
	snap := checks.NewResults()
	for _, id := range m.runPlan {
		m.Update(updateMsg{run: 1, ok: true, u: session.Update{Event: checks.Event{Type: checks.EventStarted, ID: id}}})
		snap = snap.Clone()
		snap.Apply(checks.Event{Type: checks.EventFinished, ID: id, State: r.States[id], Result: resultFor(r, id)})
		m.Update(updateMsg{run: 1, ok: true, u: session.Update{
			Event: checks.Event{Type: checks.EventFinished, ID: id}, Results: snap, Findings: interpret.Analyze(snap, th),
		}})
	}
	rep := session.BuildReport(snap, m.base, m.runStart, true)
	m.Update(updateMsg{run: 1, ok: true, u: session.Update{Done: true, Results: snap, Findings: rep.Findings, Report: &rep}})
	return m
}

func resultFor(r *checks.Results, id checks.ID) any {
	switch id {
	case checks.Local:
		return r.Local
	case checks.Gateway:
		return r.Gateway
	case checks.Internet:
		return r.Internet
	case checks.DNS:
		return r.DNS
	case checks.HTTP:
		return r.HTTP
	case checks.Trace:
		return r.Trace
	}
	return r.Speed
}

func assertFits(t *testing.T, view string) {
	t.Helper()
	lines := strings.Split(view, "\n")
	if len(lines) != termH {
		t.Errorf("view has %d lines, want exactly %d", len(lines), termH)
	}
	for i, l := range lines {
		if w := lipgloss.Width(l); w > termW {
			t.Errorf("line %d is %d wide (> %d): %q", i, w, termW, ansi.Strip(l))
		}
	}
}

func TestViewAfterHealthyRun(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	m.vp.GotoTop()
	view := m.View()
	assertFits(t, view)
	for _, want := range []string{"helpnet", "Local interface", "wlan0 · Wi-Fi · 192.168.1.42", "Gateway", "192.168.1.1 · 3.0 ms · 0% loss", "✓", "/help · ctrl+c quit", "target: example.com", "checks 6/6", "optional · /speed to run"} {
		if !strings.Contains(view, want) {
			t.Errorf("view missing %q\n%s", want, view)
		}
	}
	m.Update(key("s"))
	if v := m.View(); !strings.Contains(v, "Your connection looks healthy") || !strings.Contains(v, "100/100 · Excellent") {
		t.Errorf("summary not shown after s:\n%s", v)
	}
}

func TestFindingsStreamAndStatusIcons(t *testing.T) {
	r := fixtures.Healthy()
	r.DNS.Resolvers[0] = fixtures.Resolver("192.168.1.1", true, 412)
	m := fixtureModel(t, r)
	m.vp.GotoTop()
	view := m.View()
	assertFits(t, view)
	if !strings.Contains(view, "DNS lookups are slow") || !strings.Contains(view, "→ Your configured DNS resolver") {
		t.Errorf("finding not rendered:\n%s", view)
	}
	if m.status(checks.DNS) != interpret.StatusFail {
		t.Errorf("DNS block status %s", m.status(checks.DNS))
	}
}

func TestNavigationAndExpand(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	m.Update(key("j"))
	m.Update(key("j"))
	if m.selected != 2 {
		t.Fatalf("selected = %d", m.selected)
	}
	m.Update(key("k"))
	m.Update(key("enter"))
	if !m.expanded[checks.Gateway] {
		t.Fatal("enter should expand the gateway block")
	}
	if v := m.View(); !strings.Contains(v, "samples (ms)") {
		t.Errorf("expanded details missing:\n%s", v)
	}
	m.Update(key(" "))
	if m.expanded[checks.Gateway] {
		t.Error("space should collapse")
	}
}

func TestAutocomplete(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	m.Update(key("/"))
	if !m.input.Focused() || len(m.sugg) != len(commands) {
		t.Fatalf("/ should focus the bar and list all commands, got %d", len(m.sugg))
	}
	typeText(m, "t")
	if len(m.sugg) != 2 || m.sugg[0].name != "/target" || m.sugg[1].name != "/trace" {
		t.Fatalf("suggestions for /t: %+v", m.sugg)
	}
	view := m.View()
	assertFits(t, view)
	if !strings.Contains(view, "/target <url>") || !strings.Contains(view, "Run the per-hop route trace") {
		t.Errorf("popup not rendered:\n%s", view)
	}
	m.Update(key("down"))
	if m.sugg[m.suggIdx].name != "/trace" {
		t.Error("down should select /trace")
	}
	m.Update(key("up"))
	m.Update(key("tab"))
	if m.input.Value() != "/target " || len(m.sugg) != 0 {
		t.Errorf("tab should complete to %q, got %q", "/target ", m.input.Value())
	}
	m.Update(key("esc"))
	if m.input.Focused() {
		t.Error("esc should leave the command bar")
	}
}

func TestEnterOnRequiredArgCompletesInsteadOfRunning(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	m.Update(key("/"))
	typeText(m, "tar")
	m.Update(key("enter"))
	if !m.input.Focused() || m.input.Value() != "/target " {
		t.Errorf("enter on /target should wait for the URL, got %q", m.input.Value())
	}
}

func TestCommandsWithoutNetwork(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	m.Update(key("/"))
	typeText(m, "details")
	m.Update(key("enter"))
	if !m.showRaw {
		t.Error("/details should toggle raw output")
	}
	m.Update(key("/"))
	typeText(m, "bogus")
	m.Update(key("enter"))
	if !strings.Contains(m.toast, "Unknown command") {
		t.Errorf("toast = %q", m.toast)
	}
	path := t.TempDir() + "/r.json"
	m.Update(key("/"))
	typeText(m, "export "+path)
	m.Update(key("enter"))
	if _, err := os.Stat(path); err != nil {
		t.Errorf("/export did not write %s: %v (toast %q)", path, err, m.toast)
	}
	m.Update(key("/"))
	typeText(m, "target")
	m.Update(key("enter"))
	m.Update(key("enter"))
	if !strings.Contains(m.toast, "Usage") {
		t.Errorf("empty /target should show usage, toast %q", m.toast)
	}
}

func TestHelpOverlayAndQuit(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	m.Update(key("?"))
	v := m.View()
	assertFits(t, v)
	if !m.showHelp || !strings.Contains(v, "Expand or collapse") || !strings.Contains(v, "/export [path]") {
		t.Fatalf("help overlay:\n%s", v)
	}
	m.Update(key("q")) // closes help, doesn't quit
	if m.showHelp {
		t.Error("q should close help")
	}
	_, cmd := m.Update(key("q"))
	if cmd == nil {
		t.Fatal("q should quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("q did not return tea.Quit")
	}
}

func TestNarrowTerminalStillFits(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	for _, l := range strings.Split(m.View(), "\n") {
		if lipgloss.Width(l) > 60 {
			t.Errorf("line too wide for 60 columns: %q", ansi.Strip(l))
		}
	}
}

// TestLiveDemo drives the real TUI model against the network and prints
// frames. Run with HELPNET_TUI_DEMO=1 go test ./internal/tui -run LiveDemo -v
func TestLiveDemo(t *testing.T) {
	if os.Getenv("HELPNET_TUI_DEMO") == "" {
		t.Skip("set HELPNET_TUI_DEMO=1")
	}
	m := newModel(Options{Params: baseParams(), Version: "0.1.0"})
	m.base.Opts.Target = "https://www.google.com"
	m.Update(tea.WindowSizeMsg{Width: termW, Height: termH})
	msgs := make(chan tea.Msg, 256)
	var run func(tea.Cmd)
	run = func(cmd tea.Cmd) {
		if cmd == nil {
			return
		}
		go func() {
			switch mm := cmd().(type) {
			case tea.BatchMsg:
				for _, c := range mm {
					run(c)
				}
			case spinner.TickMsg:
				msgs <- mm
			case nil:
			default:
				msgs <- mm
			}
		}()
	}
	run(m.Init())
	frame := 0
	deadline := time.After(60 * time.Second)
	lastPrint := time.Now()
	for {
		select {
		case msg := <-msgs:
			_, cmd := m.Update(msg)
			run(cmd)
			if u, ok := msg.(updateMsg); ok && u.u.Done {
				m.vp.GotoTop()
				fmt.Printf("=== final (top) ===\n%s\n", ansi.Strip(m.View()))
				m.Update(key("s"))
				fmt.Printf("=== final (summary) ===\n%s\n", ansi.Strip(m.View()))
				m.shutdown()
				return
			}
			if time.Since(lastPrint) > 2*time.Second {
				frame++
				lastPrint = time.Now()
				fmt.Printf("=== frame %d ===\n%s\n", frame, ansi.Strip(m.View()))
			}
		case <-deadline:
			t.Fatal("live run did not finish")
		}
	}
}
