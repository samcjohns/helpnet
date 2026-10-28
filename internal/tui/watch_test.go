package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/samcjohns/helpnet/internal/fixtures"
	"github.com/samcjohns/helpnet/internal/watch"
)

func TestParseWatchDuration(t *testing.T) {
	for arg, want := range map[string]time.Duration{"": 10 * time.Minute, "600": 10 * time.Minute, "90": 90 * time.Second, "1h30m": 90 * time.Minute} {
		if d, err := parseWatchDuration(arg); err != nil || d != want {
			t.Errorf("%q → %v, %v; want %v", arg, d, err, want)
		}
	}
	for _, bad := range []string{"soon", "5", "-30", "48h"} {
		if _, err := parseWatchDuration(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// fakeWatch puts the model in watch mode without probing anything.
func fakeWatch(m *model, d time.Duration) {
	m.watchID++
	m.watching, m.watchDur = true, d
	m.watchCancel = func() {}
	m.watchOpts = watch.Options{Gateway: "192.168.1.1", Config: m.base.Opts.Config}
	m.watchWiFi = true
	m.openWatch()
}

func watchSample(at time.Time, gwOK, inetOK bool) watch.Sample {
	p := func(ok bool) watch.Probe { return watch.Probe{Ran: true, OK: ok, Ms: 4} }
	return watch.Sample{At: at, Gateway: p(gwOK), Internet: p(inetOK), DNS: p(true)}
}

func TestWatchPane(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	fakeWatch(m, time.Minute)
	t0 := time.Now()
	for i := range 40 {
		drop := (i >= 10 && i < 13) || i == 30
		m.Update(watchMsg{id: m.watchID, ok: true, s: watchSample(t0.Add(time.Duration(i)*time.Second), !drop, !drop)})
	}
	v := m.View()
	assertFits(t, v)
	for _, want := range []string{"Watch · 0:40 of 1:00", "Probing every second: gateway 192.168.1.1, internet 1.1.1.1 · 8.8.8.8, DNS",
		"Gateway", "Internet", "█", "▁", "·", "So far: 2 drops in 40 s, all at the gateway, so it's local Wi-Fi.",
		"Timeline", "drop · gateway + internet · 3 s, 3 lost → local Wi-Fi", "esc stop"} {
		if !strings.Contains(v, want) {
			t.Errorf("watch pane missing %q\n%s", want, v)
		}
	}

	// Other checks are blocked while watching.
	if m.exec("/run"); !strings.Contains(m.toast, "Watching") {
		t.Errorf("/run while watching: toast %q", m.toast)
	}
	if m.Update(key("r")); !m.showWatch || !strings.Contains(m.toast, "Watching") {
		t.Errorf("r while watching left the pane or ran: toast %q", m.toast)
	}

	// esc stops the watch; the channel then closes.
	cancelled := false
	m.watchCancel = func() { cancelled = true }
	m.Update(key("esc"))
	if !cancelled || !m.watchStopped {
		t.Fatal("esc should cancel the watch")
	}
	m.Update(watchMsg{id: m.watchID, ok: false})
	v = m.View()
	assertFits(t, v)
	if m.watching || !strings.Contains(v, "(stopped early)") || !strings.Contains(v, "Move closer to the router") || strings.Contains(v, "So far") {
		t.Errorf("finished pane:\n%s", v)
	}
	if !strings.Contains(m.toast, "Watch stopped") {
		t.Errorf("toast %q", m.toast)
	}

	// esc again goes back to the blocks; w reopens the watch.
	m.Update(key("esc"))
	if m.showWatch || strings.Contains(m.View(), "Timeline") {
		t.Error("esc should return to the check blocks")
	}
	m.Update(key("w"))
	if !m.showWatch {
		t.Error("w should reopen the watch")
	}
	// Samples from an older watch are ignored.
	n := len(m.watchSamples)
	m.Update(watchMsg{id: m.watchID - 1, ok: true, s: watchSample(t0, true, true)})
	if len(m.watchSamples) != n {
		t.Error("stale watch sample was recorded")
	}
}

func TestWatchCommand(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	if m.exec("/watch soon"); !strings.Contains(m.toast, "Usage: /watch [seconds]") {
		t.Errorf("toast %q", m.toast)
	}
	if m.exec("/watch stop"); !strings.Contains(m.toast, "No watch is running") {
		t.Errorf("toast %q", m.toast)
	}
	m.active = true
	if m.exec("/watch"); m.watching || !strings.Contains(m.toast, "run is in progress") {
		t.Errorf("watch during a run: watching=%v toast %q", m.watching, m.toast)
	}
	m.active = false

	// A real watch against loopback, stopped straight away.
	r := m.results.Clone()
	local := *r.Local
	local.Gateway = "127.0.0.1"
	r.Local = &local
	m.results = r
	m.base.Opts.Config.Hosts.Internet = []string{"127.0.0.1"}
	m.base.Opts.SystemResolver = "127.0.0.1:1"
	cmd := m.exec("/watch 30")
	if !m.watching || !m.showWatch || m.watchDur != 30*time.Second || m.watchOpts.Gateway != "127.0.0.1" || cmd == nil {
		t.Fatalf("watching=%v pane=%v dur=%v opts=%+v", m.watching, m.showWatch, m.watchDur, m.watchOpts)
	}
	if v := m.View(); !strings.Contains(v, "Waiting for the first sample") {
		t.Errorf("pane before first sample:\n%s", v)
	}
	ch := m.watchCh
	m.exec("/watch stop")
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watch didn't stop within 1s")
	}
}

func TestWatchPaneNarrow(t *testing.T) {
	m := fixtureModel(t, fixtures.Healthy())
	m.Update(tea.WindowSizeMsg{Width: 50, Height: termH})
	fakeWatch(m, 10*time.Minute)
	t0 := time.Now()
	for i := range 5 {
		m.Update(watchMsg{id: m.watchID, ok: true, s: watchSample(t0.Add(time.Duration(i)*time.Second), true, i != 2)})
	}
	for i, l := range strings.Split(m.View(), "\n") {
		if w := len([]rune(l)); w > 50 {
			t.Errorf("line %d is %d wide: %q", i, w, l)
		}
	}
}
