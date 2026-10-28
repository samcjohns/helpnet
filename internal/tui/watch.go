package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/samcjohns/nethelp/internal/interpret"
	"github.com/samcjohns/nethelp/internal/report"
	"github.com/samcjohns/nethelp/internal/sysinfo"
	"github.com/samcjohns/nethelp/internal/watch"
)

const (
	defaultWatch = 10 * time.Minute
	minWatch     = 10 * time.Second
	maxWatch     = 24 * time.Hour
)

// watchMsg carries one sample of watch number id; ok is false once the watch
// has ended.
type watchMsg struct {
	id int
	s  watch.Sample
	ok bool
}

func waitForWatch(id int, ch <-chan watch.Sample) tea.Cmd {
	return func() tea.Msg {
		s, ok := <-ch
		return watchMsg{id: id, s: s, ok: ok}
	}
}

// parseWatchDuration accepts "", plain seconds ("600") or a Go duration
// ("10m", "1h30m").
func parseWatchDuration(arg string) (time.Duration, error) {
	if arg == "" {
		return defaultWatch, nil
	}
	d, err := time.ParseDuration(arg)
	if n, aerr := strconv.Atoi(arg); aerr == nil {
		d, err = time.Duration(n)*time.Second, nil
	}
	if err != nil {
		return 0, fmt.Errorf("Usage: /watch [seconds], e.g. /watch 600 or /watch 10m")
	}
	if d < minWatch || d > maxWatch {
		return 0, fmt.Errorf("Watch for between %s and %s", interpret.FormatWatchDuration(minWatch), interpret.FormatWatchDuration(maxWatch))
	}
	return d, nil
}

// startWatch begins probing the gateway, the internet and DNS every second.
func (m *model) startWatch(arg string) tea.Cmd {
	if arg == "stop" {
		if !m.watching {
			return m.flash("No watch is running")
		}
		m.watchCancel()
		return nil
	}
	if m.watching {
		m.openWatch()
		return m.flash("Already watching — esc stops it")
	}
	if m.active {
		return m.flash("A run is in progress — wait for it, or use /run to restart")
	}
	d, err := parseWatchDuration(arg)
	if err != nil {
		return m.flash(err.Error())
	}
	o := watch.Options{Duration: d, Config: m.base.Opts.Config, SystemResolver: m.base.Opts.SystemResolver}
	m.watchWiFi = false
	if l := m.results.Local; l != nil {
		o.Gateway = l.Gateway
		m.watchWiFi = l.Type == sysinfo.TypeWiFi
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.watchID++
	m.watching, m.watchCancel, m.watchCh = true, cancel, watch.Start(ctx, o)
	m.watchOpts, m.watchDur, m.watchStart = o, d, time.Now()
	m.watchSamples, m.watchNotes = nil, nil
	m.watchStopped = false
	m.watchAnalysis = interpret.AnalyzeWatch(nil, m.watchWiFi, m.base.Opts.Config.Thresholds)
	m.openWatch()
	return tea.Batch(waitForWatch(m.watchID, m.watchCh), m.spin.Tick)
}

func (m *model) handleWatch(msg watchMsg) tea.Cmd {
	if msg.id != m.watchID {
		return nil // a cancelled watch
	}
	if !msg.ok {
		m.watching = false
		if m.watchCancel != nil {
			m.watchCancel()
		}
		if m.watchStopped {
			return m.flash("Watch stopped — c copies the summary")
		}
		return m.flash("Watch finished — c copies the summary")
	}
	m.watchSamples = append(m.watchSamples, msg.s)
	m.watchNotes = append(m.watchNotes, msg.s.Notes...)
	m.watchAnalysis = interpret.AnalyzeWatch(m.watchSamples, m.watchWiFi, m.base.Opts.Config.Thresholds)
	return waitForWatch(msg.id, m.watchCh)
}

// stopWatch ends a running watch early; the samples so far are kept.
func (m *model) stopWatch() {
	if m.watching && m.watchCancel != nil {
		m.watchStopped = true
		m.watchCancel()
	}
}

func (m *model) openWatch() {
	switch {
	case m.showRoute:
		m.watchReturn = m.routeReturn
	case !m.showWatch:
		m.watchReturn = m.vp.YOffset
	}
	m.showRoute, m.showWatch = false, true
	m.refresh()
	m.vp.GotoTop()
}

func (m *model) closeWatch() {
	m.showWatch = false
	m.refresh()
	m.vp.SetYOffset(m.watchReturn)
}

func (m *model) handleWatchKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "esc", "w":
		if m.watching {
			m.stopWatch()
			return m.flash("Stopping watch…"), true
		}
		m.closeWatch()
		return nil, true
	case "up", "k":
		m.vp.ScrollUp(1)
		return nil, true
	case "down", "j":
		m.vp.ScrollDown(1)
		return nil, true
	case "c":
		return m.copyWatch(), true
	case "r", "m":
		if m.watching {
			return m.flash("Watching — press esc to stop first"), true
		}
		m.showWatch = false // leave the pane and let the normal handler run
		return nil, false
	case "R", "enter", " ", "s":
		return nil, true
	}
	return nil, false
}

func (m *model) copyWatch() tea.Cmd {
	if len(m.watchSamples) == 0 {
		return m.flash("Nothing to copy yet")
	}
	return m.copyText(report.WatchSummary(m.watchAnalysis, m.watchWiFi), "Watch summary")
}

// watchLines renders the watch pane: a strip per layer, the verdict so far
// and a timeline of incidents.
func (m *model) watchLines(w int) []string {
	t := m.theme
	a := m.watchAnalysis
	elapsed := time.Duration(len(m.watchSamples)) * time.Second
	if !m.watching && len(m.watchSamples) > 0 {
		elapsed = a.End.Sub(a.Start) + a.Tick
	}
	title := fmt.Sprintf("Watch · %s of %s", fmtClock(elapsed), fmtClock(m.watchDur))
	if !m.watching {
		title = "Watch · " + interpret.FormatWatchDuration(elapsed)
		if m.watchStopped {
			title += " (stopped early)"
		}
	}
	lines := []string{m.rule(title, w), ""}
	add := func(s ...string) { lines = append(lines, s...) }

	if m.watchID == 0 {
		add(t.dim.Render("  No watch yet. Type /watch [seconds] to probe the gateway, internet and DNS"),
			t.dim.Render("  every second and catch problems that come and go."),
			"", t.dim.Render("  esc back"))
		return lines
	}

	what := []string{}
	if g := m.watchOpts.Gateway; g != "" {
		what = append(what, "gateway "+g)
	}
	if h := m.watchOpts.Config.Hosts.Internet; len(h) > 0 {
		what = append(what, "internet "+strings.Join(h, " · "))
	}
	what = append(what, "DNS")
	intro := "  Probing every second: " + strings.Join(what, ", ")
	if m.watching {
		intro = "  " + t.accentS.Render(m.spin.View()) + " " + strings.TrimPrefix(intro, "  ")
	}
	add(t.fg(t.text).Render(intro), "")

	// One strip per layer, filling from the left as samples arrive.
	const labelW, statsW = 12, 34
	stripW := max(10, w-labelW-statsW-3)
	if w-labelW-stripW-3 < 12 {
		stripW = max(10, w-labelW-2) // too narrow for stats on the same line
	}
	total := max(len(m.watchSamples), int(m.watchDur/time.Second))
	if !m.watching {
		total = len(m.watchSamples)
	}
	for _, l := range watch.Layers {
		label := t.fg(t.text).Render(fmt.Sprintf("  %-*s", labelW-3, report.WatchLayerNames[l])) + " "
		strip := m.watchStrip(l, stripW, total)
		stats := t.dim.Render(report.WatchLayerStats(a.Layers[l]))
		row := label + strip
		if rest := w - lipgloss.Width(row) - 2; rest >= 12 {
			row += "  " + ansi.Truncate(stats, rest, "…")
			add(row)
		} else {
			add(row, strings.Repeat(" ", labelW)+stats)
		}
	}
	if len(m.watchSamples) > 0 {
		from := m.watchSamples[0].At.Local().Format("15:04:05")
		to := a.Start.Add(m.watchDur).Local().Format("15:04:05")
		if !m.watching {
			to = a.End.Local().Format("15:04:05")
		}
		gap := max(1, stripW-len(from)-len(to))
		add(strings.Repeat(" ", labelW) + t.dim.Render(from+strings.Repeat(" ", gap)+to))
	}
	add(strings.Repeat(" ", labelW) + t.fg(t.pass).Render("▁") + t.dim.Render(" ok  ") +
		t.fg(t.warn).Render("▄") + t.dim.Render(" slow  ") + t.fg(t.fail).Render("█") + t.dim.Render(" lost"))
	add("")

	// The verdict.
	switch {
	case len(m.watchSamples) == 0:
		add(t.dim.Render("  Waiting for the first sample…"))
	default:
		col, icon := t.pass, "✓"
		switch a.Severity {
		case interpret.Fail:
			col, icon = t.fail, "✗"
		case interpret.Warn:
			col, icon = t.warn, "!"
		}
		prefix := ""
		if m.watching {
			prefix = "So far: "
		}
		for i, l := range wrapText(prefix+a.Conclusion, w-4) {
			lead := "    "
			if i == 0 {
				lead = "  " + t.fg(col).Render(icon) + " "
			}
			add(lead + t.fg(col).Bold(true).Render(l))
		}
		if a.Suggestion != "" && !m.watching {
			for _, l := range wrapText(a.Suggestion, w-4) {
				add(t.dim.Render("    " + l))
			}
		}
	}
	for _, n := range m.watchNotes {
		add(t.dim.Render("    note: " + n))
	}

	if len(a.Incidents) > 0 {
		add("", t.bold.Render("  Timeline"))
		for _, in := range a.Incidents {
			col := t.warn
			switch {
			case in.Cause == interpret.CauseRouter:
				col = t.muted
			case in.Drop:
				col = t.fail
			}
			add("  " + t.dim.Render(in.Start.Local().Format("15:04:05")) + "  " +
				t.fg(col).Render(report.WatchIncidentText(in, a.Tick, m.watchWiFi)))
		}
	}

	add("")
	if m.watching {
		add(t.dim.Render("  esc stop and show the result · c copy summary"))
	} else {
		add(t.dim.Render("  esc back · c copy summary · /watch [seconds] watch again"))
	}
	return lines
}

// watchStrip draws a layer as width cells covering total samples; each cell
// shows the worst state among the samples it covers.
func (m *model) watchStrip(l watch.Layer, width, total int) string {
	t := m.theme
	thr := interpret.SlowThreshold(l, m.watchWiFi, m.base.Opts.Config.Thresholds)
	cells := make([]int, width) // 0 future, 1 unmeasured, 2 ok, 3 slow, 4 lost
	for i, s := range m.watchSamples {
		c := i * width / max(1, total)
		if c >= width {
			c = width - 1
		}
		p := s.Get(l)
		st := 1
		switch {
		case !p.Ran:
		case !p.OK:
			st = 4
		case p.Ms > thr:
			st = 3
		default:
			st = 2
		}
		cells[c] = max(cells[c], st)
	}
	var b strings.Builder
	for _, c := range cells {
		switch c {
		case 0:
			b.WriteString(t.fg(t.subtle).Render("·"))
		case 1:
			b.WriteString(" ")
		case 2:
			b.WriteString(t.fg(t.pass).Render("▁"))
		case 3:
			b.WriteString(t.fg(t.warn).Render("▄"))
		case 4:
			b.WriteString(t.fg(t.fail).Render("█"))
		}
	}
	return b.String()
}

// wrapText word-wraps plain text to width columns.
func wrapText(s string, width int) []string {
	return strings.Split(ansi.Wordwrap(s, max(10, width), ""), "\n")
}

// fmtClock renders a duration as m:ss or h:mm:ss.
func fmtClock(d time.Duration) string {
	s := int(d.Round(time.Second).Seconds())
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}
