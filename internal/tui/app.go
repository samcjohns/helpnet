// Package tui is nethelp's full-screen terminal interface: a scrolling pane
// of live check blocks and streamed findings, a command bar with slash-command
// autocomplete, and a status line.
package tui

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	osc52 "github.com/aymanbagabas/go-osc52/v2"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/samcjohns/nethelp/internal/checks"
	"github.com/samcjohns/nethelp/internal/interpret"
	"github.com/samcjohns/nethelp/internal/probe"
	"github.com/samcjohns/nethelp/internal/report"
	"github.com/samcjohns/nethelp/internal/session"
	"github.com/samcjohns/nethelp/internal/watch"
)

// Options configures the TUI.
type Options struct {
	Params     session.Params
	Theme      string
	Version    string
	ExportPath string // --export: also written when the first run completes
	Verbose    bool   // --verbose: start with details and raw output shown
}

type updateMsg struct {
	run int
	u   session.Update
	ok  bool
}

type toastExpiredMsg struct{ id int }

// speedInstallMsg reports the end of a /speed -install.
type speedInstallMsg struct {
	path string
	err  error
}

type model struct {
	opts  Options
	base  session.Params // current target/config; Plan is the default full plan
	theme theme

	width, height int
	ready         bool

	// Run state.
	runID    int
	ch       <-chan session.Update
	cancel   context.CancelFunc
	active   bool
	runPlan  []checks.ID
	runStart time.Time
	runEnd   time.Time
	results  *checks.Results
	findings []interpret.Finding
	report   *report.Report
	running  map[checks.ID]bool
	progress map[checks.ID]string
	exported bool

	// /speed -install state.
	speedTool     bool // librespeed-cli is available
	installing    bool
	installCancel context.CancelFunc

	// /watch state.
	watchID       int
	watching      bool
	watchStopped  bool // ended early with esc or /watch stop
	watchCancel   context.CancelFunc
	watchCh       <-chan watch.Sample
	watchOpts     watch.Options
	watchDur      time.Duration
	watchStart    time.Time
	watchWiFi     bool
	watchSamples  []watch.Sample
	watchNotes    []string
	watchAnalysis interpret.WatchAnalysis
	showWatch     bool               // the pane shows the watch instead of the blocks
	watchReturn   int                // main pane scroll offset to restore on leaving the watch
	everPlans     map[checks.ID]bool // checks requested at least once this session

	// UI state.
	selected      int
	expanded      map[checks.ID]bool
	showRaw       bool
	showHelp      bool
	showRoute     bool   // the pane shows the route map instead of the blocks
	routeHost     string // destination of the last /route
	routeReturn   int    // main pane scroll offset to restore on leaving the map
	showExplain   bool   // the pane shows /explain instead of the blocks
	explainReturn int    // main pane scroll offset to restore on leaving /explain
	follow        bool   // auto-scroll to the summary when a run completes
	vp            viewport.Model
	input         textinput.Model
	sugg          []command
	suggIdx       int
	spin          spinner.Model
	toast         string
	toastID       int
	tools         string
	blockLines    map[checks.ID][2]int // first/last content line of each block
	summaryAt     int
	title         string // last terminal title sent
}

// Run starts the TUI, runs the workflow, and returns the latest report when
// the user quits. Quitting cancels the run and waits briefly for probes and
// subprocesses to stop.
func Run(o Options) (*report.Report, error) {
	m := newModel(o)
	saveTitle(os.Stdout)
	defer restoreTitle(os.Stdout)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	final, err := p.Run()
	if fm, ok := final.(*model); ok {
		m = fm
	}
	m.shutdown()
	return m.report, err
}

func newModel(o Options) *model {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = "type / for commands, or a URL to test"
	in.CharLimit = 512

	sp := spinner.New(spinner.WithSpinner(spinner.Spinner{Frames: []string{"◐", "◓", "◑", "◒"}, FPS: 120 * time.Millisecond}))
	m := &model{
		opts:      o,
		base:      o.Params,
		theme:     newTheme(o.Theme),
		results:   checks.NewResults(),
		running:   map[checks.ID]bool{},
		progress:  map[checks.ID]string{},
		expanded:  map[checks.ID]bool{},
		showRaw:   o.Verbose,
		everPlans: map[checks.ID]bool{},
		follow:    true,
		input:     in,
		spin:      sp,
		tools:     detectTools(),
		speedTool: probe.SpeedToolAvailable(),
	}
	m.input.PlaceholderStyle = m.theme.dim
	m.input.TextStyle = m.theme.fg(m.theme.text)
	m.vp = viewport.New(80, 20)
	m.vp.MouseWheelEnabled = true
	return m
}

func detectTools() string {
	mark := func(name string) string {
		if probe.LookPath(name) != "" {
			return name + " ✓"
		}
		return name + " ✗"
	}
	trace := "traceroute"
	if os.PathSeparator == '\\' {
		trace = "tracert"
	}
	speed := "librespeed-cli ✗"
	if probe.SpeedToolAvailable() {
		speed = "librespeed-cli ✓"
	}
	return strings.Join([]string{mark("trip"), mark(trace), speed}, " · ")
}

func (m *model) Init() tea.Cmd {
	return m.start(m.base.Plan, true, m.base.Opts)
}

// start launches a run. A fresh run clears earlier results; a partial run
// re-measures only plan on top of them.
func (m *model) start(plan []checks.ID, fresh bool, opts checks.Options) tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.runID++
	p := m.base
	p.Opts, p.Plan = opts, plan
	if fresh {
		m.results = checks.NewResults()
		m.findings, m.report = nil, nil
	} else {
		// A previous run's goroutine may still be reading the old snapshot.
		m.results = m.results.Clone()
		p.Prev = m.results.Clone()
	}
	m.running, m.progress = map[checks.ID]bool{}, map[checks.ID]string{}
	for _, id := range plan {
		m.everPlans[id] = true
		delete(m.results.States, id) // show as pending until it reruns
	}
	m.runPlan = plan
	m.active, m.follow = true, true
	m.runStart, m.runEnd = time.Now(), time.Time{}
	m.ch = session.Start(ctx, p)
	return tea.Batch(waitFor(m.runID, m.ch), m.spin.Tick)
}

func waitFor(run int, ch <-chan session.Update) tea.Cmd {
	return func() tea.Msg {
		u, ok := <-ch
		return updateMsg{run: run, u: u, ok: ok}
	}
}

// shutdown cancels any run and drains it so subprocesses are killed before
// nethelp exits. Bounded so quitting always completes within a second.
func (m *model) shutdown() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.installCancel != nil {
		m.installCancel()
	}
	if m.watchCancel != nil {
		m.watchCancel()
	}
	if m.ch == nil || !m.active {
		return
	}
	deadline := time.After(900 * time.Millisecond)
	for {
		select {
		case u, ok := <-m.ch:
			if !ok {
				return
			}
			if u.Done {
				m.report = u.Report
			}
		case <-deadline:
			return
		}
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmd := m.update(msg)
	m.layout()
	m.refresh()
	if t := m.titleCmd(); t != nil {
		cmd = tea.Batch(cmd, t)
	}
	return m, cmd
}

func (m *model) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height, m.ready = msg.Width, msg.Height, true
		return nil

	case updateMsg:
		return m.handleUpdate(msg)

	case watchMsg:
		return m.handleWatch(msg)

	case spinner.TickMsg:
		if !m.active && !m.watching {
			return nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return cmd

	case speedInstallMsg:
		return m.speedInstalled(msg)

	case toastExpiredMsg:
		if msg.id == m.toastID {
			m.toast = ""
		}
		return nil

	case tea.MouseMsg:
		var cmd tea.Cmd
		before := m.vp.YOffset
		m.vp, cmd = m.vp.Update(msg)
		if m.vp.YOffset < before {
			m.follow = false
		}
		return cmd

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m.quit()
		}
		if m.showHelp {
			switch msg.String() {
			case "esc", "?", "q", "enter":
				m.showHelp = false
			}
			return nil
		}
		if m.input.Focused() {
			return m.handleInputKey(msg)
		}
		return m.handleKey(msg)
	}
	return nil
}

func (m *model) handleUpdate(msg updateMsg) tea.Cmd {
	if msg.run != m.runID {
		return nil // stale update from a cancelled run
	}
	if !msg.ok {
		m.active = false
		return nil
	}
	u := msg.u
	switch u.Event.Type {
	case checks.EventStarted:
		m.running[u.Event.ID] = true
		m.progress[u.Event.ID] = ""
	case checks.EventProgress:
		m.progress[u.Event.ID] = u.Event.Text
	case checks.EventFinished:
		delete(m.running, u.Event.ID)
	}
	if u.Results != nil {
		m.results, m.findings = u.Results, u.Findings
	}
	if u.Done {
		m.report = u.Report
		m.active = false
		m.runEnd = time.Now()
		m.running = map[checks.ID]bool{}
		var cmd tea.Cmd
		if m.opts.ExportPath != "" && !m.exported && u.Report.Complete {
			m.exported = true
			if err := report.Export(*u.Report, m.opts.ExportPath); err != nil {
				cmd = m.flash("Export failed: " + err.Error())
			} else {
				cmd = m.flash("Report saved to " + m.opts.ExportPath)
			}
		}
		if m.follow && !m.showRoute && !m.showWatch && !m.showExplain {
			m.refresh()
			m.vp.SetYOffset(m.summaryAt)
		}
		return cmd
	}
	return waitFor(msg.run, m.ch)
}

func (m *model) quit() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	if m.installCancel != nil {
		m.installCancel()
	}
	if m.watchCancel != nil {
		m.watchCancel()
	}
	return tea.Quit
}

// visibleIDs lists the check blocks to show. Tailscale appears only when it
// is part of the plan (its CLI is installed) or has a result.
func (m *model) visibleIDs() []checks.ID {
	ids := make([]checks.ID, 0, len(checks.Order))
	for _, id := range checks.Order {
		if id == checks.Tailscale && !slices.Contains(m.base.Plan, id) {
			if _, ran := m.results.States[id]; !ran {
				continue
			}
		}
		ids = append(ids, id)
	}
	return ids
}

func (m *model) handleKey(msg tea.KeyMsg) tea.Cmd {
	ids := m.visibleIDs()
	if m.showWatch {
		if cmd, done := m.handleWatchKey(msg); done {
			return cmd
		}
	}
	if m.showExplain {
		if cmd, done := m.handleExplainKey(msg); done {
			return cmd
		}
	}
	if m.showRoute {
		switch msg.String() {
		case "esc", "m":
			m.closeRoute()
			return nil
		case "up", "k":
			m.vp.ScrollUp(1)
			return nil
		case "down", "j":
			m.vp.ScrollDown(1)
			return nil
		case "R":
			return m.route(m.routeHost)
		case "enter", " ", "s":
			return nil
		}
	}
	switch msg.String() {
	case "q":
		return m.quit()
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
		m.follow = false
		m.ensureSelectedVisible()
	case "down", "j":
		if m.selected < len(ids)-1 {
			m.selected++
		}
		m.follow = false
		m.ensureSelectedVisible()
	case "enter", " ":
		id := ids[m.selected]
		m.expanded[id] = !m.expanded[id]
		m.refresh()
		m.ensureSelectedVisible()
	case "r":
		return m.start(m.base.Plan, true, m.base.Opts)
	case "R":
		return m.rerun(ids[m.selected])
	case "/":
		m.input.SetValue("/")
		m.input.CursorEnd()
		m.updateSuggestions()
		return m.input.Focus()
	case "s":
		if m.report == nil {
			return m.flash("No summary yet — the run is still in progress")
		}
		m.refresh()
		m.vp.SetYOffset(m.summaryAt)
	case "c":
		return m.copySummary()
	case "m":
		m.openRoute()
	case "w":
		m.openWatch()
	case "?":
		m.showHelp = true
	case "pgup", "b":
		m.vp.PageUp()
		m.follow = false
	case "pgdown", "f":
		m.vp.PageDown()
	case "home", "g":
		m.vp.GotoTop()
		m.follow = false
	case "end", "G":
		m.vp.GotoBottom()
	case "esc":
		m.toast = ""
	}
	return nil
}

// route traces the route to host (default: the target host) and shows it as
// a map.
func (m *model) route(host string) tea.Cmd {
	if m.active {
		return m.flash("A run is in progress — wait for it, or press r to restart")
	}
	opts := m.base.Opts
	opts.TraceHost = host
	m.routeHost = host
	if host == "" {
		m.routeHost = opts.TargetHost()
	}
	cmd := m.start([]checks.ID{checks.Trace}, false, opts)
	m.openRoute()
	return cmd
}

// rerun re-measures one check, keeping everything else.
func (m *model) rerun(id checks.ID) tea.Cmd {
	if m.active {
		return m.flash("A run is in progress — wait for it, or press r to restart")
	}
	if id == checks.Local {
		return m.start(m.base.Plan, true, m.base.Opts) // everything depends on it
	}
	return m.start([]checks.ID{id}, false, m.base.Opts)
}

func (m *model) handleInputKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		if len(m.sugg) > 0 {
			m.sugg = nil
			return nil
		}
		m.input.Blur()
		m.input.SetValue("")
		return nil
	case "up":
		if len(m.sugg) > 0 {
			m.suggIdx = (m.suggIdx - 1 + len(m.sugg)) % len(m.sugg)
		}
		return nil
	case "down":
		if len(m.sugg) > 0 {
			m.suggIdx = (m.suggIdx + 1) % len(m.sugg)
		}
		return nil
	case "tab":
		if len(m.sugg) > 0 {
			c := m.sugg[m.suggIdx]
			v := c.name
			if c.args != "" {
				v += " "
			}
			m.input.SetValue(v)
			m.input.CursorEnd()
			m.updateSuggestions()
		}
		return nil
	case "enter":
		line := strings.TrimSpace(m.input.Value())
		if len(m.sugg) > 0 {
			c := m.sugg[m.suggIdx]
			if c.args != "" && !strings.HasPrefix(c.args, "[") {
				// Required argument: complete and let the user type it.
				m.input.SetValue(c.name + " ")
				m.input.CursorEnd()
				m.updateSuggestions()
				return nil
			}
			line = c.name
		}
		m.input.SetValue("")
		m.input.Blur()
		m.sugg = nil
		if line == "" {
			return nil
		}
		return m.exec(line)
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.updateSuggestions()
	return cmd
}

func (m *model) updateSuggestions() {
	prev := ""
	if len(m.sugg) > 0 && m.suggIdx < len(m.sugg) {
		prev = m.sugg[m.suggIdx].name
	}
	m.sugg = suggest(m.input.Value())
	m.suggIdx = 0
	for i, c := range m.sugg {
		if c.name == prev {
			m.suggIdx = i
		}
	}
}

// exec runs a slash command (or a bare URL, treated as /target).
func (m *model) exec(line string) tea.Cmd {
	name, arg := parseCommand(line)
	if !strings.HasPrefix(name, "/") {
		if looksLikeHost(line) {
			name, arg = "/target", line
		} else {
			return m.flash(fmt.Sprintf("Unknown input %q — type /help for commands", line))
		}
	}
	busy := func() tea.Cmd { return m.flash("A run is in progress — wait for it, or use /run to restart") }
	switch name {
	case "/run", "/quick", "/target", "/speed", "/trace", "/route", "/dns":
		// Checks running alongside a watch would show up in it as spikes.
		if m.watching {
			return m.flash("Watching — press esc or /watch stop to end it first")
		}
	}
	switch name {
	case "/watch":
		return m.startWatch(arg)
	case "/explain":
		m.openExplain()
	case "/run":
		return m.start(m.base.Plan, true, m.base.Opts)
	case "/quick":
		return m.start(checks.WithInstalled(checks.Plan(true, false)), true, m.base.Opts)
	case "/target":
		if arg == "" {
			return m.flash("Usage: /target <url>")
		}
		if m.active {
			return busy()
		}
		m.base.Opts.Target = checks.NormalizeTarget(arg)
		return m.start([]checks.ID{checks.HTTP, checks.Trace}, false, m.base.Opts)
	case "/speed":
		switch arg {
		case "":
		case "-install", "--install", "install":
			return m.installSpeed()
		default:
			return m.flash("Usage: /speed [-install]")
		}
		if m.active {
			return busy()
		}
		if m.installing {
			return m.flash("librespeed-cli is still being installed — try again when it's done")
		}
		return m.start([]checks.ID{checks.Speed}, false, m.base.Opts)
	case "/trace":
		if m.active {
			return busy()
		}
		opts := m.base.Opts
		opts.TraceHost = arg
		return m.start([]checks.ID{checks.Trace}, false, opts)
	case "/route":
		if m.active {
			return busy()
		}
		return m.route(arg)
	case "/dns":
		if m.active {
			return busy()
		}
		opts := m.base.Opts
		opts.DNSDomain = arg
		return m.start([]checks.ID{checks.DNS}, false, opts)
	case "/export":
		return m.export(arg)
	case "/verbose", "/details":
		m.showRaw = !m.showRaw
		if m.showRaw {
			return m.flash("Showing details and raw output for all blocks")
		}
		return m.flash("Raw output hidden")
	case "/help":
		m.showHelp = true
	case "/quit", "/exit", "/q":
		return m.quit()
	default:
		return m.flash(fmt.Sprintf("Unknown command %s — type /help for commands", name))
	}
	return nil
}

// installSpeed installs librespeed-cli in the background.
func (m *model) installSpeed() tea.Cmd {
	if m.installing {
		return m.flash("librespeed-cli is already being installed")
	}
	if probe.SpeedToolAvailable() {
		return m.flash("librespeed-cli is already installed — /speed to run")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.installing, m.installCancel = true, cancel
	install := func() tea.Msg {
		p, err := probe.InstallSpeedTool(ctx)
		return speedInstallMsg{path: p, err: err}
	}
	return tea.Batch(install, m.flash("Installing librespeed-cli…"))
}

func (m *model) speedInstalled(msg speedInstallMsg) tea.Cmd {
	m.installing = false
	if m.installCancel != nil {
		m.installCancel()
		m.installCancel = nil
	}
	if msg.err != nil {
		return m.flash("Install failed: " + msg.err.Error())
	}
	m.tools, m.speedTool = detectTools(), true
	return m.flash("librespeed-cli installed to " + msg.path + " — /speed to run")
}

// currentReport returns the last completed report, or builds one from the
// results so far.
func (m *model) currentReport() report.Report {
	if m.report != nil && !m.active {
		return *m.report
	}
	p := m.base
	p.Plan = m.runPlan
	return session.BuildReport(m.results, p, m.runStart, !m.active)
}

func (m *model) export(path string) tea.Cmd {
	rep := m.currentReport()
	if path == "" {
		path = report.DefaultExportName(rep)
	}
	if err := report.Export(rep, path); err != nil {
		return m.flash("Export failed: " + err.Error())
	}
	return m.flash("Report saved to " + path)
}

func (m *model) copySummary() tea.Cmd {
	if m.report == nil {
		return m.flash("No summary yet — the run is still in progress")
	}
	return m.copyText(report.SummaryText(*m.report, report.Colors{}), "Summary")
}

// copyText puts text on the clipboard; what names it in the toast.
func (m *model) copyText(text, what string) tea.Cmd {
	if err := clipboard.WriteAll(text); err != nil {
		// No system clipboard tool (e.g. over SSH): ask the terminal via OSC 52.
		if _, err := osc52.New(text).WriteTo(os.Stderr); err != nil {
			return m.flash("Couldn't copy: " + err.Error())
		}
		return m.flash(what + " sent to the terminal clipboard (OSC 52)")
	}
	return m.flash(what + " copied to clipboard")
}

func (m *model) flash(s string) tea.Cmd {
	m.toastID++
	m.toast = s
	id := m.toastID
	return tea.Tick(4*time.Second, func(time.Time) tea.Msg { return toastExpiredMsg{id: id} })
}

func (m *model) ensureSelectedVisible() {
	m.refresh()
	id := m.visibleIDs()[m.selected]
	span, ok := m.blockLines[id]
	if !ok {
		return
	}
	top, bottom := span[0], span[1]
	if bottom-top+1 > m.vp.Height {
		bottom = top + m.vp.Height - 1
	}
	switch {
	case top < m.vp.YOffset:
		m.vp.SetYOffset(top)
	case bottom >= m.vp.YOffset+m.vp.Height:
		m.vp.SetYOffset(bottom - m.vp.Height + 1)
	}
}
