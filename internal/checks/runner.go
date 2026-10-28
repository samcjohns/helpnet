package checks

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/samcjohns/nethelp/internal/config"
	"github.com/samcjohns/nethelp/internal/probe"
	"github.com/samcjohns/nethelp/internal/sysinfo"
)

// Options configures a run.
type Options struct {
	Config    config.Config
	Target    string // HTTP target URL
	TraceHost string // overrides the trace destination (default: target host)
	DNSDomain string // overrides DNS test domains with a single domain
	// PingInterval between probes; defaults to 200ms so a 10-sample run
	// takes ~2s per host.
	PingInterval time.Duration
	// TLSConfig is used for HTTP timing (tests use a self-signed server).
	TLSConfig *tls.Config
	// Detect overrides sysinfo detection (tests).
	Detect func(context.Context) (sysinfo.Info, error)
	// SystemResolver, if set, is queried directly in place of the OS
	// resolver path (tests use a local DNS server).
	SystemResolver string
}

// TargetHost returns the hostname of the HTTP target.
func (o Options) TargetHost() string {
	u, err := url.Parse(o.Target)
	if err != nil || u.Hostname() == "" {
		return strings.TrimPrefix(strings.TrimPrefix(o.Target, "https://"), "http://")
	}
	return u.Hostname()
}

// NormalizeTarget turns "example.com" into "https://example.com".
func NormalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return t
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	return t
}

// Plan returns the checks for a full run.
func Plan(quick, speed bool) []ID {
	ids := []ID{Local, Gateway, Internet, DNS, HTTP}
	if !quick {
		ids = append(ids, Trace)
	}
	if speed {
		ids = append(ids, Speed)
	}
	return ids
}

// WithInstalled adds the optional checks whose tool is installed to plan.
// Today that is Tailscale: it is irrelevant to anyone who doesn't use it,
// so it is left out rather than shown as skipped.
func WithInstalled(plan []ID) []ID {
	if probe.TailscaleInstalled() && !slices.Contains(plan, Tailscale) {
		plan = append(slices.Clone(plan), Tailscale)
	}
	return plan
}

// Check is one diagnostic step. Run returns the typed result (or an error
// meaning nothing useful could be measured); progress goes through rc.
type Check interface {
	ID() ID
	Run(ctx context.Context, rc *RunContext) (any, error)
}

// RunContext gives a check its options, earlier results and a progress sink.
type RunContext struct {
	Opts    Options
	Results *Results // results from earlier layers; read-only for checks
	notes   []string
	emit    func(Event)
	id      ID
}

// Progress reports a one-line live status.
func (rc *RunContext) Progress(format string, args ...any) {
	rc.emit(Event{Type: EventProgress, ID: rc.id, Text: fmt.Sprintf(format, args...)})
}

// Note attaches a detail line (e.g. a fallback used) to the check's state.
func (rc *RunContext) Note(format string, args ...any) {
	rc.notes = append(rc.notes, fmt.Sprintf(format, args...))
}

// SkipError makes a check finish as skipped rather than errored.
type SkipError struct{ Reason, Hint string }

func (e *SkipError) Error() string { return e.Reason }

var registry = map[ID]Check{
	Local:     localCheck{},
	Gateway:   gatewayCheck{},
	Internet:  internetCheck{},
	DNS:       dnsCheck{},
	HTTP:      httpCheck{},
	Trace:     traceCheck{},
	Speed:     speedCheck{},
	Tailscale: tailscaleCheck{},
}

// Run executes plan in layer order on top of prev (which may be nil) and
// returns the combined results. emit is called synchronously for every
// event; it must not block for long.
func Run(ctx context.Context, opts Options, plan []ID, prev *Results, emit func(Event)) *Results {
	res := NewResults()
	if prev != nil {
		res = prev.Clone()
	}
	if emit == nil {
		emit = func(Event) {}
	}
	inPlan := map[ID]bool{}
	for _, id := range plan {
		inPlan[id] = true
	}
	// Every other check needs the interface/gateway facts.
	if res.Local == nil {
		inPlan[Local] = true
	}
	for _, id := range Order {
		if !inPlan[id] {
			continue
		}
		start := Event{Type: EventStarted, ID: id}
		res.Apply(start)
		emit(start)

		var ev Event
		if reason := blockedBy(ctx, id, res); reason != "" {
			ev = Event{Type: EventFinished, ID: id, State: State{Outcome: OutcomeSkipped, SkipReason: reason}}
		} else {
			ev = runOne(ctx, id, opts, res, emit)
		}
		res.Apply(ev)
		emit(ev)
	}
	return res
}

func runOne(ctx context.Context, id ID, opts Options, res *Results, emit func(Event)) Event {
	rc := &RunContext{Opts: opts, Results: res, emit: emit, id: id}
	t0 := time.Now()
	v, err := registry[id].Run(ctx, rc)
	st := State{Outcome: OutcomeOK, DurationMs: float64(time.Since(t0)) / float64(time.Millisecond), Notes: rc.notes}
	var skip *SkipError
	switch {
	case ctx.Err() != nil:
		st.Outcome, st.SkipReason, v = OutcomeSkipped, "cancelled", nil
	case errors.As(err, &skip):
		st.Outcome, st.SkipReason, st.Hint, v = OutcomeSkipped, skip.Reason, skip.Hint, nil
	case err != nil:
		st.Outcome, st.Error = OutcomeError, err.Error()
	}
	return Event{Type: EventFinished, ID: id, State: st, Result: v}
}

// blockedBy returns why id cannot run given lower-layer results, or "".
func blockedBy(ctx context.Context, id ID, r *Results) string {
	if ctx.Err() != nil {
		return "cancelled"
	}
	if id == Local {
		return ""
	}
	if r.States[Local].Outcome == OutcomeError {
		return "no network connection"
	}
	switch id {
	case Gateway, Internet:
		return ""
	}
	if r.Internet != nil && !r.Internet.Reachable {
		if r.Internet.Captive != nil && r.Internet.Captive.Detected {
			return "" // a captive portal lets DNS/HTTP partially work; keep measuring
		}
		return "internet unreachable"
	}
	return ""
}
