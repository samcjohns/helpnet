// Package session drives a diagnostic run: it executes checks, keeps the
// accumulated results, re-runs the (pure) interpreter after every finished
// check so findings stream in, and builds the final report. All frontends
// (TUI, plain text, JSON) consume the same stream of Updates.
package session

import (
	"context"
	"time"

	"github.com/helpnet/helpnet/internal/checks"
	"github.com/helpnet/helpnet/internal/config"
	"github.com/helpnet/helpnet/internal/interpret"
	"github.com/helpnet/helpnet/internal/report"
)

// Update is one step of a run. Results and Findings are snapshots owned by
// the receiver; they are nil on progress-only updates.
type Update struct {
	Event    checks.Event
	Results  *checks.Results
	Findings []interpret.Finding
	Done     bool
	Report   *report.Report // set when Done
}

// Params describes one run.
type Params struct {
	Opts    checks.Options
	Plan    []checks.ID
	Prev    *checks.Results // earlier results to build on (partial re-runs); nil for a fresh run
	Version string
}

// Thresholds returns the configured thresholds.
func (p Params) Thresholds() config.Thresholds { return p.Opts.Config.Thresholds }

// Start launches the run and returns its update stream, which is closed after
// the final Done update. Cancelling ctx stops all probes; a Done update with
// the partial report is still delivered if the receiver is listening.
func Start(ctx context.Context, p Params) <-chan Update {
	ch := make(chan Update, 64)
	go func() {
		defer close(ch)
		started := time.Now()
		th := p.Thresholds()

		// The runner owns its Results; we keep a private copy fed by the same
		// events so snapshots never race with the runner.
		mine := checks.NewResults()
		if p.Prev != nil {
			mine = p.Prev.Clone()
		}
		final := checks.Run(ctx, p.Opts, p.Plan, p.Prev, func(ev checks.Event) {
			u := Update{Event: ev}
			if ev.Type != checks.EventProgress {
				mine.Apply(ev)
				u.Results = mine.Clone()
				u.Findings = interpret.Analyze(u.Results, th)
			}
			select {
			case ch <- u:
			case <-ctx.Done():
			}
		})
		rep := BuildReport(final, p, started, ctx.Err() == nil)
		select {
		case ch <- Update{Done: true, Results: final, Findings: rep.Findings, Report: &rep}:
		case <-time.After(2 * time.Second): // receiver went away
		}
	}()
	return ch
}

// BuildReport assembles the report for results produced by p.
func BuildReport(r *checks.Results, p Params, started time.Time, complete bool) report.Report {
	fs := interpret.Analyze(r, p.Thresholds())
	return report.Build(r, fs, report.Meta{
		Version:    p.Version,
		Target:     p.Opts.Target,
		Started:    started,
		Finished:   time.Now(),
		Complete:   complete,
		Planned:    p.Plan,
		Thresholds: p.Thresholds(),
	})
}
