package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-runewidth"

	"github.com/samcjohns/nethelp/internal/checks"
	"github.com/samcjohns/nethelp/internal/interpret"
	"github.com/samcjohns/nethelp/internal/report"
	"github.com/samcjohns/nethelp/internal/session"
)

// runPlain streams line-based output: one line per finished check, findings
// as soon as they are known, then the final summary. With a TTY it also
// shows a transient progress line. With verbose, each check line is followed
// by its details and raw tool output.
func runPlain(ctx context.Context, p session.Params, w io.Writer, tty, verbose bool) *report.Report {
	c := report.Colors{Enabled: tty && os.Getenv("NO_COLOR") == ""}
	fmt.Fprintf(w, "%s %s %s\n\n", c.Bold("nethelp"), c.Dim(version), c.Dim("· target "+p.Opts.Target))

	titleWidth := 0
	for _, id := range checks.Order {
		titleWidth = max(titleWidth, runewidth.StringWidth(id.Title()))
	}
	shown := map[string]bool{}
	progress := false
	clearProgress := func() {
		if progress {
			fmt.Fprint(w, "\r\x1b[K")
			progress = false
		}
	}

	var rep *report.Report
	for u := range session.Start(ctx, p) {
		if u.Done {
			rep = u.Report
			break
		}
		ev := u.Event
		switch ev.Type {
		case checks.EventStarted, checks.EventProgress:
			if !tty {
				continue
			}
			text := ev.Text
			if text == "" {
				text = "running…"
			}
			clearProgress()
			fmt.Fprintf(w, "  %s %s %s", c.Cyan("◐"), pad(ev.ID.Title(), titleWidth), c.Dim(truncate(text, 70)))
			progress = true
		case checks.EventFinished:
			clearProgress()
			st := interpret.CheckStatus(ev.ID, u.Results, u.Findings)
			line := report.Line(ev.ID, u.Results)
			fmt.Fprintf(w, "  %s %s %s\n", c.ForStatus(st, report.Icon(st)), pad(ev.ID.Title(), titleWidth), line)
			if verbose {
				printDetails(w, c, ev.ID, u.Results)
			}
			for _, f := range u.Findings {
				key := f.Rule + "|" + f.Title
				if shown[key] || f.Rule == interpret.RuleHealthy {
					continue
				}
				shown[key] = true
				printFinding(w, c, f)
			}
		}
	}
	clearProgress()
	if rep == nil {
		return nil
	}
	fmt.Fprintln(w)
	fmt.Fprint(w, report.SummaryText(*rep, c))
	return rep
}

func printFinding(w io.Writer, c report.Colors, f interpret.Finding) {
	fmt.Fprintf(w, "      %s %s\n", c.ForSeverity(f.Severity, report.SeverityIcon(f.Severity)), c.Bold(f.Title))
	fmt.Fprintf(w, "        %s\n", c.Dim(f.Evidence))
	if f.Suggestion != "" {
		fmt.Fprintf(w, "        → %s\n", f.Suggestion)
	}
}

// printDetails prints the expanded lines and raw tool output of a finished
// check, read from the results it already produced.
func printDetails(w io.Writer, c report.Colors, id checks.ID, r *checks.Results) {
	for _, d := range report.Details(id, r) {
		fmt.Fprintf(w, "      %s\n", c.Dim(d))
	}
	if raw := report.Raw(id, r); raw != "" {
		for _, l := range strings.Split(raw, "\n") {
			fmt.Fprintf(w, "      %s\n", c.Dim("│ "+l))
		}
	}
}

func pad(s string, w int) string {
	return s + strings.Repeat(" ", max(0, w-runewidth.StringWidth(s)))
}

func truncate(s string, n int) string {
	if runewidth.StringWidth(s) <= n {
		return s
	}
	return runewidth.Truncate(s, n, "…")
}
