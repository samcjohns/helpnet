package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattn/go-runewidth"

	"github.com/helpnet/helpnet/internal/interpret"
)

// Icon returns the status glyph used everywhere.
func Icon(s interpret.Status) string {
	switch s {
	case interpret.StatusRunning:
		return "◐"
	case interpret.StatusPass:
		return "✓"
	case interpret.StatusWarn:
		return "⚠"
	case interpret.StatusFail:
		return "✗"
	case interpret.StatusSkipped:
		return "–"
	}
	return "○"
}

// SeverityIcon returns the glyph for a finding.
func SeverityIcon(s interpret.Severity) string {
	switch s {
	case interpret.Fail:
		return "✗"
	case interpret.Warn:
		return "⚠"
	}
	return "ℹ"
}

// JSON renders the full report.
func JSON(r Report) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Markdown renders the full report: summary, findings and per-check details
// including raw tool output.
func Markdown(r Report) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# helpnet report\n\n")
	w("- **Date:** %s\n", r.Timestamp.Format("2006-01-02 15:04:05 MST"))
	w("- **helpnet:** %s (%s/%s)\n", r.Version, r.OS, r.Arch)
	if r.InterfaceType != "" {
		w("- **Interface type:** %s\n", r.InterfaceType)
	}
	w("- **Target:** %s\n", r.Target)
	w("- **Duration:** %.1fs\n\n", r.DurationMs/1000)

	w("## Conclusion\n\n")
	w("> **%s** %s\n\n", r.Conclusion.Headline, r.Conclusion.Text)

	w("## Performance rating\n\n")
	w("**%d / 100 — %s**\n\n", r.Rating.Score, r.Rating.Grade)
	if len(r.Rating.Layers) > 0 {
		w("| Layer | Score | Weight | Based on |\n|---|---:|---:|---|\n")
		for _, l := range r.Rating.Layers {
			w("| %s | %d | %.0f | %s |\n", l.Layer.Title(), l.Score, l.Weight, l.Basis)
		}
		w("\n")
	}

	w("## Statistics\n\n")
	w("| Layer | Target | Avg | p95 | Jitter | Loss | Status |\n|---|---|---|---|---|---|---|\n")
	for _, s := range r.Statistics {
		if s.Wide != "" {
			w("| %s | %s | %s |  |  |  | %s %s |\n", s.Layer, mdEscape(s.Target), s.Wide, Icon(s.Status), s.Status)
			continue
		}
		w("| %s | %s | %s | %s | %s | %s | %s %s |\n", s.Layer, mdEscape(s.Target), orDash(s.Avg), orDash(s.P95), orDash(s.Jitter), orDash(s.Loss), Icon(s.Status), s.Status)
	}
	w("\n")

	w("## Findings\n\n")
	if len(r.Findings) == 0 {
		w("No findings.\n\n")
	}
	for _, f := range r.Findings {
		w("- %s **%s** _(%s · %s · %s confidence)_  \n  %s", SeverityIcon(f.Severity), f.Title, f.Severity, f.Layer.Title(), f.Confidence, f.Evidence)
		if f.Suggestion != "" {
			w("  \n  → %s", f.Suggestion)
		}
		w("\n")
	}
	w("\n## Checks\n\n")
	for _, c := range r.Checks {
		w("### %s %s\n\n", Icon(c.Status), c.Title)
		if c.Summary != "" {
			w("%s\n\n", c.Summary)
		}
		if c.State.Error != "" {
			w("Error: `%s`\n\n", c.State.Error)
		}
		for _, d := range c.Details {
			w("- %s\n", mdEscape(d))
		}
		if raw := Raw(c.ID, r.Results); raw != "" {
			w("\n<details><summary>Raw output</summary>\n\n```\n%s\n```\n\n</details>\n", raw)
		}
		w("\n")
	}
	return b.String()
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// Colors controls ANSI styling in Text output.
type Colors struct{ Enabled bool }

func (c Colors) wrap(code, s string) string {
	if !c.Enabled || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (c Colors) Bold(s string) string  { return c.wrap("1", s) }
func (c Colors) Dim(s string) string   { return c.wrap("2", s) }
func (c Colors) Green(s string) string { return c.wrap("32", s) }
func (c Colors) Yellow(s string) string {
	return c.wrap("33", s)
}
func (c Colors) Red(s string) string  { return c.wrap("31", s) }
func (c Colors) Cyan(s string) string { return c.wrap("36", s) }

// ForStatus colours text by check status.
func (c Colors) ForStatus(s interpret.Status, text string) string {
	switch s {
	case interpret.StatusPass:
		return c.Green(text)
	case interpret.StatusWarn:
		return c.Yellow(text)
	case interpret.StatusFail:
		return c.Red(text)
	case interpret.StatusRunning:
		return c.Cyan(text)
	}
	return c.Dim(text)
}

// ForSeverity colours text by finding severity.
func (c Colors) ForSeverity(s interpret.Severity, text string) string {
	switch s {
	case interpret.Fail:
		return c.Red(text)
	case interpret.Warn:
		return c.Yellow(text)
	}
	return c.Cyan(text)
}

// SummaryText renders the three-part final summary as plain text (used by
// --no-tui and for copying to the clipboard).
func SummaryText(r Report, c Colors) string {
	var b strings.Builder
	b.WriteString(c.Bold("Conclusion") + "\n")
	head := c.ForSeverity(r.Conclusion.Severity, c.Bold(r.Conclusion.Headline))
	if r.Primary != nil && r.Primary.Rule == interpret.RuleHealthy {
		head = c.Green(c.Bold(r.Conclusion.Headline))
	}
	b.WriteString("  " + head + " " + r.Conclusion.Text + "\n\n")
	b.WriteString(c.Bold("Statistics") + "\n")
	b.WriteString(StatsTable(r.Statistics, c, "  "))
	b.WriteString("\n" + c.Bold("Performance rating") + "\n")
	b.WriteString(fmt.Sprintf("  %s %s\n", c.Bold(fmt.Sprintf("%d/100", r.Rating.Score)), gradeColor(c, r.Rating.Grade)))
	for _, l := range r.Rating.Layers {
		b.WriteString(c.Dim(fmt.Sprintf("    %-12s %3d  (weight %2.0f · %s)", l.Layer.Title(), l.Score, l.Weight, l.Basis)) + "\n")
	}
	return b.String()
}

func gradeColor(c Colors, g string) string {
	switch g {
	case "Excellent", "Good":
		return c.Green(g)
	case "Fair":
		return c.Yellow(g)
	}
	return c.Red(g)
}

// StatsTable renders the statistics as an aligned text table.
func StatsTable(rows []StatRow, c Colors, indent string) string {
	header := []string{"Layer", "Target", "Avg", "p95", "Jitter", "Loss"}
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = runewidth.StringWidth(h)
	}
	cells := func(r StatRow) []string {
		return []string{r.Layer, r.Target, orDash(r.Avg), orDash(r.P95), orDash(r.Jitter), orDash(r.Loss)}
	}
	for _, r := range rows {
		cs := cells(r)
		limit := len(cs)
		if r.Wide != "" {
			limit = 2
		}
		for i := 0; i < limit; i++ {
			widths[i] = max(widths[i], runewidth.StringWidth(cs[i]))
		}
	}
	pad := func(s string, w int) string { return s + strings.Repeat(" ", max(0, w-runewidth.StringWidth(s))) }
	var b strings.Builder
	var hl []string
	for i, h := range header {
		hl = append(hl, pad(h, widths[i]))
	}
	b.WriteString(indent + c.Dim(strings.Join(hl, "  ")+"  Status") + "\n")
	restWidth := 0
	for _, w := range widths[2:] {
		restWidth += w + 2
	}
	for _, r := range rows {
		cs := cells(r)
		line := pad(cs[0], widths[0]) + "  " + pad(cs[1], widths[1]) + "  "
		if r.Wide != "" {
			line += pad(r.Wide, restWidth-2)
		} else {
			for i := 2; i < len(cs); i++ {
				line += pad(cs[i], widths[i]) + "  "
			}
			line = strings.TrimSuffix(line, "  ")
		}
		b.WriteString(indent + line + "  " + c.ForStatus(r.Status, Icon(r.Status)) + "\n")
	}
	return b.String()
}

// Export writes the report to path: JSON if the extension is .json,
// Markdown otherwise.
func Export(r Report, path string) error {
	var data []byte
	if strings.EqualFold(filepath.Ext(path), ".json") {
		var err error
		if data, err = JSON(r); err != nil {
			return err
		}
	} else {
		data = []byte(Markdown(r))
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}

// DefaultExportName returns a timestamped file name for /export with no path.
func DefaultExportName(r Report) string {
	return "helpnet-report-" + r.Timestamp.Local().Format("20060102-150405") + ".md"
}
