// Package report builds the final summary (conclusion, statistics, rating)
// and renders it as Markdown, JSON or plain text.
package report

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/helpnet/helpnet/internal/checks"
	"github.com/helpnet/helpnet/internal/config"
	"github.com/helpnet/helpnet/internal/interpret"
)

// SchemaVersion identifies the JSON report format (documented in docs/report-schema.json).
const SchemaVersion = "helpnet.report/v1"

type Conclusion struct {
	Headline   string             `json:"headline"`
	Text       string             `json:"text"`
	Severity   interpret.Severity `json:"severity"`
	Suggestion string             `json:"suggestion,omitempty"`
}

// StatRow is one line of the statistics table. Empty strings render as "—".
type StatRow struct {
	Layer  string           `json:"layer"`
	Target string           `json:"target"`
	Avg    string           `json:"avg,omitempty"`
	P95    string           `json:"p95,omitempty"`
	Jitter string           `json:"jitter,omitempty"`
	Loss   string           `json:"loss,omitempty"`
	Wide   string           `json:"summary,omitempty"` // replaces avg…loss for HTTP/bandwidth rows
	Status interpret.Status `json:"status"`
}

type CheckReport struct {
	ID      checks.ID        `json:"id"`
	Title   string           `json:"title"`
	Layer   int              `json:"layer"`
	Status  interpret.Status `json:"status"`
	Summary string           `json:"summary"`
	State   checks.State     `json:"state"`
	Details []string         `json:"details,omitempty"`
}

type Report struct {
	Schema        string              `json:"schema"`
	Version       string              `json:"helpnet_version"`
	Timestamp     time.Time           `json:"timestamp"`
	OS            string              `json:"os"`
	Arch          string              `json:"arch"`
	InterfaceType string              `json:"interface_type,omitempty"`
	Target        string              `json:"target"`
	DurationMs    float64             `json:"duration_ms"`
	Complete      bool                `json:"complete"`
	Conclusion    Conclusion          `json:"conclusion"`
	Primary       *interpret.Finding  `json:"primary_diagnosis,omitempty"`
	Rating        interpret.Rating    `json:"rating"`
	Statistics    []StatRow           `json:"statistics"`
	Findings      []interpret.Finding `json:"findings"`
	Checks        []CheckReport       `json:"checks"`
	Results       *checks.Results     `json:"results"`
	ExitCode      int                 `json:"exit_code"`
}

// Meta is run metadata supplied by the caller.
type Meta struct {
	Version    string
	Target     string
	Started    time.Time
	Finished   time.Time
	Complete   bool
	Planned    []checks.ID
	Thresholds config.Thresholds
}

// Build assembles a report from results and findings.
func Build(r *checks.Results, fs []interpret.Finding, m Meta) Report {
	rep := Report{
		Schema:     SchemaVersion,
		Version:    m.Version,
		Timestamp:  m.Started.UTC().Truncate(time.Second),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Target:     m.Target,
		DurationMs: float64(m.Finished.Sub(m.Started).Milliseconds()),
		Complete:   m.Complete,
		Findings:   fs,
		Results:    r,
	}
	if rep.Findings == nil {
		rep.Findings = []interpret.Finding{}
	}
	if r.Local != nil {
		rep.InterfaceType = r.Local.Type
	}
	rep.Rating = interpret.Score(r, m.Thresholds)
	if p, ok := interpret.Primary(fs); ok {
		rep.Primary = &p
	}
	rep.Conclusion = conclude(rep.Primary, m.Complete)

	planned := map[checks.ID]bool{}
	for _, id := range m.Planned {
		planned[id] = true
	}
	for _, id := range checks.Order {
		if _, ran := r.States[id]; !ran && !planned[id] {
			continue
		}
		rep.Checks = append(rep.Checks, CheckReport{
			ID: id, Title: id.Title(), Layer: id.Layer(),
			Status:  interpret.CheckStatus(id, r, fs),
			Summary: Line(id, r),
			State:   r.States[id],
			Details: Details(id, r),
		})
	}
	rep.Statistics = Statistics(r, fs)
	if rep.Statistics == nil {
		rep.Statistics = []StatRow{}
	}
	if rep.Rating.Layers == nil {
		rep.Rating.Layers = []interpret.LayerScore{}
	}
	rep.ExitCode = ExitCode(rep.Checks)
	return rep
}

func conclude(p *interpret.Finding, complete bool) Conclusion {
	if p == nil {
		if !complete {
			return Conclusion{Headline: "Run incomplete.", Text: "The diagnosis was interrupted before enough checks finished to reach a conclusion."}
		}
		return Conclusion{Headline: "No conclusion.", Text: "Not enough checks completed to reach a conclusion."}
	}
	c := Conclusion{Severity: p.Severity, Suggestion: p.Suggestion}
	if p.Rule == interpret.RuleHealthy {
		c.Headline = "Your connection looks healthy."
	} else {
		c.Headline = "Likely cause: " + lowerFirst(strings.TrimSuffix(p.Title, ".")) + "."
	}
	c.Text = p.Evidence
	if p.Suggestion != "" {
		c.Text += " " + p.Suggestion
	}
	return c
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	// Keep acronyms ("DNS", "IPv6", "TLS") intact.
	first := strings.Fields(s)[0]
	if len(first) > 1 && strings.ToUpper(first[:2]) == first[:2] {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// ExitCode: 0 all passed, 1 warnings, 2 failures.
func ExitCode(cs []CheckReport) int {
	code := 0
	for _, c := range cs {
		switch c.Status {
		case interpret.StatusFail:
			return 2
		case interpret.StatusWarn:
			code = 1
		}
	}
	return code
}

func fmtMs(v float64) string {
	switch {
	case v == 0:
		return "0 ms"
	case v < 10:
		return fmt.Sprintf("%.1f ms", v)
	}
	return fmt.Sprintf("%.0f ms", v)
}

func fmtPct(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%.0f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}
