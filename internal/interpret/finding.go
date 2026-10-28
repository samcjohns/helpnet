// Package interpret turns raw check results into findings, a primary
// diagnosis and a performance rating. Everything here is pure: no I/O, no
// clocks, so it is deterministic and easy to test with fixtures.
package interpret

import (
	"fmt"
	"sort"

	"github.com/samcjohns/nethelp/internal/checks"
)

type Severity int

const (
	Info Severity = iota
	Warn
	Fail
)

func (s Severity) String() string {
	switch s {
	case Warn:
		return "warn"
	case Fail:
		return "fail"
	}
	return "info"
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	switch string(b) {
	case "info":
		*s = Info
	case "warn":
		*s = Warn
	case "fail":
		*s = Fail
	default:
		return fmt.Errorf("unknown severity %q", b)
	}
	return nil
}

type Confidence int

const (
	Low Confidence = iota
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "low"
}

func (c Confidence) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

func (c *Confidence) UnmarshalText(b []byte) error {
	switch string(b) {
	case "low":
		*c = Low
	case "medium":
		*c = Medium
	case "high":
		*c = High
	default:
		return fmt.Errorf("unknown confidence %q", b)
	}
	return nil
}

// Finding is one interpreted conclusion.
type Finding struct {
	Rule       string     `json:"rule"` // stable identifier of the rule that fired
	Severity   Severity   `json:"severity"`
	Layer      checks.ID  `json:"layer"`
	Title      string     `json:"title"`
	Evidence   string     `json:"evidence"`
	Suggestion string     `json:"suggestion,omitempty"`
	Confidence Confidence `json:"confidence"`
}

// sortFindings orders by layer (nearest first), then severity, then confidence.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Layer.Layer() != b.Layer.Layer() {
			return a.Layer.Layer() < b.Layer.Layer()
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Confidence > b.Confidence
	})
}

// Primary selects the single primary diagnosis: the highest-severity finding,
// at the lowest layer among those, with the highest confidence. When nothing
// is wrong it returns the "healthy" finding if present. ok is false when
// there is nothing to conclude yet.
func Primary(fs []Finding) (f Finding, ok bool) {
	best := -1
	for i, c := range fs {
		if c.Severity == Info && c.Rule != RuleHealthy {
			continue
		}
		if best < 0 {
			best = i
			continue
		}
		b := fs[best]
		switch {
		case c.Severity != b.Severity:
			if c.Severity > b.Severity {
				best = i
			}
		case c.Layer.Layer() != b.Layer.Layer():
			if c.Layer.Layer() < b.Layer.Layer() {
				best = i
			}
		case c.Confidence > b.Confidence:
			best = i
		}
	}
	if best < 0 {
		return Finding{}, false
	}
	return fs[best], true
}

// Status is the display state of a check block.
type Status string

const (
	StatusPending Status = "pending"
	StatusRunning Status = "running"
	StatusPass    Status = "pass"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
)

// CheckStatus derives a check's pass/warn/fail from its outcome and the
// worst finding attributed to its layer. It never returns StatusRunning;
// the frontends know which check is in progress.
func CheckStatus(id checks.ID, r *checks.Results, fs []Finding) Status {
	st, ok := r.States[id]
	if !ok {
		return StatusPending
	}
	switch st.Outcome {
	case checks.OutcomeSkipped:
		return StatusSkipped
	case checks.OutcomeError:
		return StatusFail
	}
	worst := Info
	for _, f := range fs {
		if f.Layer == id && f.Severity > worst {
			worst = f.Severity
		}
	}
	switch worst {
	case Fail:
		return StatusFail
	case Warn:
		return StatusWarn
	}
	return StatusPass
}
