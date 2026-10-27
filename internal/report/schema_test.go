package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/samcjohns/helpnet/internal/checks"
	"github.com/samcjohns/helpnet/internal/config"
	"github.com/samcjohns/helpnet/internal/fixtures"
	"github.com/samcjohns/helpnet/internal/interpret"
	"github.com/samcjohns/helpnet/internal/probe"
	"github.com/samcjohns/helpnet/internal/sysinfo"
)

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "docs", "report-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("report-schema.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("report-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func validate(t *testing.T, sch *jsonschema.Schema, rep Report) {
	t.Helper()
	data, err := JSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(v); err != nil {
		t.Errorf("report does not match docs/report-schema.json:\n%v", err)
	}
}

// TestReportsMatchSchema validates the documented schema against reports
// from very different runs.
func TestReportsMatchSchema(t *testing.T) {
	sch := compileSchema(t)
	th := config.DefaultThresholds()
	build := func(r *checks.Results, complete bool) Report {
		start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
		return Build(r, interpret.Analyze(r, th), Meta{Version: "0.1.0", Target: "https://example.com", Started: start, Finished: start.Add(time.Second), Complete: complete, Planned: checks.Plan(false, true), Thresholds: th})
	}

	t.Run("slow dns", func(t *testing.T) { validate(t, sch, fixedReport(t)) })

	t.Run("healthy with bandwidth and ipv6", func(t *testing.T) {
		r := fixtures.Healthy()
		r.Speed = &probe.SpeedResult{Tool: "librespeed-cli", Server: "x", DownloadMbps: 300, UploadMbps: 40, PingMs: 12, JitterMs: 1}
		r.States[checks.Speed] = fixtures.OK()
		r.HTTP.IPv4 = &probe.HTTPSample{URL: "https://example.com", Status: 200, TotalMs: 100}
		r.HTTP.IPv6 = &probe.HTTPSample{URL: "https://example.com", Error: "timeout", TimedOut: true, TotalMs: 6000}
		validate(t, sch, build(r, true))
	})

	t.Run("no network", func(t *testing.T) {
		r := checks.NewResults()
		r.Local = &sysinfo.Info{}
		r.States[checks.Local] = checks.State{Outcome: checks.OutcomeError, Error: sysinfo.ErrNoRoute.Error()}
		for _, id := range checks.Order[1:] {
			r.States[id] = checks.State{Outcome: checks.OutcomeSkipped, SkipReason: "no network connection"}
		}
		validate(t, sch, build(r, true))
	})

	t.Run("cancelled", func(t *testing.T) {
		r := fixtures.Healthy()
		r.DNS, r.HTTP, r.Trace = nil, nil, nil
		for _, id := range []checks.ID{checks.DNS, checks.HTTP, checks.Trace, checks.Speed} {
			r.States[id] = checks.State{Outcome: checks.OutcomeSkipped, SkipReason: "cancelled"}
		}
		validate(t, sch, build(r, false))
	})
}

// TestFileMatchesSchema validates a real report, e.g.
// helpnet --json > r.json && HELPNET_REPORT=$PWD/r.json go test ./internal/report -run FileMatches
func TestFileMatchesSchema(t *testing.T) {
	path := os.Getenv("HELPNET_REPORT")
	if path == "" {
		t.Skip("set HELPNET_REPORT to a JSON report file")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	v, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileSchema(t).Validate(v); err != nil {
		t.Errorf("%s does not match the schema:\n%v", path, err)
	}
}
