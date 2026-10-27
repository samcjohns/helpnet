package report

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helpnet/helpnet/internal/checks"
	"github.com/helpnet/helpnet/internal/config"
	"github.com/helpnet/helpnet/internal/fixtures"
	"github.com/helpnet/helpnet/internal/interpret"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixedReport builds a deterministic report: slow DNS on an otherwise
// healthy network (the spec's example scenario).
func fixedReport(t *testing.T) Report {
	t.Helper()
	r := fixtures.Healthy()
	r.DNS.Resolvers[0] = fixtures.Resolver("192.168.1.1", true, 412)
	r.Gateway.Ping.Raw = "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=3.0 ms"
	th := config.DefaultThresholds()
	start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	rep := Build(r, interpret.Analyze(r, th), Meta{
		Version: "0.1.0", Target: "https://example.com", Started: start, Finished: start.Add(12400 * time.Millisecond),
		Complete: true, Planned: checks.Plan(false, false), Thresholds: th,
	})
	rep.OS, rep.Arch = "linux", "amd64" // stable across CI platforms
	return rep
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/report -update to create)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden file; run go test ./internal/report -update and review the diff\n--- got ---\n%s", name, got)
	}
}

func TestMarkdownSnapshot(t *testing.T) {
	golden(t, "report.md", Markdown(fixedReport(t)))
}

func TestJSONSnapshot(t *testing.T) {
	data, err := JSON(fixedReport(t))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "report.json", string(data))
}

func TestJSONRoundTripsAndHasSchemaFields(t *testing.T) {
	data, _ := JSON(fixedReport(t))
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, k := range []string{"schema", "helpnet_version", "timestamp", "os", "interface_type", "conclusion", "primary_diagnosis", "rating", "statistics", "findings", "checks", "results", "exit_code"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing top-level field %q", k)
		}
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("report does not decode into Report: %v", err)
	}
	if back.Primary == nil || back.Primary.Rule != interpret.RuleDNSSystemSlow || back.Primary.Severity != interpret.Fail {
		t.Errorf("primary after round trip: %+v", back.Primary)
	}
}

func TestConclusionMatchesSpecExample(t *testing.T) {
	rep := fixedReport(t)
	if rep.Conclusion.Headline != "Likely cause: DNS lookups are slow." {
		t.Errorf("headline = %q", rep.Conclusion.Headline)
	}
	if !strings.Contains(rep.Conclusion.Text, "412 ms") || !strings.Contains(rep.Conclusion.Text, "1.1.1.1") {
		t.Errorf("conclusion text = %q", rep.Conclusion.Text)
	}
	if rep.ExitCode != 2 {
		t.Errorf("exit code = %d, want 2 (failure)", rep.ExitCode)
	}
}

func TestReportContainsNoPersonalData(t *testing.T) {
	data, _ := JSON(fixedReport(t))
	md := Markdown(fixedReport(t))
	host, _ := os.Hostname()
	user := os.Getenv("USER")
	for _, s := range []string{host, user} {
		if len(s) > 3 && (strings.Contains(string(data), s) || strings.Contains(md, s)) {
			t.Errorf("report contains %q", s)
		}
	}
}

func TestExportPicksFormatByExtension(t *testing.T) {
	dir := t.TempDir()
	rep := fixedReport(t)
	if err := Export(rep, filepath.Join(dir, "r.json")); err != nil {
		t.Fatal(err)
	}
	if err := Export(rep, filepath.Join(dir, "sub", "r.md")); err != nil {
		t.Fatal(err)
	}
	j, _ := os.ReadFile(filepath.Join(dir, "r.json"))
	m, _ := os.ReadFile(filepath.Join(dir, "sub", "r.md"))
	if !json.Valid(j) || !strings.HasPrefix(string(m), "# helpnet report") {
		t.Error("export wrote the wrong formats")
	}
}

func TestExitCodes(t *testing.T) {
	healthy := fixtures.Healthy()
	th := config.DefaultThresholds()
	rep := Build(healthy, interpret.Analyze(healthy, th), Meta{Thresholds: th, Complete: true})
	if rep.ExitCode != 0 {
		t.Errorf("healthy exit = %d", rep.ExitCode)
	}
	warn := fixtures.Healthy()
	warn.HTTP.TLSMs = 450
	rep = Build(warn, interpret.Analyze(warn, th), Meta{Thresholds: th, Complete: true})
	if rep.ExitCode != 1 {
		t.Errorf("warning exit = %d", rep.ExitCode)
	}
	// A skipped optional tool is not a failure.
	healthy.States[checks.Speed] = checks.State{Outcome: checks.OutcomeSkipped, SkipReason: "librespeed-cli not installed"}
	rep = Build(healthy, interpret.Analyze(healthy, th), Meta{Thresholds: th, Complete: true, Planned: []checks.ID{checks.Speed}})
	if rep.ExitCode != 0 {
		t.Errorf("skipped tool exit = %d", rep.ExitCode)
	}
}

func TestSummaryTextNoColor(t *testing.T) {
	s := SummaryText(fixedReport(t), Colors{})
	if strings.Contains(s, "\x1b[") {
		t.Error("colors disabled but ANSI codes present")
	}
	for _, want := range []string{"Conclusion", "Statistics", "Performance rating", "DNS (system)", "83/100 Good"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
}
