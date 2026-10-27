package checks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/samcjohns/helpnet/internal/config"
	"github.com/samcjohns/helpnet/internal/sysinfo"
)

// fakeTools puts shell-script stand-ins for external tools first on PATH.
// With no scripts, PATH is emptied so no real tools are found either.
func fakeTools(t *testing.T, scripts map[string]string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake tools are shell scripts")
	}
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if len(scripts) == 0 {
		t.Setenv("PATH", dir)
		return
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "probe", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func runOnly(t *testing.T, ids ...ID) *Results {
	t.Helper()
	prev := NewResults()
	prev.Local = &sysinfo.Info{Interface: "lo", Gateway: "127.0.0.1"}
	prev.States[Local] = State{Outcome: OutcomeOK}
	opts := Options{Config: config.Default(), Target: "https://example.com"}
	return Run(context.Background(), opts, ids, prev, nil)
}

func TestMissingToolsAreSkippedWithHints(t *testing.T) {
	fakeTools(t, nil)
	if p := WithInstalled(Plan(false, false)); slices.Contains(p, Tailscale) {
		t.Errorf("Tailscale should not be planned without its CLI: %v", p)
	}
	r := runOnly(t, Trace, Speed)
	for _, id := range []ID{Trace, Speed} {
		st := r.States[id]
		if st.Outcome != OutcomeSkipped || st.Hint == "" || st.Error != "" {
			t.Errorf("%s: %+v, want skipped with install hint", id, st)
		}
	}
	if !strings.Contains(r.States[Speed].Hint, "librespeed") {
		t.Errorf("speed hint %q", r.States[Speed].Hint)
	}
}

func TestTrippyIsPreferred(t *testing.T) {
	fakeTools(t, map[string]string{
		"trip":       "cat <<'JSON'\n" + fixture(t, "trippy.json") + "\nJSON\n",
		"traceroute": "echo should not run; exit 1\n",
	})
	r := runOnly(t, Trace)
	if r.States[Trace].Outcome != OutcomeOK || r.Trace.Tool != "trip" || len(r.Trace.Hops) != 4 {
		t.Fatalf("trace: %+v %+v", r.States[Trace], r.Trace)
	}
}

func TestTrippyFailureFallsBackToTraceroute(t *testing.T) {
	fakeTools(t, map[string]string{
		"trip":       "echo 'Error: permission denied (try --unprivileged or run as root)' >&2; exit 1\n",
		"traceroute": "cat <<'OUT'\n" + fixture(t, "traceroute_darwin.txt") + "\nOUT\n",
	})
	r := runOnly(t, Trace)
	st := r.States[Trace]
	if st.Outcome != OutcomeOK || r.Trace.Tool != "traceroute" || len(r.Trace.Hops) != 5 {
		t.Fatalf("trace: %+v %+v", st, r.Trace)
	}
	if len(st.Notes) == 0 || !strings.Contains(st.Notes[0], "trip failed") {
		t.Errorf("fallback should be noted in details: %v", st.Notes)
	}
}

func TestSpeedTestParsesLibrespeed(t *testing.T) {
	fakeTools(t, map[string]string{
		"librespeed-cli": "cat <<'JSON'\n" + fixture(t, "librespeed.json") + "\nJSON\n",
	})
	r := runOnly(t, Speed)
	if r.States[Speed].Outcome != OutcomeOK || r.Speed == nil || r.Speed.DownloadMbps < 312 {
		t.Fatalf("speed: %+v %+v", r.States[Speed], r.Speed)
	}
	if r.Speed.Raw == "" {
		t.Error("raw output should be kept for the report")
	}
}

func TestBrokenToolOutputIsAnErrorNotACrash(t *testing.T) {
	fakeTools(t, map[string]string{"librespeed-cli": "echo 'not json'\n"})
	r := runOnly(t, Speed)
	if st := r.States[Speed]; st.Outcome != OutcomeError || st.Error == "" {
		t.Errorf("speed: %+v", st)
	}
}

func TestPlan(t *testing.T) {
	if p := Plan(false, false); len(p) != 6 || p[5] != Trace {
		t.Errorf("default plan %v", p)
	}
	if p := Plan(true, true); len(p) != 6 || p[5] != Speed {
		t.Errorf("quick+speed plan %v", p)
	}
	if NormalizeTarget("example.com") != "https://example.com" || NormalizeTarget("http://x.test") != "http://x.test" {
		t.Error("NormalizeTarget")
	}
	if (Options{Target: "https://example.com:8443/path"}).TargetHost() != "example.com" {
		t.Error("TargetHost")
	}
}

func TestTailscaleCheckReadsStatusAndNetcheck(t *testing.T) {
	fakeTools(t, map[string]string{
		"tailscale": `case "$1" in
status) cat <<'JSON'
` + fixture(t, "tailscale_status.json") + `
JSON
;;
netcheck) echo 'portmap: UPnP discovery response' >&2; cat <<'JSON'
` + fixture(t, "tailscale_netcheck.json") + `
JSON
;;
esac
`,
	})
	if p := WithInstalled(Plan(true, false)); p[len(p)-1] != Tailscale {
		t.Errorf("Tailscale should be planned when installed: %v", p)
	}
	r := runOnly(t, Tailscale)
	ts := r.Tailscale
	if r.States[Tailscale].Outcome != OutcomeOK || ts == nil || ts.Status.Active != 3 || ts.Netcheck == nil || !ts.Netcheck.UDP {
		t.Fatalf("tailscale: %+v %+v", r.States[Tailscale], ts)
	}
}

func TestTailscaleNotRunningIsSkipped(t *testing.T) {
	fakeTools(t, map[string]string{
		"tailscale": "echo 'failed to connect to local tailscaled; it doesn'\\''t appear to be running' >&2; exit 1\n",
	})
	r := runOnly(t, Tailscale)
	if st := r.States[Tailscale]; st.Outcome != OutcomeSkipped || !strings.Contains(st.SkipReason, "not running") {
		t.Errorf("tailscale: %+v", st)
	}
}

func TestTailscaleNetcheckFailureKeepsStatus(t *testing.T) {
	fakeTools(t, map[string]string{
		"tailscale": `if [ "$1" = status ]; then cat <<'JSON'
` + fixture(t, "tailscale_status_stopped.json") + `
JSON
else echo 'netcheck: no DERP map' >&2; exit 1; fi
`,
	})
	r := runOnly(t, Tailscale)
	st := r.States[Tailscale]
	if st.Outcome != OutcomeOK || r.Tailscale == nil || r.Tailscale.Netcheck != nil {
		t.Fatalf("tailscale: %+v %+v", st, r.Tailscale)
	}
	if len(st.Notes) == 0 || !strings.Contains(st.Notes[0], "no DERP map") {
		t.Errorf("netcheck failure should be noted: %v", st.Notes)
	}
}
