package report

import (
	"strings"
	"testing"
	"time"

	"github.com/samcjohns/helpnet/internal/config"
	"github.com/samcjohns/helpnet/internal/interpret"
	"github.com/samcjohns/helpnet/internal/watch"
)

func TestWatchSummary(t *testing.T) {
	t0 := time.Date(2026, 10, 28, 14, 0, 0, 0, time.Local)
	var samples []watch.Sample
	for i := range 120 {
		ok := i < 30 || i > 33
		p := watch.Probe{Ran: true, OK: ok, Ms: 4}
		samples = append(samples, watch.Sample{At: t0.Add(time.Duration(i) * time.Second), Gateway: watch.Probe{}, Internet: p, DNS: watch.Probe{Ran: true, OK: true, Ms: 12}})
	}
	a := interpret.AnalyzeWatch(samples, false, config.DefaultThresholds())
	got := WatchSummary(a, false)
	for _, want := range []string{
		"helpnet watch · 2026-10-28 14:00 · 2 min",
		"1 drop in 2 min, past this device, so it's beyond this device",
		"Gateway   not measured",
		"Internet  4 lost · median 4.0 ms",
		"DNS       0 lost · median 12 ms",
		"14:00:30  drop · internet · 4 s, 4 lost → past this device",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q:\n%s", want, got)
		}
	}
}
