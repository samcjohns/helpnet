package interpret

import (
	"strings"
	"testing"
	"time"

	"github.com/samcjohns/helpnet/internal/config"
	"github.com/samcjohns/helpnet/internal/watch"
)

var watchT0 = time.Date(2026, 10, 28, 14, 0, 0, 0, time.UTC)

// watchSamples builds one sample per second from a strip per layer:
// '.' answered, 'x' lost, 's' slow (above the fail threshold), '-' not
// measured. All strips must be the same length.
func watchSamples(gw, inet, dns string) []watch.Sample {
	conv := func(c byte, slowMs float64) watch.Probe {
		switch c {
		case 'x':
			return watch.Probe{Ran: true}
		case 's':
			return watch.Probe{Ran: true, OK: true, Ms: slowMs}
		case '-':
			return watch.Probe{}
		}
		return watch.Probe{Ran: true, OK: true, Ms: 5}
	}
	out := make([]watch.Sample, len(gw))
	for i := range gw {
		out[i] = watch.Sample{
			At:       watchT0.Add(time.Duration(i) * time.Second),
			Gateway:  conv(gw[i], 500),
			Internet: conv(inet[i], 900),
			DNS:      conv(dns[i], 900),
		}
	}
	return out
}

// stretch repeats a pattern to n samples, then overlays s at offset.
func stretch(n int, overlays map[int]string) string {
	b := []byte(strings.Repeat(".", n))
	for at, s := range overlays {
		copy(b[at:], s)
	}
	return string(b)
}

func TestWatchLocalWiFiDrops(t *testing.T) {
	// Three bursts in 10 minutes where the gateway and everything behind it
	// drop together.
	n := 600
	bursts := map[int]string{60: "xxxx", 250: "xx", 480: "xxx"}
	a := AnalyzeWatch(watchSamples(stretch(n, bursts), stretch(n, bursts), stretch(n, nil)), true, config.DefaultThresholds())
	if a.Counted != 3 || a.Primary != CauseLocal || a.Severity != Fail {
		t.Fatalf("counted=%d primary=%s sev=%s", a.Counted, a.Primary, a.Severity)
	}
	want := "3 drops in 10 min, all at the gateway, so it's local Wi-Fi."
	if a.Conclusion != want {
		t.Errorf("conclusion = %q, want %q", a.Conclusion, want)
	}
	in := a.Incidents[0]
	if !in.Start.Equal(watchT0.Add(60*time.Second)) || len(in.Events) != 2 || in.Events[0].Lost != 4 {
		t.Errorf("first incident = %+v", in)
	}
	if st := a.Layers[watch.Gateway]; st.Lost != 9 || st.Samples != n {
		t.Errorf("gateway stats = %+v", st)
	}
}

func TestWatchISP(t *testing.T) {
	n := 120
	a := AnalyzeWatch(watchSamples(stretch(n, nil), stretch(n, map[int]string{10: "xxx", 70: "xx"}), stretch(n, map[int]string{11: "x"})), false, config.DefaultThresholds())
	if a.Primary != CauseISP || a.Counted != 2 {
		t.Fatalf("primary=%s counted=%d", a.Primary, a.Counted)
	}
	if want := "2 drops in 2 min, all past your router, so it's your ISP or the wider internet."; a.Conclusion != want {
		t.Errorf("conclusion = %q", a.Conclusion)
	}
}

func TestWatchRouterDeprioritisesPings(t *testing.T) {
	// The router drops pings to itself while traffic through it is fine.
	n := 60
	a := AnalyzeWatch(watchSamples(stretch(n, map[int]string{5: "xx", 40: "x"}), stretch(n, nil), stretch(n, nil)), true, config.DefaultThresholds())
	if a.Counted != 0 || len(a.Incidents) != 2 || a.Incidents[0].Cause != CauseRouter || a.Severity != Info {
		t.Fatalf("counted=%d incidents=%+v sev=%s", a.Counted, a.Incidents, a.Severity)
	}
	if !strings.HasPrefix(a.Conclusion, "No real drops in 1 min. The router ignored some pings to itself (2 times)") {
		t.Errorf("conclusion = %q", a.Conclusion)
	}
}

func TestWatchMixedCausesAndSpikes(t *testing.T) {
	n := 300
	gw := stretch(n, map[int]string{20: "xx", 100: "ss"})
	inet := stretch(n, map[int]string{20: "xx", 100: "ss", 200: "x"})
	dns := stretch(n, map[int]string{250: "x"})
	a := AnalyzeWatch(watchSamples(gw, inet, dns), true, config.DefaultThresholds())
	if a.Counted != 4 || a.Primary != CauseLocal || a.Severity != Fail {
		t.Fatalf("counted=%d primary=%s", a.Counted, a.Primary)
	}
	want := "3 drops and 1 latency spike in 5 min, 2 of 4 at the gateway, so it's most likely local Wi-Fi."
	if a.Conclusion != want {
		t.Errorf("conclusion = %q, want %q", a.Conclusion, want)
	}
	if a.Incidents[1].Drop || a.Incidents[1].Events[0].WorstMs != 500 {
		t.Errorf("spike incident = %+v", a.Incidents[1])
	}
}

func TestWatchMergesBurstWithOneGoodSample(t *testing.T) {
	n := 30
	inet := stretch(n, map[int]string{5: "xx.xx", 20: "x"}) // one answer inside a burst
	a := AnalyzeWatch(watchSamples(stretch(n, nil), inet, stretch(n, nil)), true, config.DefaultThresholds())
	if a.Counted != 2 || a.Incidents[0].Events[0].Lost != 4 {
		t.Fatalf("incidents = %+v", a.Incidents)
	}
}

func TestWatchNoGateway(t *testing.T) {
	n := 30
	a := AnalyzeWatch(watchSamples(strings.Repeat("-", n), stretch(n, map[int]string{3: "xx"}), stretch(n, nil)), true, config.DefaultThresholds())
	if a.Primary != CauseUpstream || !strings.Contains(a.Conclusion, "past this device") {
		t.Fatalf("primary=%s conclusion=%q", a.Primary, a.Conclusion)
	}
	if st := a.Layers[watch.Gateway]; st.Samples != 0 {
		t.Errorf("gateway stats = %+v", st)
	}
}

func TestWatchDNSOnlyAndClean(t *testing.T) {
	n := 45
	a := AnalyzeWatch(watchSamples(stretch(n, nil), stretch(n, nil), stretch(n, map[int]string{9: "ss"})), true, config.DefaultThresholds())
	if a.Primary != CauseDNS || a.Severity != Warn || a.Conclusion != "1 latency spike in 45 s, in DNS only, so it's your DNS resolver." {
		t.Fatalf("primary=%s sev=%s conclusion=%q", a.Primary, a.Severity, a.Conclusion)
	}
	clean := AnalyzeWatch(watchSamples(stretch(n, nil), stretch(n, nil), stretch(n, nil)), true, config.DefaultThresholds())
	if clean.Counted != 0 || clean.Severity != Info || !strings.HasPrefix(clean.Conclusion, "No drops or spikes in 45 s") {
		t.Fatalf("clean = %+v", clean)
	}
	if empty := AnalyzeWatch(nil, true, config.DefaultThresholds()); empty.Samples != 0 || empty.Counted != 0 {
		t.Fatalf("empty = %+v", empty)
	}
}

func TestFormatWatchDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Second:                "45 s",
		90 * time.Second:                "1 min 30 s",
		10 * time.Minute:                "10 min",
		10*time.Minute + 20*time.Second: "10 min",
		65 * time.Minute:                "1 h 5 min",
		2 * time.Hour:                   "2 h",
	} {
		if got := FormatWatchDuration(d); got != want {
			t.Errorf("%v → %q, want %q", d, got, want)
		}
	}
}
