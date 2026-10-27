package interpret

import (
	"testing"

	"github.com/helpnet/helpnet/internal/checks"
	"github.com/helpnet/helpnet/internal/probe"
)

func TestMetricScoreCurve(t *testing.T) {
	cases := []struct{ v, want float64 }{
		{0, 100}, {50, 100}, {75, 90}, {100, 80}, {200, 60}, {300, 40}, {450, 20}, {600, 0}, {5000, 0},
	}
	for _, c := range cases {
		if got := metricScore(c.v, 100, 300); got != c.want {
			t.Errorf("metricScore(%v) = %v, want %v", c.v, got, c.want)
		}
	}
	// Monotonically non-increasing.
	prev := 101.0
	for v := 0.0; v < 1000; v += 7 {
		s := metricScore(v, 100, 300)
		if s > prev {
			t.Fatalf("score increased at %v: %v > %v", v, s, prev)
		}
		prev = s
	}
	low := []struct{ v, want float64 }{{100, 100}, {50, 100}, {25, 80}, {5, 40}, {2.5, 0}, {0, 0}}
	for _, c := range low {
		if got := metricScoreLow(c.v, 25, 5); got != c.want {
			t.Errorf("metricScoreLow(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestScoreHealthyIsExcellent(t *testing.T) {
	rt := Score(healthy(), th)
	if rt.Score != 100 || rt.Grade != "Excellent" {
		t.Errorf("healthy rating = %+v", rt)
	}
	if len(rt.Layers) != 4 {
		t.Errorf("expected gateway/internet/dns/http layers, got %+v", rt.Layers)
	}
	for _, l := range rt.Layers {
		if l.Basis == "" || l.Weight == 0 {
			t.Errorf("layer %s lacks an explanation: %+v", l.Layer, l)
		}
	}
}

func TestScoreIsStable(t *testing.T) {
	r := healthy()
	r.DNS.Resolvers[0] = resolver("192.168.1.1", true, 412)
	first := Score(r, th)
	for i := 0; i < 20; i++ {
		if got := Score(r, th); got.Score != first.Score || got.Grade != first.Grade {
			t.Fatalf("score changed between runs: %+v vs %+v", got, first)
		}
	}
}

func TestScoreExplainsWorstMetric(t *testing.T) {
	r := healthy()
	r.DNS.Resolvers[0] = resolver("192.168.1.1", true, 412) // between fail and 2×fail
	rt := Score(r, th)
	var dns LayerScore
	for _, l := range rt.Layers {
		if l.Layer == checks.DNS {
			dns = l
		}
	}
	// 412 ms with warn 100 / fail 300: 40 - (112/300)*40 ≈ 25.
	if dns.Score != 25 || dns.Basis != "avg lookup 412 ms" {
		t.Errorf("dns layer = %+v", dns)
	}
	// Weighted mean: (100*20 + 100*25 + 25*20 + 100*25) / 90 = 83.3.
	if rt.Score != 83 || rt.Grade != "Good" {
		t.Errorf("overall = %d %s", rt.Score, rt.Grade)
	}
}

func TestScoreIncludesBandwidthWhenTested(t *testing.T) {
	r := healthy()
	r.Speed = &probe.SpeedResult{Tool: "librespeed-cli", DownloadMbps: 15}
	r.States[checks.Speed] = okState()
	rt := Score(r, th)
	if len(rt.Layers) != 5 || rt.Score >= 100 {
		t.Errorf("bandwidth should be scored: %+v", rt)
	}
}

func TestGrades(t *testing.T) {
	for score, want := range map[int]string{100: "Excellent", 90: "Excellent", 89: "Good", 75: "Good", 74: "Fair", 50: "Fair", 49: "Poor", 1: "Poor", 0: "Down"} {
		if got := GradeFor(score); got != want {
			t.Errorf("GradeFor(%d) = %s, want %s", score, got, want)
		}
	}
}
