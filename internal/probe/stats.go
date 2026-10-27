// Package probe contains the low-level network measurements helpnet uses:
// ICMP ping, TCP connect, DNS queries, HTTP phase timing, route tracing and
// bandwidth tests. Probes do I/O but no interpretation.
package probe

import (
	"math"
	"sort"
	"time"
)

// Ms converts a duration to fractional milliseconds.
func Ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// LatencyStats summarises a series of round-trip samples.
type LatencyStats struct {
	Sent     int       `json:"sent"`
	Received int       `json:"received"`
	LossPct  float64   `json:"loss_pct"`
	MinMs    float64   `json:"min_ms"`
	AvgMs    float64   `json:"avg_ms"`
	MaxMs    float64   `json:"max_ms"`
	P95Ms    float64   `json:"p95_ms"`
	JitterMs float64   `json:"jitter_ms"`
	Samples  []float64 `json:"samples_ms"`
}

// Summarise computes LatencyStats from the RTTs of the replies that arrived.
// Jitter is the mean absolute difference between consecutive samples.
func Summarise(sent int, rtts []float64) LatencyStats {
	s := LatencyStats{Sent: sent, Received: len(rtts), Samples: append([]float64(nil), rtts...)}
	if sent > 0 {
		s.LossPct = 100 * float64(sent-len(rtts)) / float64(sent)
		if s.LossPct < 0 {
			s.LossPct = 0
		}
	}
	if len(rtts) == 0 {
		return s
	}
	s.MinMs, s.MaxMs = math.Inf(1), math.Inf(-1)
	var sum, diff float64
	for i, v := range rtts {
		sum += v
		s.MinMs = math.Min(s.MinMs, v)
		s.MaxMs = math.Max(s.MaxMs, v)
		if i > 0 {
			diff += math.Abs(v - rtts[i-1])
		}
	}
	s.AvgMs = sum / float64(len(rtts))
	if len(rtts) > 1 {
		s.JitterMs = diff / float64(len(rtts)-1)
	}
	s.P95Ms = Percentile(rtts, 95)
	return s
}

// Percentile returns the nearest-rank percentile of values.
func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}

// Mean returns the arithmetic mean, or 0 for an empty slice.
func Mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}
