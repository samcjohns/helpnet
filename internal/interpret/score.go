package interpret

import (
	"fmt"
	"math"

	"github.com/samcjohns/helpnet/internal/checks"
	"github.com/samcjohns/helpnet/internal/config"
)

// Rating weights. The overall score is the weighted mean of the layers that
// produced a score, so skipping the optional bandwidth test doesn't penalise
// a run. Weights reflect how directly each layer affects page loads:
//
//	Gateway   20  local network quality underpins everything else
//	Internet  25  latency/loss to the wider internet
//	DNS       20  every new site waits on a lookup
//	HTTP      25  what a page load actually experiences
//	Bandwidth 10  only when tested; matters for large pages and media
//
// The local interface, route trace and Tailscale are not scored: the first
// is a prerequisite (no network = "Down"), the second explains problems the
// other layers already measure, and Tailscale is about peer-to-peer paths,
// not page loads.
var layerWeights = map[checks.ID]float64{
	checks.Gateway:  20,
	checks.Internet: 25,
	checks.DNS:      20,
	checks.HTTP:     25,
	checks.Speed:    10,
}

// LayerScore is one row of the rating breakdown.
type LayerScore struct {
	Layer  checks.ID `json:"layer"`
	Score  int       `json:"score"`
	Weight float64   `json:"weight"`
	Basis  string    `json:"basis"` // which metric set the score
}

// Rating is the overall 0–100 score and grade.
type Rating struct {
	Score  int          `json:"score"`
	Grade  string       `json:"grade"`
	Layers []LayerScore `json:"layers"`
}

// metricScore maps a larger-is-worse metric to 0–100: anything up to half
// the warn threshold scores 100, the warn threshold scores 80, the fail
// threshold 40, and twice the fail threshold or worse scores 0. The curve
// is piecewise linear in between, so small changes move the score smoothly.
func metricScore(v, warn, fail float64) float64 {
	switch {
	case v <= warn/2:
		return 100
	case v <= warn:
		return lerp(v, warn/2, warn, 100, 80)
	case v <= fail:
		return lerp(v, warn, fail, 80, 40)
	case v <= 2*fail:
		return lerp(v, fail, 2*fail, 40, 0)
	}
	return 0
}

// metricScoreLow is metricScore for smaller-is-worse metrics (bandwidth):
// twice the warn threshold or better scores 100, warn 80, fail 40, and half
// of fail or worse 0.
func metricScoreLow(v, warn, fail float64) float64 {
	switch {
	case v >= 2*warn:
		return 100
	case v >= warn:
		return lerp(v, warn, 2*warn, 80, 100)
	case v >= fail:
		return lerp(v, fail, warn, 40, 80)
	case v >= fail/2:
		return lerp(v, fail/2, fail, 0, 40)
	}
	return 0
}

func lerp(v, x0, x1, y0, y1 float64) float64 {
	if x1 == x0 {
		return y1
	}
	return y0 + (v-x0)*(y1-y0)/(x1-x0)
}

// worst returns the lowest-scoring metric and its label.
type metric struct {
	label string
	score float64
}

func worst(metrics ...metric) (float64, string) {
	best := metric{score: math.Inf(1)}
	for _, m := range metrics {
		if m.score < best.score {
			best = m
		}
	}
	return best.score, best.label
}

// Score computes the performance rating. Each layer's score is its worst
// metric's score, so one bad number is never averaged away within a layer.
func Score(r *checks.Results, th config.Thresholds) Rating {
	var rating Rating
	down := ""
	if r.States[checks.Local].Outcome == checks.OutcomeError {
		down = "no network connection"
	}
	if in := r.Internet; in != nil && r.Ran(checks.Internet) && !in.Reachable {
		down = "internet unreachable"
	}

	add := func(id checks.ID, score float64, basis string) {
		rating.Layers = append(rating.Layers, LayerScore{Layer: id, Score: int(math.Round(score)), Weight: layerWeights[id], Basis: basis})
	}
	addWorst := func(id checks.ID, ms ...metric) {
		score, basis := worst(ms...)
		add(id, score, basis)
	}
	a := &analysis{r: r, th: th}

	if g := r.Gateway; g != nil && r.Ran(checks.Gateway) {
		switch {
		case g.Ping.Stats.Received > 0:
			s := g.Ping.Stats
			w, f := a.gatewayLatencyLimits()
			// Metrics the router merely deprioritises (see
			// gatewayDeprioritized) aren't held against the connection.
			dLoss, dLat := a.gatewayDeprioritized()
			var gm []metric
			if !dLat {
				gm = append(gm,
					metric{fmt.Sprintf("avg latency %s", ms(s.AvgMs)), metricScore(s.AvgMs, w, f)},
					metric{fmt.Sprintf("jitter %s", ms(s.JitterMs)), metricScore(s.JitterMs, th.JitterWarnMs, th.JitterFailMs)})
			}
			if !dLoss {
				gm = append(gm, metric{fmt.Sprintf("loss %s", pct(s.LossPct)), metricScore(s.LossPct, th.GatewayLossWarnPct, th.GatewayLossFailPct)})
			}
			if len(gm) == 0 {
				gm = append(gm, metric{"reachable; ping replies deprioritised", 100})
			}
			addWorst(checks.Gateway, gm...)
		case !g.Reachable && down != "":
			add(checks.Gateway, 0, "unreachable")
		}
		// A router that ignores ping but is otherwise up isn't scored.
	}

	if in := r.Internet; in != nil && r.Ran(checks.Internet) {
		switch {
		case in.Captive != nil && in.Captive.Detected:
			add(checks.Internet, 0, "captive portal")
		case !in.Reachable:
			add(checks.Internet, 0, "unreachable")
		case in.ICMPBlocked:
			if t := in.BestTCP(); t != nil {
				addWorst(checks.Internet, metric{fmt.Sprintf("TCP connect %s", ms(t.Stats.AvgMs)), metricScore(t.Stats.AvgMs, th.InternetWarnMs, th.InternetFailMs)})
			}
		default:
			if p := bestInternetStats(in); p != nil {
				s := p.Stats
				addWorst(checks.Internet,
					metric{fmt.Sprintf("avg latency %s", ms(s.AvgMs)), metricScore(s.AvgMs, th.InternetWarnMs, th.InternetFailMs)},
					metric{fmt.Sprintf("loss %s", pct(s.LossPct)), metricScore(s.LossPct, th.InternetLossWarnPct, th.InternetLossFailPct)},
					metric{fmt.Sprintf("jitter %s", ms(s.JitterMs)), metricScore(s.JitterMs, th.JitterWarnMs, th.JitterFailMs)},
				)
			}
		}
	}

	if d := r.DNS; d != nil {
		if sys := d.System(); sys != nil {
			if sys.Unreachable() {
				add(checks.DNS, 0, "resolver not answering")
			} else {
				score, basis := worst(metric{fmt.Sprintf("avg lookup %s", ms(sys.AvgMs)), metricScore(sys.AvgMs, th.DNSWarnMs, th.DNSFailMs)})
				if n := len(sys.Queries); n > 0 && sys.Failures > 0 {
					score *= 1 - float64(sys.Failures)/float64(n)
					basis += fmt.Sprintf(", %d/%d failed", sys.Failures, n)
				}
				add(checks.DNS, score, basis)
			}
		}
	}

	if h := r.HTTP; h != nil && r.States[checks.HTTP].Outcome != "" {
		if h.OK == 0 {
			add(checks.HTTP, 0, "requests failed")
		} else {
			score, basis := worst(
				metric{fmt.Sprintf("TCP connect %s", ms(h.ConnectMs)), metricScore(h.ConnectMs, th.TCPWarnMs, th.TCPFailMs)},
				metric{fmt.Sprintf("TLS %s", ms(h.TLSMs)), metricScore(h.TLSMs, th.TLSWarnMs, th.TLSFailMs)},
				metric{fmt.Sprintf("TTFB %s", ms(h.TTFBMs)), metricScore(h.TTFBMs, th.TTFBWarnMs, th.TTFBFailMs)},
			)
			score *= float64(h.OK) / float64(len(h.Samples))
			add(checks.HTTP, score, basis)
		}
	}

	if s := r.Speed; s != nil && r.Ran(checks.Speed) {
		addWorst(checks.Speed, metric{fmt.Sprintf("download %.0f Mbps", s.DownloadMbps), metricScoreLow(s.DownloadMbps, th.DownloadWarnMbps, th.DownloadFailMbps)})
	}

	if down != "" {
		rating.Score, rating.Grade = 0, "Down"
		return rating
	}
	var sum, wsum float64
	for _, l := range rating.Layers {
		sum += float64(l.Score) * l.Weight
		wsum += l.Weight
	}
	if wsum == 0 {
		rating.Grade = "Unknown"
		return rating
	}
	rating.Score = int(math.Round(sum / wsum))
	rating.Grade = GradeFor(rating.Score)
	return rating
}

// GradeFor maps a score to its grade label.
func GradeFor(score int) string {
	switch {
	case score >= 90:
		return "Excellent"
	case score >= 75:
		return "Good"
	case score >= 50:
		return "Fair"
	case score > 0:
		return "Poor"
	}
	return "Down"
}
