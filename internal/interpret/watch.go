package interpret

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/samcjohns/helpnet/internal/config"
	"github.com/samcjohns/helpnet/internal/watch"
)

// WatchCause is where an incident in watch mode most likely came from.
type WatchCause string

const (
	CauseLocal    WatchCause = "local"    // the gateway failed too: Wi-Fi, cable or router
	CauseUpstream WatchCause = "upstream" // past this device, but the gateway can't be measured
	CauseISP      WatchCause = "isp"      // the gateway was fine, the internet wasn't
	CauseDNS      WatchCause = "dns"      // only name lookups failed
	CauseRouter   WatchCause = "router"   // only pings to the router failed: harmless deprioritisation
)

// causeOrder breaks ties between causes, lowest layer first.
var causeOrder = []WatchCause{CauseLocal, CauseUpstream, CauseISP, CauseDNS, CauseRouter}

// watchMergeGap is how many good samples may sit inside one event before it
// counts as two: a single answer in the middle of a burst doesn't end it.
const watchMergeGap = 1

// WatchEvent is a run of lost or slow probes on one layer.
type WatchEvent struct {
	Layer       watch.Layer `json:"layer"`
	Start       time.Time   `json:"start"` // first bad sample
	End         time.Time   `json:"end"`   // last bad sample
	Lost        int         `json:"lost"`
	Slow        int         `json:"slow"`
	WorstMs     float64     `json:"worst_ms,omitempty"` // slowest answer in the event
	first, last int         // sample indexes
}

// Drop reports whether any probe in the event went unanswered.
func (e WatchEvent) Drop() bool { return e.Lost > 0 }

// Length is the time from the first to the last bad sample, at least one tick.
func (e WatchEvent) Length(tick time.Duration) time.Duration {
	return e.End.Sub(e.Start) + tick
}

// WatchIncident groups events on different layers that overlap in time.
type WatchIncident struct {
	Start  time.Time    `json:"start"`
	End    time.Time    `json:"end"`
	Cause  WatchCause   `json:"cause"`
	Drop   bool         `json:"drop"` // false: latency spike only
	Events []WatchEvent `json:"events"`
	last   int
}

// WatchLayerStats summarises one layer over the whole watch.
type WatchLayerStats struct {
	Samples  int     `json:"samples"`
	Lost     int     `json:"lost"`
	Slow     int     `json:"slow"`
	MedianMs float64 `json:"median_ms"`
}

// WatchAnalysis is the verdict of a watch.
type WatchAnalysis struct {
	Start      time.Time                       `json:"start"`
	End        time.Time                       `json:"end"`
	Tick       time.Duration                   `json:"tick"`
	Samples    int                             `json:"samples"`
	Layers     map[watch.Layer]WatchLayerStats `json:"layers"`
	Incidents  []WatchIncident                 `json:"incidents"` // includes harmless router ones
	Counted    int                             `json:"counted"`   // incidents that aren't harmless
	Primary    WatchCause                      `json:"primary,omitempty"`
	Severity   Severity                        `json:"severity"`
	Conclusion string                          `json:"conclusion"`
	Suggestion string                          `json:"suggestion,omitempty"`
}

// SlowThreshold is the latency above which a probe of layer l counts as a
// spike: the layer's fail threshold.
func SlowThreshold(l watch.Layer, wifi bool, th config.Thresholds) float64 {
	switch l {
	case watch.Gateway:
		if wifi {
			return th.GatewayWiFiFailMs
		}
		return th.GatewayEthernetFailMs
	case watch.Internet:
		return th.InternetFailMs
	}
	return th.DNSFailMs
}

// AnalyzeWatch finds loss bursts and latency spikes in samples (oldest
// first), groups the ones that happen together, and blames each group on the
// lowest layer that failed. wifi says whether the link is Wi-Fi, which picks
// the gateway threshold and the wording. It is called on the samples so far
// after every tick, so it must cope with an empty or short slice.
func AnalyzeWatch(samples []watch.Sample, wifi bool, th config.Thresholds) WatchAnalysis {
	a := WatchAnalysis{Samples: len(samples), Layers: map[watch.Layer]WatchLayerStats{}, Tick: time.Second}
	if len(samples) == 0 {
		a.Conclusion = "Watching…"
		return a
	}
	a.Start, a.End = samples[0].At, samples[len(samples)-1].At
	if len(samples) > 1 {
		a.Tick = a.End.Sub(a.Start) / time.Duration(len(samples)-1)
	}

	var events []WatchEvent
	for _, l := range watch.Layers {
		thr := SlowThreshold(l, wifi, th)
		var st WatchLayerStats
		var rtts []float64
		var cur *WatchEvent
		for i, s := range samples {
			p := s.Get(l)
			if !p.Ran {
				continue
			}
			st.Samples++
			slow := p.OK && p.Ms > thr
			switch {
			case !p.OK:
				st.Lost++
			case slow:
				st.Slow++
			}
			if p.OK {
				rtts = append(rtts, p.Ms)
			}
			if p.OK && !slow {
				continue
			}
			if cur == nil || i-cur.last > watchMergeGap+1 {
				if cur != nil {
					events = append(events, *cur)
				}
				cur = &WatchEvent{Layer: l, Start: s.At, first: i}
			}
			cur.End, cur.last = s.At, i
			if p.OK {
				cur.Slow++
				cur.WorstMs = max(cur.WorstMs, p.Ms)
			} else {
				cur.Lost++
			}
		}
		if cur != nil {
			events = append(events, *cur)
		}
		st.MedianMs = median(rtts)
		a.Layers[l] = st
	}

	// Group overlapping events into incidents.
	slices.SortStableFunc(events, func(x, y WatchEvent) int { return x.first - y.first })
	for _, e := range events {
		if n := len(a.Incidents); n > 0 && e.first <= a.Incidents[n-1].last+1 {
			in := &a.Incidents[n-1]
			in.Events = append(in.Events, e)
			if e.last > in.last {
				in.End, in.last = e.End, e.last
			}
			continue
		}
		a.Incidents = append(a.Incidents, WatchIncident{Start: e.Start, End: e.End, Events: []WatchEvent{e}, last: e.last})
	}
	counts := map[WatchCause]int{}
	for i := range a.Incidents {
		in := &a.Incidents[i]
		in.Cause = incidentCause(*in, samples, wifi, th)
		for _, e := range in.Events {
			in.Drop = in.Drop || e.Drop()
		}
		if in.Cause == CauseRouter {
			continue
		}
		a.Counted++
		counts[in.Cause]++
		if in.Drop {
			a.Severity = Fail
		} else if a.Severity < Warn {
			a.Severity = Warn
		}
	}
	for _, c := range causeOrder {
		if c != CauseRouter && counts[c] > 0 && (a.Primary == "" || counts[c] > counts[a.Primary]) {
			a.Primary = c
		}
	}
	a.Conclusion, a.Suggestion = watchVerdict(a, counts, wifi)
	return a
}

func incidentCause(in WatchIncident, samples []watch.Sample, wifi bool, th config.Thresholds) WatchCause {
	has := map[watch.Layer]bool{}
	for _, e := range in.Events {
		has[e.Layer] = true
	}
	gatewayMeasured := false
	for _, s := range samples {
		gatewayMeasured = gatewayMeasured || s.Gateway.Ran
	}
	switch {
	case has[watch.Gateway] && (has[watch.Internet] || has[watch.DNS]):
		return CauseLocal
	case has[watch.Gateway]:
		// Pings to the router failed but traffic through it was fine: the
		// router just deprioritised pings to itself (see deviation 2).
		thr := SlowThreshold(watch.Internet, wifi, th)
		for _, s := range samples[in.Events[0].first : in.last+1] {
			if p := s.Internet; !p.Ran || !p.OK || p.Ms > thr {
				return CauseLocal
			}
		}
		return CauseRouter
	case has[watch.Internet] && !gatewayMeasured:
		return CauseUpstream
	case has[watch.Internet]:
		return CauseISP
	}
	return CauseDNS
}

func watchVerdict(a WatchAnalysis, counts map[WatchCause]int, wifi bool) (conclusion, suggestion string) {
	span := FormatWatchDuration(a.End.Sub(a.Start) + a.Tick)
	harmless := len(a.Incidents) - a.Counted
	if a.Counted == 0 {
		c := fmt.Sprintf("No drops or spikes in %s; the connection was stable while watched.", span)
		if harmless > 0 {
			c = fmt.Sprintf("No real drops in %s. The router ignored some pings to itself (%d %s), but traffic through it was fine.", span, harmless, pluralWord(harmless, "time", "times"))
		}
		return c, "If the problem comes back, run a longer /watch while it's happening."
	}
	drops, spikes := 0, 0
	for _, in := range a.Incidents {
		switch {
		case in.Cause == CauseRouter:
		case in.Drop:
			drops++
		default:
			spikes++
		}
	}
	var what []string
	if drops > 0 {
		what = append(what, fmt.Sprintf("%d %s", drops, pluralWord(drops, "drop", "drops")))
	}
	if spikes > 0 {
		what = append(what, fmt.Sprintf("%d %s", spikes, pluralWord(spikes, "latency spike", "latency spikes")))
	}
	where, meaning := causeWords(a.Primary, wifi)
	switch n := counts[a.Primary]; {
	case n < a.Counted:
		where = fmt.Sprintf("%d of %d %s", n, a.Counted, where)
		meaning = "most likely " + meaning
	case n > 1:
		where = "all " + where
	}
	conclusion = fmt.Sprintf("%s in %s, %s, so it's %s.", strings.Join(what, " and "), span, where, meaning)
	switch a.Primary {
	case CauseLocal:
		suggestion = "Check the cable and the router, and restart the router if it keeps happening."
		if wifi {
			suggestion = "Move closer to the router, switch to the 5 GHz band, or try Ethernet. If it still drops on Ethernet, it's the router."
		}
	case CauseISP:
		suggestion = "Your router stayed reachable while the internet dropped. Note the times above and report them to your ISP."
	case CauseUpstream:
		suggestion = "Try again on Ethernet, or ask your ISP whether they see drops at these times."
	case CauseDNS:
		suggestion = "Try a different DNS server (for example 1.1.1.1 or 9.9.9.9) in your network settings."
	}
	return conclusion, suggestion
}

// causeWords returns where an incident happened and what that means.
func causeWords(c WatchCause, wifi bool) (where, meaning string) {
	switch c {
	case CauseLocal:
		if wifi {
			return "at the gateway", "local Wi-Fi"
		}
		return "at the gateway", "your local network or router"
	case CauseISP:
		return "past your router", "your ISP or the wider internet"
	case CauseUpstream:
		return "past this device", "beyond this device (the router doesn't answer probes, so local and ISP can't be told apart)"
	case CauseDNS:
		return "in DNS only", "your DNS resolver"
	}
	return "at the router", "harmless"
}

// FormatWatchDuration renders a watch length the way people say it:
// "45 s", "10 min", "1 h 5 min".
func FormatWatchDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		m, s := int(d.Minutes()), int(d.Seconds())%60
		if s == 0 || m >= 10 {
			return fmt.Sprintf("%d min", int(d.Round(time.Minute).Minutes()))
		}
		return fmt.Sprintf("%d min %d s", m, s)
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	if m == 0 {
		return fmt.Sprintf("%d h", h)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}
