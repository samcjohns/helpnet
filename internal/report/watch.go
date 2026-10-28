package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/samcjohns/nethelp/internal/interpret"
	"github.com/samcjohns/nethelp/internal/watch"
)

// WatchLayerNames are the display names of the watched layers.
var WatchLayerNames = map[watch.Layer]string{
	watch.Gateway:  "Gateway",
	watch.Internet: "Internet",
	watch.DNS:      "DNS",
}

func watchLayerWord(l watch.Layer) string {
	if l == watch.DNS {
		return "DNS"
	}
	return strings.ToLower(WatchLayerNames[l])
}

// WatchLayerStats renders one layer's totals, e.g. "2 lost · 1 slow · median 3.1 ms".
func WatchLayerStats(st interpret.WatchLayerStats) string {
	if st.Samples == 0 {
		return "not measured"
	}
	parts := []string{fmt.Sprintf("%d lost", st.Lost)}
	if st.Slow > 0 {
		parts = append(parts, fmt.Sprintf("%d slow", st.Slow))
	}
	if st.Samples > st.Lost {
		parts = append(parts, "median "+fmtMs(st.MedianMs))
	}
	return strings.Join(parts, " · ")
}

// WatchIncidentText describes an incident without its time, e.g.
// "drop · gateway + internet · 4 s, 4 lost → local Wi-Fi".
func WatchIncidentText(in interpret.WatchIncident, tick time.Duration, wifi bool) string {
	var layers []string
	lost, worst := 0, 0.0
	var length time.Duration
	for _, l := range watch.Layers {
		for _, e := range in.Events {
			if e.Layer != l {
				continue
			}
			layers = append(layers, watchLayerWord(l))
			lost = max(lost, e.Lost)
			worst = max(worst, e.WorstMs)
			length = max(length, e.Length(tick))
			break
		}
	}
	kind, detail := "spike", "worst "+fmtMs(worst)
	if in.Drop {
		kind, detail = "drop", fmt.Sprintf("%d lost", lost)
	}
	text := fmt.Sprintf("%s · %s · %s, %s", kind, strings.Join(layers, " + "), interpret.FormatWatchDuration(length), detail)
	if in.Cause == interpret.CauseRouter {
		return text + " → router ignored pings to itself (harmless)"
	}
	return text + " → " + WatchCauseLabel(in.Cause, wifi)
}

// WatchCauseLabel is a short name for a cause.
func WatchCauseLabel(c interpret.WatchCause, wifi bool) string {
	switch c {
	case interpret.CauseLocal:
		if wifi {
			return "local Wi-Fi"
		}
		return "local network"
	case interpret.CauseISP:
		return "ISP"
	case interpret.CauseUpstream:
		return "past this device"
	case interpret.CauseDNS:
		return "DNS"
	}
	return "router"
}

// WatchSummary renders a finished watch as plain text for the clipboard.
func WatchSummary(a interpret.WatchAnalysis, wifi bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "nethelp watch · %s · %s\n\n", a.Start.Local().Format("2006-01-02 15:04"), interpret.FormatWatchDuration(a.End.Sub(a.Start)+a.Tick))
	fmt.Fprintf(&b, "%s\n", a.Conclusion)
	if a.Suggestion != "" {
		fmt.Fprintf(&b, "%s\n", a.Suggestion)
	}
	b.WriteString("\n")
	for _, l := range watch.Layers {
		fmt.Fprintf(&b, "%-9s %s\n", WatchLayerNames[l], WatchLayerStats(a.Layers[l]))
	}
	if len(a.Incidents) > 0 {
		b.WriteString("\nTimeline\n")
		for _, in := range a.Incidents {
			fmt.Fprintf(&b, "%s  %s\n", in.Start.Local().Format("15:04:05"), WatchIncidentText(in, a.Tick, wifi))
		}
	}
	return b.String()
}
