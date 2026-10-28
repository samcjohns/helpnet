package interpret

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/samcjohns/nethelp/internal/checks"
	"github.com/samcjohns/nethelp/internal/sysinfo"
)

// Explanation walks through one clear-cut problem in plain words: what was
// measured, with the numbers from this run, and the fix with short how-to
// steps. Only problems whose fix follows directly from the measurements get
// one; everything else stays a finding.
type Explanation struct {
	Rule     string   `json:"rule"` // the finding it explains
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	What     string   `json:"what"` // what nethelp measured
	Fix      string   `json:"fix"`
	Steps    []string `json:"steps,omitempty"`
}

// ExplainTopics names the problems Explain covers, for "nothing to explain".
var ExplainTopics = []string{
	"slow DNS", "a DNS server that doesn't answer", "a captive portal (login page)",
	"a weak Wi-Fi signal", "Wi-Fi limiting your speed",
}

// Explain returns explanations for the warn/fail findings that have an
// obvious fix, in finding order. goos selects the how-to steps
// ("windows", "darwin", "linux"; anything else gets generic steps).
func Explain(r *checks.Results, fs []Finding, goos string) []Explanation {
	var out []Explanation
	for _, f := range fs {
		if f.Severity < Warn {
			continue
		}
		var e *Explanation
		switch f.Rule {
		case RuleDNSSystemSlow:
			e = explainDNSSlow(r, fs, goos)
		case RuleDNSSystemDown:
			e = explainDNSDown(r, fs, goos)
		case RuleCaptivePortal:
			e = explainCaptive(r)
		case RuleWeakWiFi:
			e = explainWeakWiFi(r)
		case RuleSlowDownload:
			if wifiLimitsSpeed(r) {
				e = explainWiFiSpeed(r)
			}
		}
		if e != nil {
			e.Rule, e.Severity, e.Title = f.Rule, f.Severity, f.Title
			out = append(out, *e)
		}
	}
	return out
}

// ---- DNS -------------------------------------------------------------------

type dnsProvider struct{ name, alt string }

// dnsProviders names well-known public resolvers and their backup address.
var dnsProviders = map[string]dnsProvider{
	"1.1.1.1":         {"Cloudflare", "1.0.0.1"},
	"1.0.0.1":         {"Cloudflare", "1.1.1.1"},
	"9.9.9.9":         {"Quad9", "149.112.112.112"},
	"149.112.112.112": {"Quad9", "9.9.9.9"},
	"8.8.8.8":         {"Google", "8.8.4.4"},
	"8.8.4.4":         {"Google", "8.8.8.8"},
}

// dnsSwitchable reports whether "use a public DNS server" is an obvious fix.
// It isn't when a VPN carries traffic (its resolver may be needed for
// internal names) or when the resolver filters answers on purpose
// (parental controls, ad blocking, workplace policy).
func dnsSwitchable(r *checks.Results, fs []Finding) bool {
	if r.Local != nil && r.Local.VPN.DefaultRoute {
		return false
	}
	return !slices.ContainsFunc(fs, func(f Finding) bool { return f.Rule == RuleDNSDiffers })
}

// sysResolverLabels returns how to refer to the system resolver: a full
// label for the first mention and a short one after it.
func sysResolverLabels(r *checks.Results, sys *checks.ResolverStats) (full, short string) {
	if sys.Name == "" || sys.Name == "system" {
		return "your configured DNS server", "your DNS server"
	}
	if r.Local != nil && r.Local.Gateway != "" && slices.Contains(strings.Split(sys.Name, ", "), r.Local.Gateway) {
		return "your router (" + sys.Name + ")", "your router"
	}
	return "your DNS server (" + sys.Name + ")", "your DNS server"
}

// pubResolver describes the public resolver to recommend.
func pubResolver(pub *checks.ResolverStats) (label, name, primary, alt string) {
	primary = firstNonEmpty(pub.Server, pub.Name)
	if p, ok := dnsProviders[primary]; ok {
		return fmt.Sprintf("%s's DNS server (%s)", p.name, primary), p.name + "'s DNS", primary, p.alt
	}
	return "the public DNS server " + primary, "the public DNS server", primary, ""
}

func domainList(ds []string) string {
	switch {
	case len(ds) == 0:
		return "a few websites"
	case len(ds) == 1:
		return ds[0]
	case len(ds) == 2:
		return ds[0] + " and " + ds[1]
	}
	return fmt.Sprintf("%s, %s and %d other sites", ds[0], ds[1], len(ds)-2)
}

func times(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.1f×", v)
	}
	return fmt.Sprintf("%.0f×", v)
}

func explainDNSSlow(r *checks.Results, fs []Finding, goos string) *Explanation {
	d := r.DNS
	sys, pub := d.System(), d.BestPublic()
	if sys == nil || pub == nil || pub.AvgMs <= 0 || !dnsSwitchable(r, fs) {
		return nil
	}
	full, _ := sysResolverLabels(r, sys)
	label, name, primary, alt := pubResolver(pub)
	return &Explanation{
		What: fmt.Sprintf("Your computer asked for the address of %s. %s answered in %s on average, which is %s slower than %s at %s. "+
			"Every new website you open starts with one of these lookups, so this delay comes before the page even starts loading.",
			domainList(d.Domains), capitalize(full), ms(sys.AvgMs), times(sys.AvgMs/pub.AvgMs), label, ms(pub.AvgMs)),
		Fix:   dnsFix(name, primary, alt),
		Steps: dnsSteps(r, goos, primary, alt),
	}
}

func explainDNSDown(r *checks.Results, fs []Finding, goos string) *Explanation {
	d := r.DNS
	sys, pub := d.System(), d.BestPublic()
	if sys == nil || pub == nil || !dnsSwitchable(r, fs) {
		return nil
	}
	full, short := sysResolverLabels(r, sys)
	label, name, primary, alt := pubResolver(pub)
	steps := dnsSteps(r, goos, primary, alt)
	if short == "your router" {
		steps = append(steps, "Restarting the router often brings its DNS back for a while; switching is the lasting fix.")
	}
	return &Explanation{
		What: fmt.Sprintf("Your computer asked %s for the address of %s %d times and got no answer at all. %s answered the same questions in %s on average, "+
			"so your connection works; only %s has stopped answering. Without DNS, browsers can't turn website names into addresses, so pages fail to load even though the internet is up.",
			full, domainList(d.Domains), len(sys.Queries), capitalize(label), ms(pub.AvgMs), short),
		Fix:   dnsFix(name, primary, alt),
		Steps: steps,
	}
}

func dnsFix(name, primary, alt string) string {
	if alt == "" {
		return fmt.Sprintf("Change your DNS server to %s (%s).", name, primary)
	}
	return fmt.Sprintf("Change your DNS server to %s: %s, with %s as the backup.", name, primary, alt)
}

func dnsSteps(r *checks.Results, goos, primary, alt string) []string {
	both := primary
	if alt != "" {
		both = primary + " and " + alt
	}
	conn := "your connection"
	if r.Local != nil && (r.Local.Type == sysinfo.TypeWiFi || r.Local.Type == sysinfo.TypeEthernet) {
		conn = r.Local.Type
	}
	var steps []string
	switch goos {
	case "windows":
		s := fmt.Sprintf("Open Settings → Network & internet → %s → your network's properties. Next to DNS server assignment, click Edit, choose Manual, turn on IPv4 and enter %s as Preferred DNS", conn, primary)
		if alt != "" {
			s += " and " + alt + " as Alternate DNS"
		}
		steps = append(steps, s+". Click Save.")
	case "darwin":
		steps = append(steps, fmt.Sprintf("Open System Settings → Network → %s → Details… → DNS. Click + under DNS Servers, add %s, then click OK.", conn, both))
	case "linux":
		steps = append(steps,
			fmt.Sprintf("Open your network settings, edit this connection, and on the IPv4 tab turn off automatic DNS and enter %s.", strings.ReplaceAll(both, " and ", ", ")),
			fmt.Sprintf("Or, with NetworkManager in a terminal: nmcli connection modify \"<connection name>\" ipv4.dns \"%s\" ipv4.ignore-auto-dns yes, then reconnect.", strings.ReplaceAll(both, " and ", " ")))
	default:
		steps = append(steps, fmt.Sprintf("In your system's network settings, set the DNS servers for %s to %s.", conn, both))
	}
	return append(steps,
		"To fix it for every device at once, enter the same addresses as the DNS servers on your router's admin page (usually under DHCP or Internet settings).",
		"Then run /dns to see the difference.")
}

// ---- Captive portal --------------------------------------------------------

func explainCaptive(r *checks.Results) *Explanation {
	in := r.Internet
	if in == nil || in.Captive == nil || !in.Captive.Detected {
		return nil
	}
	c := in.Captive
	got := fmt.Sprintf("HTTP %d", c.Status)
	portal := ""
	if u, err := url.Parse(c.Location); err == nil && u.Host != "" {
		got += " and sent it on to " + u.Host
		portal = u.Scheme + "://" + u.Host
	} else if c.BodySample != "" {
		got += " with a web page"
	}
	steps := []string{"Open a browser and go to http://neverssl.com. It is a plain http:// site, so the network can redirect you to its sign-in page."}
	if portal != "" {
		steps[0] = "Open a browser and go to " + portal + " (where the network redirected nethelp), or to http://neverssl.com."
	}
	steps = append(steps,
		"Sign in, enter the room number or voucher code, or accept the terms on the page that appears.",
		"Then press r to run the checks again.")
	return &Explanation{
		What: fmt.Sprintf("nethelp opened %s, a test page that always gives an empty reply (HTTP 204) when you're really on the internet. "+
			"This network answered with %s instead. Something is holding back your web traffic until you sign in: a captive portal, common on hotel, airport, café and guest Wi-Fi.",
			c.URL, got),
		Fix:   "Open the network's sign-in page and log in or accept its terms.",
		Steps: steps,
	}
}

// ---- Wi-Fi -----------------------------------------------------------------

func wifiSignal(w *sysinfo.WiFiInfo) string {
	if w.SignalDBm != 0 {
		return fmt.Sprintf("%d dBm (about %d%%)", w.SignalDBm, w.Quality())
	}
	return fmt.Sprintf("%d%%", w.Quality())
}

func explainWeakWiFi(r *checks.Results) *Explanation {
	if r.Local == nil || r.Local.WiFi == nil {
		return nil
	}
	w := r.Local.WiFi
	what := fmt.Sprintf("Your Wi-Fi signal is %s. A strong signal is -60 dBm (80%%) or better; below -80 dBm (40%%) the connection drops to slower speeds and has to resend data.", wifiSignal(w))
	if w.LinkRateMbps > 0 {
		what += fmt.Sprintf(" Your device and router are currently connected at %.0f Mbps.", w.LinkRateMbps)
	}
	if g := r.Gateway; g != nil && g.Ping.Stats.Received > 0 {
		s := g.Ping.Stats
		what += fmt.Sprintf(" Pings to your router averaged %s with %s loss.", ms(s.AvgMs), pct(s.LossPct))
	}
	return &Explanation{
		What: what,
		Fix:  "Get a stronger signal: move closer to the router or connect with an Ethernet cable.",
		Steps: []string{
			"Move into the same room as the router, or within sight of it. Walls, floors, mirrors and metal furniture weaken the signal the most.",
			"Raise the router off the floor and away from microwaves and cordless phone bases.",
			"If you can, plug in an Ethernet cable; that removes the problem entirely.",
			"If the router is far from where you usually sit, a mesh system or Wi-Fi extender placed halfway between brings the signal to you.",
		},
	}
}

func explainWiFiSpeed(r *checks.Results) *Explanation {
	w, s := r.Local.WiFi, r.Speed
	move := "Move closer to the router; the link rate rises as the signal gets stronger."
	if w.SignalDBm != 0 {
		move = fmt.Sprintf("Move closer to the router; the link rate rises as the signal gets stronger (yours is %d dBm, and -60 dBm or better is strong).", w.SignalDBm)
	}
	return &Explanation{
		What: fmt.Sprintf("The speed test downloaded at %.1f Mbps. Your Wi-Fi link (the raw speed your device and router agreed to talk at) is %.0f Mbps, "+
			"and Wi-Fi usually delivers about half its link rate as real throughput, so roughly %.0f Mbps here. "+
			"The Wi-Fi between this device and the router is the bottleneck, not necessarily your internet plan.",
			s.DownloadMbps, w.LinkRateMbps, w.LinkRateMbps/2),
		Fix: "Improve the Wi-Fi link: get closer to the router, use its 5 GHz network, or use Ethernet.",
		Steps: []string{
			move,
			"If your router broadcasts a second network (often with \"5G\" or \"5GHz\" in its name), connect to that one; it is several times faster within a room or two.",
			"Plug in an Ethernet cable to see what your plan really delivers.",
			"Then run /speed again to compare.",
		},
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
