package interpret

import (
	"strings"

	"github.com/samcjohns/helpnet/internal/probe"
	"github.com/samcjohns/helpnet/internal/sysinfo"
)

// HopRole is a best guess at what a hop on the route is.
type HopRole string

const (
	RoleRouter      HopRole = "router"       // your own router (gateway)
	RoleLocalRouter HopRole = "local-router" // a second router on your premises
	RoleVPN         HopRole = "vpn"          // inside a VPN tunnel
	RoleCGNAT       HopRole = "cgnat"        // ISP carrier-grade NAT
	RoleISP         HopRole = "isp"          // your ISP's network
	RoleIXP         HopRole = "ixp"          // an internet exchange point
	RoleTransit     HopRole = "transit"      // a backbone/transit carrier
	RoleInternet    HopRole = "internet"     // a router we can't place
	RoleDestNet     HopRole = "dest-network" // the destination's own network
	RoleDest        HopRole = "destination"
	RoleSilent      HopRole = "silent" // one or more hops that never answered
)

// RouteHop is one stop on the route map. Silent hops in a row are merged.
type RouteHop struct {
	probe.TraceHop
	LastTTL   int // last TTL covered (> TTL only for merged silent hops)
	Role      HopRole
	Label     string  // e.g. "Your router", "ISP network"
	Org       string  // operator guessed from reverse DNS, e.g. "Google"
	Place     string  // location guessed from reverse DNS, e.g. "London"
	DeltaMs   float64 // latency added since the previous answering hop
	Loss      bool    // packet loss starts here and persists
	Jump      bool    // a persistent latency jump starts here
	RateLimit bool    // drops trace probes but later hops are fine
}

// RouteMap is a stylised, annotated view of a route trace.
type RouteMap struct {
	Target   string
	Tool     string
	Reached  bool
	VPN      bool // the default route goes through a VPN, hiding the real path
	Hops     []RouteHop
	Analysis TraceAnalysis
}

// MapRoute annotates a trace with guesses about who runs each hop. The
// guesses come only from the addresses and their reverse DNS names; nothing
// is looked up externally. local may be nil.
func MapRoute(t *probe.TraceResult, local *sysinfo.Info) RouteMap {
	rm := RouteMap{}
	if t == nil {
		return rm
	}
	rm.Target, rm.Tool = t.Target, t.Tool
	if local != nil {
		rm.VPN = local.VPN.DefaultRoute
	}
	rm.Analysis = AnalyzeTrace(t.Hops)
	rm.Reached = rm.Analysis.FinalReached

	gateway := ""
	if local != nil {
		gateway = local.Gateway
	}
	// The ISP is whoever names the first public hop; unnamed hops count as
	// ISP only while a later hop still carries its name.
	ispDomain, lastISP := "", -1
	for i, h := range t.Hops {
		if !h.Responded() || len(h.Hosts) == 0 || !probe.IsPublicAddr(h.Hosts[0]) {
			continue
		}
		d := registeredDomain(h.Name)
		if _, role := knownOrg(h.Name); role != "" || looksLikeIXP(h.Name) {
			break
		}
		if ispDomain == "" && d != "" {
			ispDomain = d
		}
		if d != "" && d == ispDomain {
			lastISP = i
		} else if d != "" {
			break
		}
	}
	var (
		prev       *probe.TraceHop // previous answering hop
		first      *probe.TraceHop // hop 1, if it answered
		pastISP    bool            // a hop beyond the ISP has been seen
		seenPublic bool
	)
	for i, h := range t.Hops {
		if !h.Responded() || len(h.Hosts) == 0 {
			if n := len(rm.Hops); n > 0 && rm.Hops[n-1].Role == RoleSilent {
				rm.Hops[n-1].LastTTL = h.TTL
				continue
			}
			rm.Hops = append(rm.Hops, RouteHop{TraceHop: h, LastTTL: h.TTL, Role: RoleSilent, Label: "No reply"})
			continue
		}
		rh := RouteHop{TraceHop: h, LastTTL: h.TTL}
		if prev != nil {
			rh.DeltaMs = h.AvgMs - prev.AvgMs
		}
		addr := h.Hosts[0]
		domain := registeredDomain(h.Name)
		org, orgRole := knownOrg(h.Name)
		rh.Place = guessPlace(h.Name)
		isLast := i == len(t.Hops)-1 && rm.Reached
		switch {
		case rm.VPN && !seenPublic && !probe.IsPublicAddr(addr):
			rh.Role = RoleVPN
		case !seenPublic && (h.TTL <= 1 || addr == gateway) && !probe.IsPublicAddr(addr):
			rh.Role = RoleRouter
			first = &t.Hops[i]
		case !seenPublic && probe.IsCGNAT(addr):
			rh.Role = RoleCGNAT
		case !seenPublic && probe.IsPrivateAddr(addr) && h.TTL == 2 && first != nil && bestMs(h) <= bestMs(*first)+2:
			rh.Role = RoleLocalRouter
		case !seenPublic && !probe.IsPublicAddr(addr):
			rh.Role = RoleISP // ISPs often number their first routers privately
		default:
			seenPublic = true
			switch {
			case isLast:
				rh.Role = RoleDest
			case orgRole == RoleDestNet:
				rh.Role, pastISP = RoleDestNet, true
			case looksLikeIXP(h.Name):
				rh.Role, pastISP = RoleIXP, true
			case orgRole == RoleTransit:
				rh.Role, pastISP = RoleTransit, true
			case !pastISP && ispDomain != "" && (domain == ispDomain || domain == "" && i < lastISP):
				rh.Role = RoleISP
			default:
				rh.Role, pastISP = RoleInternet, i > lastISP
			}
		}
		if rh.Role == RoleISP && org == "" {
			org = ispDomain
		}
		if rh.Role == RoleDest && org == "" {
			if org, _ = knownOrg(t.Target); org == "" {
				org = domain
			}
		}
		rh.Org = org
		rh.Label = roleLabel(rh.Role)
		rh.Loss = h.TTL == rm.Analysis.LossHop
		rh.Jump = h.TTL == rm.Analysis.JumpHop
		for _, ttl := range rm.Analysis.RateLimited {
			if ttl == h.TTL && rm.Analysis.LossHop == 0 {
				rh.RateLimit = true
			}
		}
		rm.Hops = append(rm.Hops, rh)
		prev = &t.Hops[i]
	}
	return rm
}

func roleLabel(r HopRole) string {
	switch r {
	case RoleRouter:
		return "Your router"
	case RoleLocalRouter:
		return "Second local router"
	case RoleVPN:
		return "VPN tunnel"
	case RoleCGNAT:
		return "ISP carrier-grade NAT"
	case RoleISP:
		return "ISP network"
	case RoleIXP:
		return "Internet exchange"
	case RoleTransit:
		return "Backbone carrier"
	case RoleDestNet:
		return "Destination network"
	case RoleDest:
		return "Destination"
	case RoleSilent:
		return "No reply"
	}
	return "Internet router"
}

// registeredDomain returns the last two labels of a hostname (three for
// common second-level country domains such as co.uk), or "".
func registeredDomain(name string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	if len(labels) < 2 {
		return ""
	}
	n := 2
	sld := labels[len(labels)-2]
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && (sld == "co" || sld == "com" || sld == "net" || sld == "ne" || sld == "or" || sld == "ac") {
		n = 3
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

// orgs maps reverse-DNS domains to well-known operators.
var orgs = map[string]struct {
	name string
	role HopRole
}{
	"1e100.net":                {"Google", RoleDestNet},
	"google.com":               {"Google", RoleDestNet},
	"googleusercontent.com":    {"Google", RoleDestNet},
	"cloudflare.com":           {"Cloudflare", RoleDestNet},
	"cloudflare.net":           {"Cloudflare", RoleDestNet},
	"akamaitechnologies.com":   {"Akamai", RoleDestNet},
	"akamaiedge.net":           {"Akamai", RoleDestNet},
	"amazonaws.com":            {"Amazon AWS", RoleDestNet},
	"fastly.net":               {"Fastly", RoleDestNet},
	"facebook.com":             {"Meta", RoleDestNet},
	"fbcdn.net":                {"Meta", RoleDestNet},
	"msn.net":                  {"Microsoft", RoleDestNet},
	"microsoft.com":            {"Microsoft", RoleDestNet},
	"apple.com":                {"Apple", RoleDestNet},
	"level3.net":               {"Lumen", RoleTransit},
	"lumen.com":                {"Lumen", RoleTransit},
	"cogentco.com":             {"Cogent", RoleTransit},
	"he.net":                   {"Hurricane Electric", RoleTransit},
	"telia.net":                {"Arelion", RoleTransit},
	"arelion.net":              {"Arelion", RoleTransit},
	"ntt.net":                  {"NTT", RoleTransit},
	"gtt.net":                  {"GTT", RoleTransit},
	"zayo.com":                 {"Zayo", RoleTransit},
	"seabone.net":              {"Sparkle", RoleTransit},
	"as6453.net":               {"Tata", RoleTransit},
	"tatacommunications.com":   {"Tata", RoleTransit},
	"pccwglobal.net":           {"PCCW Global", RoleTransit},
	"retn.net":                 {"RETN", RoleTransit},
	"alter.net":                {"Verizon", RoleTransit},
	"sprintlink.net":           {"Sprint", RoleTransit},
	"twelve99.net":             {"Arelion", RoleTransit},
	"core-backbone.com":        {"Core-Backbone", RoleTransit},
	"telstraglobal.net":        {"Telstra", RoleTransit},
	"liberty-global.net":       {"Liberty Global", RoleTransit},
	"globalcrossing.net":       {"Lumen", RoleTransit},
	"savvis.net":               {"Lumen", RoleTransit},
	"vodafone.com":             {"Vodafone", RoleTransit},
	"telefonica-wholesale.net": {"Telefónica", RoleTransit},
}

func knownOrg(name string) (string, HopRole) {
	if o, ok := orgs[registeredDomain(name)]; ok {
		return o.name, o.role
	}
	return "", ""
}

func looksLikeIXP(name string) bool {
	n := strings.ToLower(name)
	if n == "" {
		return false
	}
	for _, s := range []string{"decix", "de-cix", "linx", "ams-ix", "amsix", "equinix", "nyiix", "any2ix", "franceix", "netnod", "ixp.", ".ix.", "-ix."} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// places maps city/airport codes that routers commonly carry in their
// reverse DNS names to readable names.
var places = map[string]string{
	"lon": "London", "lhr": "London", "ams": "Amsterdam", "fra": "Frankfurt", "par": "Paris", "cdg": "Paris",
	"mad": "Madrid", "mil": "Milan", "mxp": "Milan", "sto": "Stockholm", "arn": "Stockholm", "cph": "Copenhagen",
	"osl": "Oslo", "hel": "Helsinki", "waw": "Warsaw", "vie": "Vienna", "zrh": "Zurich", "dub": "Dublin",
	"bru": "Brussels", "prg": "Prague", "mrs": "Marseille", "ber": "Berlin", "muc": "Munich", "ham": "Hamburg",
	"dus": "Düsseldorf", "lis": "Lisbon", "nyc": "New York", "jfk": "New York", "ewr": "Newark", "iad": "Ashburn",
	"ash": "Ashburn", "atl": "Atlanta", "mia": "Miami", "chi": "Chicago", "ord": "Chicago", "dfw": "Dallas",
	"hou": "Houston", "den": "Denver", "lax": "Los Angeles", "sjc": "San Jose", "sfo": "San Francisco",
	"sea": "Seattle", "phx": "Phoenix", "bos": "Boston", "yyz": "Toronto", "tor": "Toronto", "yvr": "Vancouver",
	"ymq": "Montreal", "sin": "Singapore", "hkg": "Hong Kong", "tyo": "Tokyo", "nrt": "Tokyo", "osa": "Osaka",
	"syd": "Sydney", "mel": "Melbourne", "akl": "Auckland", "bom": "Mumbai", "del": "Delhi", "gru": "São Paulo",
	"jnb": "Johannesburg", "dxb": "Dubai", "man": "Manchester", "lds": "Leeds", "bhx": "Birmingham", "edi": "Edinburgh",
}

// guessPlace looks for a city code among the labels of a reverse DNS name,
// e.g. "ae1.lon2.example.net" → London. Digits after the code are ignored.
func guessPlace(name string) string {
	labels := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	// The registered domain carries no location; skip it.
	if len(labels) <= 2 {
		return ""
	}
	labels = labels[:len(labels)-2]
	for _, l := range labels {
		l = strings.TrimRight(l, "0123456789")
		if p, ok := places[l]; ok {
			return p
		}
	}
	return ""
}
