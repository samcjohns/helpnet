// Package checks implements the layered diagnostic workflow. Each check is
// UI-agnostic: it reports progress and a typed result through Events, which
// the TUI, the plain-text renderer and JSON mode all consume.
package checks

import (
	"github.com/samcjohns/helpnet/internal/probe"
	"github.com/samcjohns/helpnet/internal/sysinfo"
)

// ID names a check. Checks run in Order, nearest to farthest.
type ID string

const (
	Local    ID = "local"
	Gateway  ID = "gateway"
	Internet ID = "internet"
	DNS      ID = "dns"
	HTTP     ID = "http"
	Trace    ID = "trace"
	Speed    ID = "speed"
	// Tailscale is optional and only planned when its CLI is installed
	// (see WithInstalled). It comes last so the spec's layer numbers stay.
	Tailscale ID = "tailscale"
)

var Order = []ID{Local, Gateway, Internet, DNS, HTTP, Trace, Speed, Tailscale}

// Layer returns the layer number (0 = local … 6 = bandwidth, 7 = Tailscale).
func (id ID) Layer() int {
	for i, v := range Order {
		if v == id {
			return i
		}
	}
	return len(Order)
}

func (id ID) Title() string {
	switch id {
	case Local:
		return "Local interface"
	case Gateway:
		return "Gateway"
	case Internet:
		return "Internet"
	case DNS:
		return "DNS"
	case HTTP:
		return "HTTP timing"
	case Trace:
		return "Route trace"
	case Speed:
		return "Bandwidth"
	case Tailscale:
		return "Tailscale"
	}
	return string(id)
}

// Outcome is how a check ended, independent of whether its numbers are good.
type Outcome string

const (
	OutcomeOK      Outcome = "ok"
	OutcomeError   Outcome = "error"   // the check could not measure anything useful
	OutcomeSkipped Outcome = "skipped" // not run (dependency failed, tool missing, not requested)
)

// State records how a check ran.
type State struct {
	Outcome    Outcome  `json:"outcome"`
	Error      string   `json:"error,omitempty"`
	SkipReason string   `json:"skip_reason,omitempty"`
	Hint       string   `json:"hint,omitempty"`
	DurationMs float64  `json:"duration_ms"`
	Notes      []string `json:"notes,omitempty"`
}

type GatewayResult struct {
	Address     string            `json:"address"`
	Ping        probe.PingResult  `json:"ping"`
	TCP         []probe.TCPResult `json:"tcp_fallback,omitempty"`
	ICMPBlocked bool              `json:"icmp_blocked"` // no ping replies but TCP proved it is up
	Reachable   bool              `json:"reachable"`
}

type InternetResult struct {
	Pings       []probe.PingResult   `json:"pings"`
	TCP         []probe.TCPResult    `json:"tcp"`
	Captive     *probe.CaptiveResult `json:"captive_portal,omitempty"`
	ICMPBlocked bool                 `json:"icmp_blocked"`
	Reachable   bool                 `json:"reachable"`
}

// BestPing returns the ping with the lowest average among hosts that replied.
func (r *InternetResult) BestPing() *probe.PingResult {
	var best *probe.PingResult
	for i := range r.Pings {
		p := &r.Pings[i]
		if p.Stats.Received == 0 {
			continue
		}
		if best == nil || p.Stats.AvgMs < best.Stats.AvgMs {
			best = p
		}
	}
	return best
}

// BestTCP returns the TCP probe with the lowest average connect time.
func (r *InternetResult) BestTCP() *probe.TCPResult {
	var best *probe.TCPResult
	for i := range r.TCP {
		t := &r.TCP[i]
		if t.Connected == 0 {
			continue
		}
		if best == nil || t.Stats.AvgMs < best.Stats.AvgMs {
			best = t
		}
	}
	return best
}

// ResolverStats aggregates the queries sent to one resolver.
type ResolverStats struct {
	Name      string           `json:"name"`
	Server    string           `json:"server"`
	System    bool             `json:"system"`
	Queries   []probe.DNSQuery `json:"queries"`
	Answered  int              `json:"answered"`
	AvgMs     float64          `json:"avg_ms"`
	MinMs     float64          `json:"min_ms"`
	MaxMs     float64          `json:"max_ms"`
	P95Ms     float64          `json:"p95_ms"`
	ColdAvgMs float64          `json:"cold_avg_ms"` // first lookup per domain (likely uncached)
	WarmAvgMs float64          `json:"warm_avg_ms"` // repeat lookups
	Failures  int              `json:"failures"`    // timeouts, errors, SERVFAIL
	NXDomain  int              `json:"nxdomain"`
	ServFail  int              `json:"servfail"`
	Timeouts  int              `json:"timeouts"`
	AAAA      int              `json:"aaaa_answers"` // AAAA queries that returned addresses
}

// Unreachable reports whether the resolver never answered.
func (s ResolverStats) Unreachable() bool { return s.Answered == 0 && len(s.Queries) > 0 }

type DNSResult struct {
	Domains   []string        `json:"domains"`
	Resolvers []ResolverStats `json:"resolvers"`
	// Differences lists answers that disagree in a way a CDN would not
	// explain: NXDOMAIN vs real answers, or private/blocked addresses.
	Differences []string `json:"differences,omitempty"`
	// CDNDiffers counts domains whose answers differ only in public IPs.
	CDNDiffers int `json:"cdn_differs"`
}

// System returns the system resolver's stats, if measured.
func (r *DNSResult) System() *ResolverStats {
	for i := range r.Resolvers {
		if r.Resolvers[i].System {
			return &r.Resolvers[i]
		}
	}
	return nil
}

// BestPublic returns the fastest public resolver that answered.
func (r *DNSResult) BestPublic() *ResolverStats {
	var best *ResolverStats
	for i := range r.Resolvers {
		s := &r.Resolvers[i]
		if s.System || s.Answered == 0 {
			continue
		}
		if best == nil || s.AvgMs < best.AvgMs {
			best = s
		}
	}
	return best
}

type HTTPResult struct {
	Target     string             `json:"target"`
	Host       string             `json:"host"`
	Samples    []probe.HTTPSample `json:"samples"`
	OK         int                `json:"ok"`
	DNSMs      float64            `json:"dns_ms"`
	ConnectMs  float64            `json:"connect_ms"`
	TLSMs      float64            `json:"tls_ms"`
	TTFBMs     float64            `json:"ttfb_ms"`
	TransferMs float64            `json:"transfer_ms"`
	TotalMs    float64            `json:"total_ms"`
	Status     int                `json:"status,omitempty"`
	FinalURL   string             `json:"final_url,omitempty"`
	Redirects  int                `json:"redirects"`
	Proto      string             `json:"proto,omitempty"`
	TLSVersion string             `json:"tls_version,omitempty"`
	RemoteAddr string             `json:"remote_addr,omitempty"`
	ViaProxy   bool               `json:"via_proxy"`
	HasIPv4    bool               `json:"has_ipv4"`
	HasIPv6    bool               `json:"has_ipv6"`
	IPv4       *probe.HTTPSample  `json:"ipv4,omitempty"`
	IPv6       *probe.HTTPSample  `json:"ipv6,omitempty"`
	FamilyNote string             `json:"family_note,omitempty"`
}

// Results is everything measured in a run. Each field is nil until its
// check finishes; finished results are never mutated, so they can be shared.
type Results struct {
	Local     *sysinfo.Info          `json:"local,omitempty"`
	Gateway   *GatewayResult         `json:"gateway,omitempty"`
	Internet  *InternetResult        `json:"internet,omitempty"`
	DNS       *DNSResult             `json:"dns,omitempty"`
	HTTP      *HTTPResult            `json:"http,omitempty"`
	Trace     *probe.TraceResult     `json:"trace,omitempty"`
	Speed     *probe.SpeedResult     `json:"speed,omitempty"`
	Tailscale *probe.TailscaleResult `json:"tailscale,omitempty"`
	States    map[ID]State           `json:"states"`
}

func NewResults() *Results { return &Results{States: map[ID]State{}} }

// Clone returns a shallow copy safe to hand to another goroutine: the typed
// results are immutable, only the States map needs copying.
func (r *Results) Clone() *Results {
	c := *r
	c.States = make(map[ID]State, len(r.States))
	for k, v := range r.States {
		c.States[k] = v
	}
	return &c
}

// Ran reports whether id completed with a usable result.
func (r *Results) Ran(id ID) bool { return r.States[id].Outcome == OutcomeOK }

// set stores a typed result for id.
func (r *Results) set(id ID, v any) {
	switch id {
	case Local:
		r.Local, _ = v.(*sysinfo.Info)
	case Gateway:
		r.Gateway, _ = v.(*GatewayResult)
	case Internet:
		r.Internet, _ = v.(*InternetResult)
	case DNS:
		r.DNS, _ = v.(*DNSResult)
	case HTTP:
		r.HTTP, _ = v.(*HTTPResult)
	case Trace:
		r.Trace, _ = v.(*probe.TraceResult)
	case Speed:
		r.Speed, _ = v.(*probe.SpeedResult)
	case Tailscale:
		r.Tailscale, _ = v.(*probe.TailscaleResult)
	}
}

// clear forgets any previous result for id before it is re-run.
func (r *Results) clear(id ID) { r.set(id, nil) }

// Apply records a Finished/Skipped event into r. Frontends that keep their
// own Results call this for every event they receive.
func (r *Results) Apply(ev Event) {
	switch ev.Type {
	case EventStarted:
		r.clear(ev.ID)
		delete(r.States, ev.ID)
	case EventFinished:
		r.set(ev.ID, ev.Result)
		r.States[ev.ID] = ev.State
	}
}

// EventType distinguishes check lifecycle events.
type EventType int

const (
	EventStarted EventType = iota
	EventProgress
	EventFinished // includes skipped checks (State.Outcome == OutcomeSkipped)
)

// Event is emitted by the runner. Result is a pointer to the check's typed
// result (nil if skipped or failed).
type Event struct {
	Type   EventType
	ID     ID
	Text   string // progress text, one line
	State  State
	Result any
}
