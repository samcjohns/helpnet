package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// TailscaleResult is Tailscale's own view of this device and network, from
// `tailscale status --json` and `tailscale netcheck --format=json`. It keeps
// counts and capabilities only: no peer names, tailnet name or public IPs.
type TailscaleResult struct {
	Status   TailscaleStatus    `json:"status"`
	Netcheck *TailscaleNetcheck `json:"netcheck,omitempty"` // nil if netcheck failed
}

// TailscaleStatus summarises `tailscale status --json`.
type TailscaleStatus struct {
	BackendState string   `json:"backend_state"` // Running, Stopped, NeedsLogin, …
	Version      string   `json:"version,omitempty"`
	HomeRelay    string   `json:"home_relay,omitempty"` // this device's home DERP region code
	MagicDNS     bool     `json:"magic_dns"`
	ExitNode     bool     `json:"exit_node"` // traffic goes through an exit node
	Health       []string `json:"health,omitempty"`
	Peers        int      `json:"peers"`
	Online       int      `json:"online"`
	// Active peers have exchanged traffic recently; only they have a
	// connection path to judge.
	Active      int `json:"active"`
	Direct      int `json:"direct"`       // active peers connected directly
	Relayed     int `json:"relayed"`      // active peers relayed through DERP
	PeerRelayed int `json:"peer_relayed"` // active peers relayed through a Tailscale peer relay
	// RelayRegions are the DERP regions carrying relayed active peers.
	RelayRegions []string `json:"relay_regions,omitempty"`
}

// Running reports whether tailscaled is logged in and connected.
func (s TailscaleStatus) Running() bool { return s.BackendState == "Running" }

// TailscaleNetcheck summarises `tailscale netcheck`. Optional facts are nil
// when netcheck could not determine them.
type TailscaleNetcheck struct {
	UDP  bool `json:"udp"`
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`
	// HardNAT means the NAT maps each destination to a different public
	// port (MappingVariesByDestIP), which defeats hole punching.
	HardNAT       *bool   `json:"hard_nat,omitempty"`
	HairPinning   *bool   `json:"hairpinning,omitempty"`
	UPnP          *bool   `json:"upnp,omitempty"`
	PMP           *bool   `json:"nat_pmp,omitempty"`
	PCP           *bool   `json:"pcp,omitempty"`
	CaptivePortal *bool   `json:"captive_portal,omitempty"`
	PreferredDERP int     `json:"preferred_derp,omitempty"`  // region ID
	DERPLatencyMs float64 `json:"derp_latency_ms,omitempty"` // to the preferred region
}

// PortMapping lists the port-mapping protocols the router offers.
func (n TailscaleNetcheck) PortMapping() []string {
	var out []string
	for _, p := range []struct {
		name string
		v    *bool
	}{{"UPnP", n.UPnP}, {"NAT-PMP", n.PMP}, {"PCP", n.PCP}} {
		if p.v != nil && *p.v {
			out = append(out, p.name)
		}
	}
	return out
}

// TailscaleInstalled reports whether the tailscale CLI is on PATH.
func TailscaleInstalled() bool { return LookPath("tailscale") != "" }

// ErrTailscaleNotRunning means the CLI is installed but tailscaled is not
// running, so there is nothing to ask.
var ErrTailscaleNotRunning = errors.New("tailscaled is not running")

// TailscaleStatusOf runs `tailscale status --json`.
func TailscaleStatusOf(ctx context.Context) (TailscaleStatus, error) {
	out, errOut, err := RunCommandStdout(ctx, "tailscale", "status", "--json")
	if ctx.Err() != nil {
		return TailscaleStatus{}, ctx.Err()
	}
	if err != nil && !strings.Contains(out, "{") {
		msg := strings.TrimSpace(errOut + out)
		if strings.Contains(msg, "tailscaled") || strings.Contains(msg, "not running") || strings.Contains(msg, "Is Tailscale running") {
			return TailscaleStatus{}, ErrTailscaleNotRunning
		}
		return TailscaleStatus{}, fmt.Errorf("tailscale status: %s", firstLineOf(msg, err))
	}
	return ParseTailscaleStatus([]byte(out))
}

// TailscaleNetcheckOf runs `tailscale netcheck --format=json`. Portmapper
// logs go to stderr and are ignored.
func TailscaleNetcheckOf(ctx context.Context) (TailscaleNetcheck, error) {
	out, errOut, err := RunCommandStdout(ctx, "tailscale", "netcheck", "--format=json")
	if ctx.Err() != nil {
		return TailscaleNetcheck{}, ctx.Err()
	}
	if err != nil && !strings.Contains(out, "{") {
		return TailscaleNetcheck{}, fmt.Errorf("tailscale netcheck: %s", firstLineOf(strings.TrimSpace(errOut+out), err))
	}
	return ParseTailscaleNetcheck([]byte(out))
}

func firstLineOf(msg string, err error) string {
	if msg == "" {
		return err.Error()
	}
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		return msg[:i]
	}
	return msg
}

// jsonObject strips anything before the first '{' (netcheck prints a
// "# Warning: … not yet considered a stable interface" line first).
func jsonObject(b []byte) ([]byte, error) {
	i := bytes.IndexByte(b, '{')
	if i < 0 {
		return nil, errors.New("no JSON object in output")
	}
	return b[i:], nil
}

// ParseTailscaleStatus reduces `tailscale status --json` to counts.
func ParseTailscaleStatus(b []byte) (TailscaleStatus, error) {
	b, err := jsonObject(b)
	if err != nil {
		return TailscaleStatus{}, fmt.Errorf("tailscale status: %w", err)
	}
	var raw struct {
		BackendState   string
		Version        string
		Health         []string
		ExitNodeStatus json.RawMessage
		CurrentTailnet *struct{ MagicDNSEnabled bool }
		Self           *struct{ Relay string }
		Peer           map[string]struct {
			Online, Active, ExitNode bool
			CurAddr, Relay           string
			PeerRelay                string
		}
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return TailscaleStatus{}, fmt.Errorf("tailscale status: %w", err)
	}
	s := TailscaleStatus{
		BackendState: raw.BackendState,
		Version:      shortVersion(raw.Version),
		Health:       raw.Health,
		Peers:        len(raw.Peer),
		ExitNode:     len(raw.ExitNodeStatus) > 0 && string(raw.ExitNodeStatus) != "null",
	}
	if raw.CurrentTailnet != nil {
		s.MagicDNS = raw.CurrentTailnet.MagicDNSEnabled
	}
	if raw.Self != nil {
		s.HomeRelay = raw.Self.Relay
	}
	regions := map[string]bool{}
	for _, p := range raw.Peer {
		if p.ExitNode {
			s.ExitNode = true
		}
		if p.Online {
			s.Online++
		}
		if !p.Active {
			continue
		}
		s.Active++
		switch {
		case p.CurAddr != "":
			s.Direct++
		case p.PeerRelay != "":
			s.PeerRelayed++
		default:
			s.Relayed++
			if p.Relay != "" {
				regions[p.Relay] = true
			}
		}
	}
	for r := range regions {
		s.RelayRegions = append(s.RelayRegions, r)
	}
	sort.Strings(s.RelayRegions)
	return s, nil
}

// shortVersion turns "1.102.2-t6cac91817-g6ff0ddc72" into "1.102.2".
func shortVersion(v string) string {
	if i := strings.IndexByte(v, '-'); i > 0 {
		return v[:i]
	}
	return v
}

// ParseTailscaleNetcheck reads `tailscale netcheck --format=json`. Tailscale
// marks that format unstable, so unknown or missing fields are tolerated and
// optional booleans may be JSON booleans, "true"/"false" strings or null.
func ParseTailscaleNetcheck(b []byte) (TailscaleNetcheck, error) {
	b, err := jsonObject(b)
	if err != nil {
		return TailscaleNetcheck{}, fmt.Errorf("tailscale netcheck: %w", err)
	}
	var raw struct {
		UDP, IPv4, IPv6       bool
		MappingVariesByDestIP json.RawMessage
		HairPinning           json.RawMessage
		UPnP, PMP, PCP        json.RawMessage
		CaptivePortal         json.RawMessage
		PreferredDERP         int
		RegionLatency         map[string]float64 // nanoseconds, keyed by region ID
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return TailscaleNetcheck{}, fmt.Errorf("tailscale netcheck: %w", err)
	}
	n := TailscaleNetcheck{
		UDP: raw.UDP, IPv4: raw.IPv4, IPv6: raw.IPv6,
		HardNAT:       optBool(raw.MappingVariesByDestIP),
		HairPinning:   optBool(raw.HairPinning),
		UPnP:          optBool(raw.UPnP),
		PMP:           optBool(raw.PMP),
		PCP:           optBool(raw.PCP),
		CaptivePortal: optBool(raw.CaptivePortal),
		PreferredDERP: raw.PreferredDERP,
	}
	if ns, ok := raw.RegionLatency[strconv.Itoa(raw.PreferredDERP)]; ok && raw.PreferredDERP != 0 {
		n.DERPLatencyMs = ns / 1e6
	}
	return n, nil
}

// optBool decodes Tailscale's opt.Bool: true, false, "true", "false" or
// null/"" for unknown.
func optBool(m json.RawMessage) *bool {
	var v any
	if len(m) == 0 || json.Unmarshal(m, &v) != nil {
		return nil
	}
	var b bool
	switch x := v.(type) {
	case bool:
		b = x
	case string:
		parsed, err := strconv.ParseBool(x)
		if err != nil {
			return nil
		}
		b = parsed
	default:
		return nil
	}
	return &b
}
