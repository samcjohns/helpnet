package probe

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestParseTailscaleStatus(t *testing.T) {
	s, err := ParseTailscaleStatus([]byte(readFixture(t, "tailscale_status.json")))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Running() || s.Version != "1.102.2" || s.HomeRelay != "nyc" || !s.MagicDNS || s.ExitNode {
		t.Errorf("status %+v", s)
	}
	if s.Peers != 5 || s.Online != 4 || s.Active != 3 || s.Direct != 1 || s.Relayed != 1 || s.PeerRelayed != 1 {
		t.Errorf("peer counts %+v", s)
	}
	if !slices.Equal(s.RelayRegions, []string{"iad"}) {
		t.Errorf("relay regions %v", s.RelayRegions)
	}
	if len(s.Health) != 1 {
		t.Errorf("health %v", s.Health)
	}
	// Nothing identifying survives into the result.
	b, _ := json.Marshal(s)
	for _, leak := range []string{"laptop", "fileserver9", "example", "192.0.2.10", "100.100.1"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("result contains %q: %s", leak, b)
		}
	}
}

func TestParseTailscaleStatusStopped(t *testing.T) {
	s, err := ParseTailscaleStatus([]byte(readFixture(t, "tailscale_status_stopped.json")))
	if err != nil {
		t.Fatal(err)
	}
	if s.Running() || s.BackendState != "Stopped" || s.Peers != 0 {
		t.Errorf("status %+v", s)
	}
}

func TestParseTailscaleNetcheck(t *testing.T) {
	n, err := ParseTailscaleNetcheck([]byte(readFixture(t, "tailscale_netcheck.json")))
	if err != nil {
		t.Fatal(err)
	}
	if !n.UDP || !n.IPv4 || !n.IPv6 || n.HardNAT == nil || *n.HardNAT || n.CaptivePortal != nil {
		t.Errorf("netcheck %+v", n)
	}
	if n.PreferredDERP != 1 || !approx(n.DERPLatencyMs, 43.83) {
		t.Errorf("DERP %d %.2f ms", n.PreferredDERP, n.DERPLatencyMs)
	}
	if !slices.Equal(n.PortMapping(), []string{"UPnP"}) {
		t.Errorf("port mapping %v", n.PortMapping())
	}
	b, _ := json.Marshal(n)
	if strings.Contains(string(b), "203.0.113") || strings.Contains(string(b), "2001:db8") {
		t.Errorf("public addresses leaked: %s", b)
	}
}

func TestParseTailscaleNetcheckLenient(t *testing.T) {
	n, err := ParseTailscaleNetcheck([]byte(readFixture(t, "tailscale_netcheck_hard.json")))
	if err != nil {
		t.Fatal(err)
	}
	if n.HardNAT == nil || !*n.HardNAT {
		t.Errorf("string \"true\" should parse as hard NAT: %+v", n.HardNAT)
	}
	if n.UPnP != nil || n.PMP != nil || n.PCP == nil || *n.PCP {
		t.Errorf("null and \"\" are unknown, false is false: upnp=%v pmp=%v pcp=%v", n.UPnP, n.PMP, n.PCP)
	}
	if !approx(n.DERPLatencyMs, 18.5) || n.IPv6 {
		t.Errorf("netcheck %+v", n)
	}
	if _, err := ParseTailscaleNetcheck([]byte("portmap: no gateway")); err == nil {
		t.Error("output without JSON should be an error")
	}
}

func TestAddressClasses(t *testing.T) {
	tests := []struct {
		addr                   string
		cgnat, private, public bool
	}{
		{"100.64.0.1", true, false, false},
		{"100.127.255.254", true, false, false},
		{"100.128.0.1", false, false, true},
		{"10.1.2.3", false, true, false},
		{"192.168.1.1", false, true, false},
		{"203.0.113.9", false, false, true},
		{"2001:db8::1", false, false, true},
		{"fe80::1", false, false, false},
		{"not an ip", false, false, false},
	}
	for _, tt := range tests {
		if got := IsCGNAT(tt.addr); got != tt.cgnat {
			t.Errorf("IsCGNAT(%s) = %v", tt.addr, got)
		}
		if got := IsPrivateAddr(tt.addr); got != tt.private {
			t.Errorf("IsPrivateAddr(%s) = %v", tt.addr, got)
		}
		if got := IsPublicAddr(tt.addr); got != tt.public {
			t.Errorf("IsPublicAddr(%s) = %v", tt.addr, got)
		}
	}
}
