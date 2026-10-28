package interpret

import (
	"testing"

	"github.com/samcjohns/helpnet/internal/fixtures"
	"github.com/samcjohns/helpnet/internal/probe"
	"github.com/samcjohns/helpnet/internal/sysinfo"
)

func named(h probe.TraceHop, name string) probe.TraceHop {
	h.Name = name
	return h
}

func TestMapRouteRoles(t *testing.T) {
	tr := &probe.TraceResult{Tool: "traceroute", Target: "www.google.com", Hops: []probe.TraceHop{
		fixtures.Hop(1, "192.168.1.1", 2, 0),
		fixtures.Hop(2, "10.20.0.1", 9, 0),
		named(fixtures.Hop(3, "198.51.100.1", 11, 0), "ae1.lon2.core.example-isp.co.uk"),
		fixtures.Hop(4, "198.51.100.9", 12, 0), // unnamed, but a later hop is the ISP's
		named(fixtures.Hop(5, "198.51.100.17", 13, 0), "ae3.man1.core.example-isp.co.uk"),
		fixtures.Hop(6, "", 0, 100),
		fixtures.Hop(7, "", 0, 100),
		named(fixtures.Hop(8, "203.0.113.5", 14, 0), "ae-2.r01.fra1.de.bb.gin.ntt.net"),
		fixtures.Hop(9, "203.0.113.9", 14, 0), // unnamed, past the ISP
		named(fixtures.Hop(10, "203.0.113.20", 15, 0), "192.0.2.1.1e100.net"),
		fixtures.Hop(11, "192.0.2.10", 16, 0),
	}}
	local := &sysinfo.Info{Gateway: "192.168.1.1", Type: sysinfo.TypeWiFi}
	rm := MapRoute(tr, local)
	if !rm.Reached {
		t.Fatal("destination should count as reached")
	}
	want := []struct {
		role  HopRole
		org   string
		place string
	}{
		{RoleRouter, "", ""},
		{RoleISP, "example-isp.co.uk", ""}, // privately numbered ISP router
		{RoleISP, "example-isp.co.uk", "London"},
		{RoleISP, "example-isp.co.uk", ""},
		{RoleISP, "example-isp.co.uk", "Manchester"},
		{RoleSilent, "", ""},
		{RoleTransit, "NTT", "Frankfurt"},
		{RoleInternet, "", ""},
		{RoleDestNet, "Google", ""},
		{RoleDest, "Google", ""}, // from the target name
	}
	if len(rm.Hops) != len(want) {
		t.Fatalf("got %d stops, want %d: %+v", len(rm.Hops), len(want), rm.Hops)
	}
	for i, w := range want {
		h := rm.Hops[i]
		if h.Role != w.role || h.Org != w.org || h.Place != w.place {
			t.Errorf("stop %d (ttl %d): got %s/%q/%q, want %s/%q/%q", i, h.TTL, h.Role, h.Org, h.Place, w.role, w.org, w.place)
		}
	}
	if s := rm.Hops[5]; s.TTL != 6 || s.LastTTL != 7 {
		t.Errorf("silent hops should merge into 6–7, got %d–%d", s.TTL, s.LastTTL)
	}
	if d := rm.Hops[1].DeltaMs; d != 7 {
		t.Errorf("hop 2 delta = %v, want 7", d)
	}
}

func TestMapRouteNATAndProblems(t *testing.T) {
	tr := &probe.TraceResult{Tool: "trip", Target: "example.com", Hops: []probe.TraceHop{
		fixtures.Hop(1, "192.168.1.1", 2, 0),
		fixtures.Hop(2, "192.168.0.1", 3, 0),
		fixtures.Hop(3, "100.64.3.1", 10, 0),
		fixtures.Hop(4, "198.51.100.1", 70, 20),
		fixtures.Hop(5, "203.0.113.7", 72, 20),
	}}
	rm := MapRoute(tr, &sysinfo.Info{Gateway: "192.168.1.1"})
	// No reverse DNS anywhere: public hops can't be pinned on the ISP.
	roles := []HopRole{RoleRouter, RoleLocalRouter, RoleCGNAT, RoleInternet, RoleDest}
	for i, r := range roles {
		if rm.Hops[i].Role != r {
			t.Errorf("hop %d role %s, want %s", i+1, rm.Hops[i].Role, r)
		}
	}
	if !rm.Hops[3].Loss || !rm.Hops[3].Jump {
		t.Errorf("hop 4 should mark loss and jump: %+v", rm.Hops[3])
	}
}

func TestMapRouteVPNAndUnreached(t *testing.T) {
	tr := &probe.TraceResult{Target: "example.com", Hops: []probe.TraceHop{
		fixtures.Hop(1, "100.100.0.1", 20, 0),
		fixtures.Hop(2, "198.51.100.1", 25, 0),
		fixtures.Hop(3, "", 0, 100),
	}}
	rm := MapRoute(tr, &sysinfo.Info{VPN: sysinfo.VPNInfo{DefaultRoute: true}})
	if !rm.VPN || rm.Reached || rm.Hops[0].Role != RoleVPN || rm.Hops[2].Role != RoleSilent {
		t.Errorf("unexpected map: %+v", rm)
	}
	if MapRoute(nil, nil).Hops != nil {
		t.Error("nil trace should give an empty map")
	}
}

func TestGuessPlaceAndDomain(t *testing.T) {
	for name, want := range map[string]string{
		"ae1.lon2.example.net":  "London",
		"be3-ams10.example.net": "Amsterdam",
		"core1.example.net":     "",
		"lon.net":               "", // registered domain only
		"":                      "",
	} {
		if got := guessPlace(name); got != want {
			t.Errorf("guessPlace(%q) = %q, want %q", name, got, want)
		}
	}
	if d := registeredDomain("a.b.example.co.uk"); d != "example.co.uk" {
		t.Errorf("registeredDomain = %q", d)
	}
}
