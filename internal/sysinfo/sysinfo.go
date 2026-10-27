// Package sysinfo detects the local network setup: active interface, its
// type, addresses, default gateway, DNS servers, VPNs, proxies and Wi-Fi
// signal. Per-OS code lives in sysinfo_<os>.go; text parsers live in parse.go
// so they can be unit-tested on any platform.
package sysinfo

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Interface types.
const (
	TypeWiFi     = "Wi-Fi"
	TypeEthernet = "Ethernet"
	TypeCellular = "Cellular"
	TypeVPN      = "VPN"
	TypeOther    = "Other"
)

// ErrNoRoute means there is no default route: the machine is offline.
var ErrNoRoute = errors.New("no default route (not connected to a network)")

type Info struct {
	Interface  string    `json:"interface"`
	Type       string    `json:"type"`
	IPv4       []string  `json:"ipv4,omitempty"`
	IPv6       []string  `json:"ipv6,omitempty"`
	Gateway    string    `json:"gateway,omitempty"`
	DNSServers []string  `json:"dns_servers,omitempty"`
	DNSNote    string    `json:"dns_note,omitempty"`
	VPN        VPNInfo   `json:"vpn"`
	Proxy      ProxyInfo `json:"proxy"`
	WiFi       *WiFiInfo `json:"wifi,omitempty"`
	Notes      []string  `json:"notes,omitempty"`
}

// HasGlobalIPv6 reports whether the interface has a routable IPv6 address.
func (i Info) HasGlobalIPv6() bool {
	for _, a := range i.IPv6 {
		ip := net.ParseIP(a)
		if ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

type VPNInfo struct {
	Active       bool     `json:"active"`
	Interfaces   []string `json:"interfaces,omitempty"`
	DefaultRoute bool     `json:"default_route"` // internet traffic goes through the VPN
}

type ProxyInfo struct {
	Detected bool     `json:"detected"`
	Sources  []string `json:"sources,omitempty"` // e.g. "HTTPS_PROXY=http://proxy:3128", "system: auto-config (PAC)"
}

type WiFiInfo struct {
	SignalDBm    int     `json:"signal_dbm,omitempty"`
	SignalPct    int     `json:"signal_pct,omitempty"`
	LinkRateMbps float64 `json:"link_rate_mbps,omitempty"`
	Source       string  `json:"source"`
}

// Quality returns signal quality as a percentage, converting from dBm when
// that is all we have (-50 dBm or better ≈ 100%, -100 dBm ≈ 0%).
func (w WiFiInfo) Quality() int {
	if w.SignalPct > 0 {
		return w.SignalPct
	}
	if w.SignalDBm == 0 {
		return 0
	}
	q := 2 * (w.SignalDBm + 100)
	return max(0, min(100, q))
}

// Detect gathers everything it can. Only the absence of a default route is an
// error; optional facts (Wi-Fi, proxy, DNS) are left empty when unavailable.
func Detect(ctx context.Context) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	info, err := detect(ctx)
	if err != nil {
		return info, err
	}
	fillAddrs(&info)
	info.Proxy.Sources = append(envProxies(), info.Proxy.Sources...)
	info.Proxy.Detected = len(info.Proxy.Sources) > 0
	if len(info.VPN.Interfaces) == 0 {
		info.VPN.Interfaces = vpnInterfaces(info.Interface)
	}
	info.VPN.Active = info.VPN.Active || len(info.VPN.Interfaces) > 0 || info.VPN.DefaultRoute
	return info, nil
}

func fillAddrs(info *Info) {
	ifc, err := net.InterfaceByName(info.Interface)
	if err != nil {
		return
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipn.IP.To4() != nil {
			info.IPv4 = append(info.IPv4, ipn.IP.String())
		} else {
			info.IPv6 = append(info.IPv6, ipn.IP.String())
		}
	}
}

var vpnPrefixes = []string{"tun", "tap", "wg", "utun", "ppp", "ipsec", "tailscale", "zt", "nordlynx", "proton", "cloudflarewarp", "gpd", "vpn"}

// LooksLikeVPN guesses from an interface name/description whether it is a
// VPN or tunnel adapter.
func LooksLikeVPN(name string) bool {
	l := strings.ToLower(name)
	for _, p := range vpnPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	for _, s := range []string{"wireguard", "openvpn", "tap-windows", "wintun", "vpn", "anyconnect", "fortinet", "globalprotect"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// vpnInterfaces lists up VPN-like interfaces that carry an IPv4 address.
// (macOS always has a few idle utun interfaces with only link-local IPv6.)
func vpnInterfaces(primary string) []string {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifcs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Name == primary || !LooksLikeVPN(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				out = append(out, ifc.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func envProxies() []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		v := os.Getenv(k)
		if v == "" || seen[strings.ToUpper(k)] {
			continue
		}
		seen[strings.ToUpper(k)] = true
		out = append(out, strings.ToUpper(k)+"="+RedactProxy(v))
	}
	return out
}

// RedactProxy strips credentials from a proxy URL so they never reach a report.
func RedactProxy(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.User == nil {
		return v
	}
	u.User = url.User("***")
	return u.String()
}
