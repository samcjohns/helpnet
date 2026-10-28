//go:build linux

package sysinfo

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/samcjohns/nethelp/internal/probe"
)

func detect(ctx context.Context) (Info, error) {
	var info Info
	data, _ := os.ReadFile("/proc/net/route")
	routes := ParseProcNetRoute(string(data))

	// `ip route get` reflects policy routing (e.g. wg-quick), so it tells us
	// where internet traffic really goes.
	var rg RouteGet
	if probe.LookPath("ip") != "" {
		out, err := probe.RunCommand(ctx, "ip", "route", "get", "1.1.1.1")
		if err == nil {
			rg = ParseIPRouteGet(out)
		}
	}

	// Prefer the physical default route for the "local" view so the gateway we
	// ping is the actual router, not a VPN endpoint.
	for _, r := range routes {
		if !LooksLikeVPN(r.Iface) && !isTun(r.Iface) {
			info.Interface, info.Gateway = r.Iface, r.Gateway
			break
		}
	}
	if info.Interface == "" && len(routes) > 0 {
		info.Interface, info.Gateway = routes[0].Iface, routes[0].Gateway
	}
	if info.Interface == "" && rg.Dev != "" {
		info.Interface, info.Gateway = rg.Dev, rg.Via
	}
	if info.Interface == "" {
		return info, ErrNoRoute
	}
	if rg.Dev != "" && rg.Dev != info.Interface && (LooksLikeVPN(rg.Dev) || isTun(rg.Dev)) {
		info.VPN.DefaultRoute = true
		info.VPN.Interfaces = []string{rg.Dev}
	}
	info.Type = linuxIfaceType(info.Interface)
	if info.Type == TypeWiFi {
		info.WiFi = linuxWiFi(ctx, info.Interface)
	}
	info.DNSServers, info.DNSNote = linuxDNS(ctx)
	info.Proxy.Sources = gnomeProxy(ctx)
	return info, nil
}

func isTun(iface string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", iface, "tun_flags"))
	return err == nil
}

func linuxIfaceType(iface string) string {
	base := filepath.Join("/sys/class/net", iface)
	if exists(filepath.Join(base, "wireless")) || exists(filepath.Join(base, "phy80211")) {
		return TypeWiFi
	}
	if isTun(iface) || LooksLikeVPN(iface) {
		return TypeVPN
	}
	if strings.HasPrefix(iface, "ww") {
		return TypeCellular
	}
	if exists(filepath.Join(base, "device")) {
		return TypeEthernet
	}
	return TypeOther
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func linuxWiFi(ctx context.Context, iface string) *WiFiInfo {
	var w *WiFiInfo
	if probe.LookPath("iw") != "" {
		if out, err := probe.RunCommand(ctx, "iw", "dev", iface, "link"); err == nil {
			w = ParseIwLink(out)
		}
	}
	if w == nil {
		if data, err := os.ReadFile("/proc/net/wireless"); err == nil {
			w = ParseProcNetWireless(string(data), iface)
		}
	}
	if (w == nil || w.LinkRateMbps == 0) && probe.LookPath("nmcli") != "" {
		out, err := probe.RunCommand(ctx, "nmcli", "-t", "-f", "IN-USE,SIGNAL,RATE", "dev", "wifi", "list", "ifname", iface, "--rescan", "no")
		if err == nil {
			if n := ParseNmcliWifi(out); n != nil {
				if w == nil {
					w = n
				} else {
					w.LinkRateMbps = n.LinkRateMbps
				}
			}
		}
	}
	return w
}

func linuxDNS(ctx context.Context) ([]string, string) {
	data, _ := os.ReadFile("/etc/resolv.conf")
	servers := ParseResolvConf(string(data))
	if len(servers) == 1 && strings.HasPrefix(servers[0], "127.0.0.53") && probe.LookPath("resolvectl") != "" {
		if out, err := probe.RunCommand(ctx, "resolvectl", "status"); err == nil {
			if up := ParseResolvectl(out); len(up) > 0 {
				return up, "via systemd-resolved (127.0.0.53)"
			}
		}
		return servers, "systemd-resolved stub"
	}
	return servers, ""
}

func gnomeProxy(ctx context.Context) []string {
	if probe.LookPath("gsettings") == "" || os.Getenv("DISPLAY")+os.Getenv("WAYLAND_DISPLAY") == "" {
		return nil
	}
	out, err := probe.RunCommand(ctx, "gsettings", "get", "org.gnome.system.proxy", "mode")
	if err != nil {
		return nil
	}
	switch strings.Trim(strings.TrimSpace(out), "'") {
	case "manual":
		return []string{"system: GNOME manual proxy"}
	case "auto":
		return []string{"system: auto-config (PAC)"}
	}
	return nil
}
