//go:build windows

package sysinfo

import (
	"context"
	"net"

	"github.com/samcjohns/helpnet/internal/probe"
)

func detect(ctx context.Context) (Info, error) {
	var info Info
	out, err := probe.RunCommand(ctx, "route", "print", "-4")
	if err != nil && out == "" {
		return info, ErrNoRoute
	}
	routes := ParseWindowsRoutePrint(out)

	var defaults []WinRoute
	splitVPN := false
	for _, r := range routes {
		if r.Dest == "0.0.0.0" && r.Mask == "0.0.0.0" {
			defaults = append(defaults, r)
		}
		// OpenVPN and friends override the default with two /1 routes.
		if (r.Dest == "0.0.0.0" || r.Dest == "128.0.0.0") && r.Mask == "128.0.0.0" {
			splitVPN = true
		}
	}
	if len(defaults) == 0 {
		return info, ErrNoRoute
	}
	byMetric := defaults[0]
	for _, r := range defaults[1:] {
		if r.Metric < byMetric.Metric {
			byMetric = r
		}
	}

	// Pick the physical default route (non-VPN adapter) for the local view.
	physical := WinRoute{}
	for _, r := range defaults {
		name := ifaceNameForIP(r.IfaceIP)
		if !LooksLikeVPN(name) && (physical.IfaceIP == "" || r.Metric < physical.Metric) {
			physical = r
		}
	}
	if physical.IfaceIP == "" {
		physical = byMetric
	}
	info.Interface = ifaceNameForIP(physical.IfaceIP)
	info.Gateway = physical.Gateway
	if info.Interface == "" {
		info.Interface = physical.IfaceIP
	}
	if vpnName := ifaceNameForIP(byMetric.IfaceIP); LooksLikeVPN(vpnName) || splitVPN {
		info.VPN.DefaultRoute = true
		if LooksLikeVPN(vpnName) {
			info.VPN.Interfaces = []string{vpnName}
		}
	}

	info.Type = PortType(info.Interface)
	if info.Type == TypeOther {
		info.Type = TypeEthernet
	}
	if info.Type == TypeWiFi {
		if out, err := probe.RunCommand(ctx, "netsh", "wlan", "show", "interfaces"); err == nil {
			info.WiFi = ParseNetshWlan(out)
		}
	}
	if out, err := probe.RunCommand(ctx, "netsh", "interface", "ipv4", "show", "dnsservers", "name="+info.Interface); err == nil {
		info.DNSServers = ParseIPsInText(out)
	}
	if out, err := probe.RunCommand(ctx, "reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`); err == nil {
		info.Proxy.Sources = ParseWindowsProxyReg(out)
	}
	return info, nil
}

func ifaceNameForIP(ip string) string {
	target := net.ParseIP(ip)
	ifcs, _ := net.Interfaces()
	for _, ifc := range ifcs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(target) {
				return ifc.Name
			}
		}
	}
	return ""
}
