//go:build darwin

package sysinfo

import (
	"context"
	"os"
	"time"

	"github.com/samcjohns/helpnet/internal/probe"
)

func detect(ctx context.Context) (Info, error) {
	var info Info
	out, err := probe.RunCommand(ctx, "route", "-n", "get", "default")
	if err != nil {
		return info, ErrNoRoute
	}
	kv := ParseKeyValues(out)
	info.Interface, info.Gateway = kv["interface"], kv["gateway"]
	if info.Interface == "" {
		return info, ErrNoRoute
	}

	// A VPN that takes the default route typically installs more-specific
	// routes, so ask where 1.1.1.1 actually goes.
	if out, err := probe.RunCommand(ctx, "route", "-n", "get", "1.1.1.1"); err == nil {
		dev := ParseKeyValues(out)["interface"]
		if dev != "" && LooksLikeVPN(dev) {
			info.VPN.DefaultRoute = true
			info.VPN.Interfaces = []string{dev}
		}
	}
	// If the default route itself is a utun, find the physical service order.
	if LooksLikeVPN(info.Interface) {
		info.VPN.DefaultRoute = true
		info.VPN.Interfaces = []string{info.Interface}
		info.Notes = append(info.Notes, "default route points at a VPN tunnel")
	}

	info.Type = TypeOther
	if out, err := probe.RunCommand(ctx, "networksetup", "-listallhardwareports"); err == nil {
		if port, ok := ParseHardwarePorts(out)[info.Interface]; ok {
			info.Type = PortType(port)
		}
	}
	if LooksLikeVPN(info.Interface) {
		info.Type = TypeVPN
	}
	if info.Type == TypeWiFi {
		wctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		if out, err := probe.RunCommand(wctx, "system_profiler", "SPAirPortDataType"); err == nil {
			info.WiFi = ParseSystemProfilerAirport(out)
		}
		cancel()
	}

	if out, err := probe.RunCommand(ctx, "scutil", "--dns"); err == nil {
		info.DNSServers = ParseScutilDNS(out)
	}
	if len(info.DNSServers) == 0 {
		data, _ := os.ReadFile("/etc/resolv.conf")
		info.DNSServers = ParseResolvConf(string(data))
	}
	if out, err := probe.RunCommand(ctx, "scutil", "--proxy"); err == nil {
		info.Proxy.Sources = ParseScutilProxy(out)
	}
	return info, nil
}
