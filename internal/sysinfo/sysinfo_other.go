//go:build !linux && !darwin && !windows

package sysinfo

import (
	"context"
	"os"

	"github.com/helpnet/helpnet/internal/probe"
)

// BSDs: `route -n get default` has the same format as macOS.
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
	info.Type = PortType(info.Interface)
	data, _ := os.ReadFile("/etc/resolv.conf")
	info.DNSServers = ParseResolvConf(string(data))
	return info, nil
}
