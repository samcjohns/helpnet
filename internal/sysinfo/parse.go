package sysinfo

import (
	"bufio"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// RouteGet is the parsed output of `ip route get` on Linux.
type RouteGet struct {
	Via, Dev, Src string
}

// ParseIPRouteGet parses e.g. "1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.42 uid 1000".
func ParseIPRouteGet(out string) RouteGet {
	var r RouteGet
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			r.Via = f[i+1]
		case "dev":
			r.Dev = f[i+1]
		case "src":
			r.Src = f[i+1]
		}
	}
	return r
}

// DefaultRoute is one default-route entry.
type DefaultRoute struct {
	Iface, Gateway string
	Metric         int
}

// ParseProcNetRoute parses /proc/net/route and returns default routes sorted
// by metric (lowest first).
func ParseProcNetRoute(data string) []DefaultRoute {
	var routes []DefaultRoute
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[0] == "Iface" || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		gw := hexToIPv4(f[2])
		metric, _ := strconv.Atoi(f[6])
		routes = append(routes, DefaultRoute{Iface: f[0], Gateway: gw, Metric: metric})
	}
	sortRoutes(routes)
	return routes
}

func sortRoutes(r []DefaultRoute) {
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j].Metric < r[j-1].Metric; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
}

// hexToIPv4 converts the little-endian hex address used by /proc/net/route.
func hexToIPv4(h string) string {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil || v == 0 {
		return ""
	}
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
}

// ParseResolvConf returns the nameserver entries in resolv.conf.
func ParseResolvConf(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// ParseResolvectl extracts upstream servers from `resolvectl status`,
// preferring "Current DNS Server".
func ParseResolvectl(out string) []string {
	var current, all []string
	inList := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		// "Key: value" lines use ": " — IPv6 addresses only contain bare colons.
		key, val, isKey := strings.Cut(t, ": ")
		switch {
		case isKey && key == "Current DNS Server":
			current = appendIPs(current, val)
			inList = false
		case isKey && key == "DNS Servers":
			all = appendIPs(all, val)
			inList = true
		case !isKey && inList && t != "":
			all = appendIPs(all, t) // continuation line of the DNS Servers list
		default:
			inList = false
		}
	}
	if len(current) > 0 {
		return current
	}
	return all
}

func appendIPs(list []string, s string) []string {
	for _, f := range strings.Fields(s) {
		f = strings.SplitN(f, "#", 2)[0] // "1.1.1.1#cloudflare-dns.com"
		if net.ParseIP(f) != nil {
			list = appendUnique(list, f)
		}
	}
	return list
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

var procWirelessRe = regexp.MustCompile(`^\s*(\S+):\s+\S+\s+([-\d.]+)\.?\s+([-\d.]+)\.?`)

// ParseProcNetWireless reads link quality and signal level (dBm) for iface
// from /proc/net/wireless.
func ParseProcNetWireless(data, iface string) *WiFiInfo {
	for _, line := range strings.Split(data, "\n") {
		m := procWirelessRe.FindStringSubmatch(line)
		if m == nil || m[1] != iface {
			continue
		}
		level, err := strconv.ParseFloat(strings.TrimSuffix(m[3], "."), 64)
		if err != nil || level >= 0 {
			return nil
		}
		return &WiFiInfo{SignalDBm: int(level), Source: "/proc/net/wireless"}
	}
	return nil
}

var (
	iwSignalRe = regexp.MustCompile(`signal:\s*(-?\d+)\s*dBm`)
	iwRateRe   = regexp.MustCompile(`tx bitrate:\s*([\d.]+)\s*MBit/s`)
)

// ParseIwLink parses `iw dev <if> link`.
func ParseIwLink(out string) *WiFiInfo {
	if strings.Contains(out, "Not connected") {
		return nil
	}
	w := &WiFiInfo{Source: "iw"}
	if m := iwSignalRe.FindStringSubmatch(out); m != nil {
		w.SignalDBm, _ = strconv.Atoi(m[1])
	}
	if m := iwRateRe.FindStringSubmatch(out); m != nil {
		w.LinkRateMbps, _ = strconv.ParseFloat(m[1], 64)
	}
	if w.SignalDBm == 0 && w.LinkRateMbps == 0 {
		return nil
	}
	return w
}

// ParseNmcliWifi parses `nmcli -t -f IN-USE,SIGNAL,RATE dev wifi list`,
// e.g. "*:72:270 Mbit/s".
func ParseNmcliWifi(out string) *WiFiInfo {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 || strings.TrimSpace(f[0]) != "*" {
			continue
		}
		w := &WiFiInfo{Source: "nmcli"}
		w.SignalPct, _ = strconv.Atoi(f[1])
		if rf := strings.Fields(f[2]); len(rf) > 0 {
			w.LinkRateMbps, _ = strconv.ParseFloat(rf[0], 64)
		}
		return w
	}
	return nil
}

// ParseKeyValues parses "key : value" / "key: value" lines (macOS route,
// scutil, netsh). Keys are lower-cased and trimmed; first occurrence wins.
func ParseKeyValues(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, exists := m[k]; !exists {
			m[k] = strings.TrimSpace(strings.TrimRight(v, "\r"))
		}
	}
	return m
}

// ParseHardwarePorts maps device → port name from
// `networksetup -listallhardwareports` (macOS).
func ParseHardwarePorts(out string) map[string]string {
	m := map[string]string{}
	var port string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(t, "Hardware Port:"); ok {
			port = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(t, "Device:"); ok && port != "" {
			m[strings.TrimSpace(v)] = port
			port = ""
		}
	}
	return m
}

// PortType classifies a macOS hardware port / Windows adapter name.
func PortType(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "wi-fi") || strings.Contains(l, "wifi") || strings.Contains(l, "wireless") || strings.Contains(l, "wlan") || strings.Contains(l, "airport"):
		return TypeWiFi
	case LooksLikeVPN(name):
		return TypeVPN
	case strings.Contains(l, "ethernet") || strings.Contains(l, "lan") || strings.Contains(l, "thunderbolt") || strings.Contains(l, "usb 10/100"):
		return TypeEthernet
	case strings.Contains(l, "cellular") || strings.Contains(l, "mobile") || strings.Contains(l, "wwan") || strings.Contains(l, "iphone"):
		return TypeCellular
	}
	return TypeOther
}

var (
	spSignalRe = regexp.MustCompile(`Signal / Noise:\s*(-?\d+)\s*dBm`)
	spRateRe   = regexp.MustCompile(`Transmit Rate:\s*([\d.]+)`)
)

// ParseSystemProfilerAirport parses the current-network section of
// `system_profiler SPAirPortDataType` (macOS).
func ParseSystemProfilerAirport(out string) *WiFiInfo {
	i := strings.Index(out, "Current Network Information:")
	if i < 0 {
		return nil
	}
	out = out[i:]
	w := &WiFiInfo{Source: "system_profiler"}
	if m := spSignalRe.FindStringSubmatch(out); m != nil {
		w.SignalDBm, _ = strconv.Atoi(m[1])
	}
	if m := spRateRe.FindStringSubmatch(out); m != nil {
		w.LinkRateMbps, _ = strconv.ParseFloat(m[1], 64)
	}
	if w.SignalDBm == 0 && w.LinkRateMbps == 0 {
		return nil
	}
	return w
}

// ParseScutilDNS returns the nameservers of the first resolver in
// `scutil --dns` (macOS).
func ParseScutilDNS(out string) []string {
	var servers []string
	started := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "resolver #") {
			if started && len(servers) > 0 {
				break
			}
			started = true
			continue
		}
		if strings.HasPrefix(t, "nameserver[") {
			if _, v, ok := strings.Cut(t, ":"); ok {
				servers = appendIPs(servers, v)
			}
		}
	}
	return servers
}

// ParseScutilProxy describes enabled proxies from `scutil --proxy` (macOS).
func ParseScutilProxy(out string) []string {
	kv := ParseKeyValues(out)
	var src []string
	if kv["httpenable"] == "1" {
		src = append(src, "system: HTTP proxy "+kv["httpproxy"]+":"+kv["httpport"])
	}
	if kv["httpsenable"] == "1" {
		src = append(src, "system: HTTPS proxy "+kv["httpsproxy"]+":"+kv["httpsport"])
	}
	if kv["proxyautoconfigenable"] == "1" {
		src = append(src, "system: auto-config (PAC)")
	}
	if kv["proxyautodiscoveryenable"] == "1" {
		src = append(src, "system: auto-discovery (WPAD)")
	}
	return src
}

// WinRoute is a row from `route print -4`.
type WinRoute struct {
	Dest, Mask, Gateway, IfaceIP string
	Metric                       int
}

// ParseWindowsRoutePrint parses the IPv4 Active Routes table.
func ParseWindowsRoutePrint(out string) []WinRoute {
	var routes []WinRoute
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 5 || net.ParseIP(f[0]) == nil || net.ParseIP(f[1]) == nil {
			continue
		}
		metric, err := strconv.Atoi(f[4])
		if err != nil {
			continue
		}
		routes = append(routes, WinRoute{Dest: f[0], Mask: f[1], Gateway: f[2], IfaceIP: f[3], Metric: metric})
	}
	return routes
}

var netshPctRe = regexp.MustCompile(`(\d+)%`)

// ParseNetshWlan parses `netsh wlan show interfaces`.
func ParseNetshWlan(out string) *WiFiInfo {
	kv := ParseKeyValues(out)
	if s, ok := kv["state"]; ok && !strings.EqualFold(s, "connected") {
		return nil
	}
	w := &WiFiInfo{Source: "netsh"}
	if m := netshPctRe.FindStringSubmatch(kv["signal"]); m != nil {
		w.SignalPct, _ = strconv.Atoi(m[1])
	}
	for _, k := range []string{"receive rate (mbps)", "transmit rate (mbps)"} {
		if v, err := strconv.ParseFloat(kv[k], 64); err == nil {
			w.LinkRateMbps = v
			break
		}
	}
	if w.SignalPct == 0 && w.LinkRateMbps == 0 {
		return nil
	}
	return w
}

// ParseIPsInText returns every IP address token in text (used for netsh DNS
// listings, which vary by locale).
func ParseIPsInText(out string) []string {
	var ips []string
	for _, f := range strings.Fields(out) {
		if net.ParseIP(f) != nil {
			ips = appendUnique(ips, f)
		}
	}
	return ips
}

// ParseWindowsProxyReg parses `reg query ...\Internet Settings`.
func ParseWindowsProxyReg(out string) []string {
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.HasPrefix(f[1], "REG_") {
			vals[strings.ToLower(f[0])] = strings.Join(f[2:], " ")
		}
	}
	var src []string
	if v := vals["proxyenable"]; v == "0x1" {
		src = append(src, "system: proxy "+vals["proxyserver"])
	}
	if vals["autoconfigurl"] != "" {
		src = append(src, "system: auto-config (PAC)")
	}
	return src
}
