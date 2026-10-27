package sysinfo

import (
	"reflect"
	"testing"
)

func TestParseIPRouteGet(t *testing.T) {
	r := ParseIPRouteGet("1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.42 uid 1000 \n    cache")
	if r != (RouteGet{Via: "192.168.1.1", Dev: "wlan0", Src: "192.168.1.42"}) {
		t.Errorf("got %+v", r)
	}
	wg := ParseIPRouteGet("1.1.1.1 dev wg0 table 51820 src 10.2.0.2 uid 1000")
	if wg.Dev != "wg0" || wg.Via != "" {
		t.Errorf("wireguard route %+v", wg)
	}
}

func TestParseProcNetRoute(t *testing.T) {
	data := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0101A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	FE01A8C0	0003	0	0	100	00000000	0	0	0
wlan0	0001A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
`
	got := ParseProcNetRoute(data)
	want := []DefaultRoute{{"eth0", "192.168.1.254", 100}, {"wlan0", "192.168.1.1", 600}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseResolvConfAndResolvectl(t *testing.T) {
	rc := "# comment\nnameserver 127.0.0.53\noptions edns0\nsearch lan\n"
	if got := ParseResolvConf(rc); !reflect.DeepEqual(got, []string{"127.0.0.53"}) {
		t.Errorf("resolv.conf: %v", got)
	}
	status := `Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 3 (wlp2s0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1 fe80::1%wlp2s0
                    1.1.1.1#cloudflare-dns.com
        DNS Domain: lan
`
	if got := ParseResolvectl(status); !reflect.DeepEqual(got, []string{"192.168.1.1"}) {
		t.Errorf("current server: %v", got)
	}
	noCurrent := "       DNS Servers: 9.9.9.9\n                    1.1.1.1#cloudflare-dns.com\n        DNS Domain: lan\n"
	if got := ParseResolvectl(noCurrent); !reflect.DeepEqual(got, []string{"9.9.9.9", "1.1.1.1"}) {
		t.Errorf("server list: %v", got)
	}
}

func TestWiFiParsers(t *testing.T) {
	iw := `Connected to aa:bb:cc:dd:ee:ff (on wlan0)
	SSID: home
	freq: 5180
	signal: -67 dBm
	rx bitrate: 433.3 MBit/s VHT-MCS 9 80MHz VHT-NSS 1
	tx bitrate: 390.0 MBit/s VHT-MCS 8 80MHz VHT-NSS 1
`
	w := ParseIwLink(iw)
	if w == nil || w.SignalDBm != -67 || w.LinkRateMbps != 390 {
		t.Errorf("iw: %+v", w)
	}
	if ParseIwLink("Not connected.") != nil {
		t.Error("iw not connected should be nil")
	}
	proc := `Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
wlan0: 0000   43.  -67.  -256        0      0      0      0     12        0
`
	if w := ParseProcNetWireless(proc, "wlan0"); w == nil || w.SignalDBm != -67 {
		t.Errorf("/proc/net/wireless: %+v", w)
	}
	if w := ParseNmcliWifi(" :40:130 Mbit/s\n*:72:270 Mbit/s\n"); w == nil || w.SignalPct != 72 || w.LinkRateMbps != 270 {
		t.Errorf("nmcli: %+v", w)
	}
	netsh := "    Name                   : Wi-Fi\r\n    State                  : connected\r\n    Signal                 : 38%\r\n    Receive rate (Mbps)    : 144.4\r\n    Transmit rate (Mbps)   : 130\r\n"
	if w := ParseNetshWlan(netsh); w == nil || w.SignalPct != 38 || w.LinkRateMbps != 144.4 {
		t.Errorf("netsh: %+v", w)
	}
	sp := `Wi-Fi:
      Interfaces:
        en0:
          Status: Connected
          Current Network Information:
            Home:
              PHY Mode: 802.11ac
              Signal / Noise: -58 dBm / -91 dBm
              Transmit Rate: 585
          Other Local Wi-Fi Networks:
            Neighbour:
              Signal / Noise: -80 dBm / -91 dBm
`
	if w := ParseSystemProfilerAirport(sp); w == nil || w.SignalDBm != -58 || w.LinkRateMbps != 585 {
		t.Errorf("system_profiler: %+v", w)
	}
}

func TestWiFiQuality(t *testing.T) {
	cases := map[int]int{-50: 100, -40: 100, -75: 50, -100: 0}
	for dbm, want := range cases {
		if got := (WiFiInfo{SignalDBm: dbm}).Quality(); got != want {
			t.Errorf("Quality(%d dBm) = %d, want %d", dbm, got, want)
		}
	}
	if got := (WiFiInfo{SignalPct: 77, SignalDBm: -90}).Quality(); got != 77 {
		t.Errorf("percentage should win, got %d", got)
	}
}

func TestMacOSParsers(t *testing.T) {
	route := "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n"
	kv := ParseKeyValues(route)
	if kv["gateway"] != "192.168.1.1" || kv["interface"] != "en0" {
		t.Errorf("route: %v", kv)
	}
	ports := "Hardware Port: Ethernet Adapter (en4)\nDevice: en4\nEthernet Address: x\n\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: y\n"
	m := ParseHardwarePorts(ports)
	if PortType(m["en0"]) != TypeWiFi || PortType(m["en4"]) != TypeEthernet {
		t.Errorf("ports: %v", m)
	}
	dns := "DNS configuration\n\nresolver #1\n  search domain[0] : lan\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : fe80::1%en0\n  flags    : Request A records\n\nresolver #2\n  nameserver[0] : 10.0.0.1\n"
	if got := ParseScutilDNS(dns); !reflect.DeepEqual(got, []string{"192.168.1.1"}) {
		t.Errorf("scutil dns: %v", got)
	}
	proxy := "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 1\n  HTTPSPort : 8080\n  HTTPSProxy : proxy.corp\n  ProxyAutoConfigEnable : 1\n}\n"
	if got := ParseScutilProxy(proxy); len(got) != 2 || got[0] != "system: HTTPS proxy proxy.corp:8080" {
		t.Errorf("scutil proxy: %v", got)
	}
}

func TestWindowsParsers(t *testing.T) {
	route := `IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.42     35
          0.0.0.0        128.0.0.0         10.8.0.1        10.8.0.2      5
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
Persistent Routes:
  None
`
	routes := ParseWindowsRoutePrint(route)
	if len(routes) != 3 || routes[0].Gateway != "192.168.1.1" || routes[0].IfaceIP != "192.168.1.42" || routes[0].Metric != 35 {
		t.Errorf("routes: %+v", routes)
	}
	reg := "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    proxy.corp:3128\r\n"
	if got := ParseWindowsProxyReg(reg); len(got) != 1 || got[0] != "system: proxy proxy.corp:3128" {
		t.Errorf("reg: %v", got)
	}
	dns := "Configuration for interface \"Wi-Fi\"\r\n    DNS servers configured through DHCP:  192.168.1.1\r\n                                          8.8.8.8\r\n    Register with which suffix:           Primary only\r\n"
	if got := ParseIPsInText(dns); !reflect.DeepEqual(got, []string{"192.168.1.1", "8.8.8.8"}) {
		t.Errorf("netsh dns: %v", got)
	}
}

func TestLooksLikeVPNAndRedact(t *testing.T) {
	for _, n := range []string{"utun3", "wg0", "tun0", "tailscale0", "OpenVPN TAP-Windows6", "WireGuard Tunnel", "ppp0"} {
		if !LooksLikeVPN(n) {
			t.Errorf("%q should look like a VPN", n)
		}
	}
	for _, n := range []string{"en0", "eth0", "wlan0", "Wi-Fi", "Ethernet"} {
		if LooksLikeVPN(n) {
			t.Errorf("%q should not look like a VPN", n)
		}
	}
	if got := RedactProxy("http://alice:s3cret@proxy:3128"); got != "http://%2A%2A%2A@proxy:3128" && got != "http://***@proxy:3128" {
		t.Errorf("redact: %q", got)
	}
}
