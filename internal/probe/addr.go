package probe

import "net/netip"

// cgnatPrefix is the shared address space ISPs use for carrier-grade NAT
// (RFC 6598). Tailscale assigns its device addresses from the same range.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// IsCGNAT reports whether s is an IPv4 address in 100.64.0.0/10.
func IsCGNAT(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && cgnatPrefix.Contains(a.Unmap())
}

// IsPrivateAddr reports whether s is an RFC 1918 / RFC 4193 private address.
func IsPrivateAddr(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Unmap().IsPrivate()
}

// IsPublicAddr reports whether s is a globally routable unicast address:
// not private, shared (CGNAT), loopback or link-local.
func IsPublicAddr(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnatPrefix.Contains(a)
}
