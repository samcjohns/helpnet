package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/miekg/dns"
)

// DNSQuery is a single timed lookup.
type DNSQuery struct {
	Domain  string   `json:"domain"`
	Type    string   `json:"type"` // A or AAAA
	Ms      float64  `json:"ms"`
	Rcode   string   `json:"rcode"` // NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT, ERROR
	Answers []string `json:"answers,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// OK reports whether the query got a usable response (even if empty).
func (q DNSQuery) OK() bool { return q.Rcode == "NOERROR" }

// QueryResolver sends one query for domain directly to server (ip or ip:port).
func QueryResolver(ctx context.Context, server, domain string, qtype uint16, timeout time.Duration) DNSQuery {
	q := DNSQuery{Domain: domain, Type: dns.TypeToString[qtype]}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true
	c := &dns.Client{Net: "udp", Timeout: timeout}
	start := time.Now()
	in, _, err := c.ExchangeContext(ctx, msg, server)
	q.Ms = Ms(time.Since(start))
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			q.Rcode = "TIMEOUT"
		} else {
			q.Rcode = "ERROR"
		}
		q.Error = err.Error()
		return q
	}
	q.Rcode = dns.RcodeToString[in.Rcode]
	for _, rr := range in.Answer {
		switch v := rr.(type) {
		case *dns.A:
			q.Answers = append(q.Answers, v.A.String())
		case *dns.AAAA:
			q.Answers = append(q.Answers, v.AAAA.String())
		}
	}
	sort.Strings(q.Answers)
	return q
}

// QuerySystem resolves domain through the operating system's resolver path
// (the same one a browser uses), including any local caching it does.
func QuerySystem(ctx context.Context, domain string, qtype uint16, timeout time.Duration) DNSQuery {
	q := DNSQuery{Domain: domain, Type: dns.TypeToString[qtype]}
	network := "ip4"
	if qtype == dns.TypeAAAA {
		network = "ip6"
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupNetIP(cctx, network, domain)
	q.Ms = Ms(time.Since(start))
	if err != nil {
		var de *net.DNSError
		switch {
		case errors.As(err, &de) && de.IsNotFound:
			// Go reports both NXDOMAIN and "no records of this type" as not
			// found; for AAAA the latter is normal, so treat it as empty.
			q.Rcode = "NOERROR"
			if qtype == dns.TypeA {
				q.Rcode = "NXDOMAIN"
			}
		case errors.As(err, &de) && de.IsTimeout, cctx.Err() != nil:
			q.Rcode = "TIMEOUT"
		default:
			q.Rcode = "ERROR"
		}
		if q.Rcode != "NOERROR" {
			q.Error = err.Error()
		}
		return q
	}
	q.Rcode = "NOERROR"
	for _, a := range addrs {
		q.Answers = append(q.Answers, a.Unmap().String())
	}
	sort.Strings(q.Answers)
	return q
}

// IsBogon reports whether an answer address is one a public name should never
// resolve to (unspecified, loopback, private, link-local) — a sign of
// filtering or blocking.
func IsBogon(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
}
