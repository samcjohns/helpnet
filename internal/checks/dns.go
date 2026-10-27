package checks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/helpnet/helpnet/internal/probe"
)

// Layer 3 — DNS comparison between the system resolver and public ones.
type dnsCheck struct{}

func (dnsCheck) ID() ID { return DNS }

// repeatsPerDomain is how many A lookups each resolver gets per domain; the
// first is reported as "cold", the rest as "warm".
const repeatsPerDomain = 3

func (dnsCheck) Run(ctx context.Context, rc *RunContext) (any, error) {
	cfg := rc.Opts.Config
	domains := dnsDomains(rc.Opts)
	res := &DNSResult{Domains: domains}

	sysName := "system"
	if l := rc.Results.Local; l != nil && len(l.DNSServers) > 0 {
		sysName = strings.Join(l.DNSServers, ", ")
	}
	type resolver struct {
		name, server string
		system       bool
	}
	resolvers := []resolver{{name: sysName, system: true}}
	for _, s := range cfg.Hosts.DNSPublic {
		resolvers = append(resolvers, resolver{name: s, server: s})
	}

	res.Resolvers = make([]ResolverStats, len(resolvers))
	timeout := cfg.Timeout.Duration
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	total := len(resolvers) * len(domains)
	for i, r := range resolvers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			query := func(domain string, qt uint16) probe.DNSQuery {
				if r.system && rc.Opts.SystemResolver == "" {
					return probe.QuerySystem(ctx, domain, qt, timeout)
				}
				if r.system {
					return probe.QueryResolver(ctx, rc.Opts.SystemResolver, domain, qt, timeout)
				}
				return probe.QueryResolver(ctx, r.server, domain, qt, timeout)
			}
			stats := ResolverStats{Name: r.name, Server: r.server, System: r.system}
			consecutiveTimeouts := 0
			for _, d := range domains {
				if ctx.Err() != nil || consecutiveTimeouts >= 2 {
					break // an unreachable resolver would otherwise cost timeout × queries
				}
				for k := 0; k < repeatsPerDomain && consecutiveTimeouts < 2; k++ {
					q := query(d, dns.TypeA)
					stats.Queries = append(stats.Queries, q)
					if q.Rcode == "TIMEOUT" {
						consecutiveTimeouts++
					} else {
						consecutiveTimeouts = 0
					}
				}
				if consecutiveTimeouts < 2 {
					stats.Queries = append(stats.Queries, query(d, dns.TypeAAAA))
				}
				mu.Lock()
				done++
				rc.Progress("resolving %s via %s (%d/%d)", d, r.name, done, total)
				mu.Unlock()
			}
			summariseResolver(&stats)
			res.Resolvers[i] = stats
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	compareAnswers(res)
	if sys := res.System(); sys != nil && sys.Unreachable() && res.BestPublic() == nil {
		return res, fmt.Errorf("no resolver answered any query")
	}
	return res, nil
}

func dnsDomains(o Options) []string {
	if o.DNSDomain != "" {
		return []string{o.DNSDomain}
	}
	var out []string
	seen := map[string]bool{}
	for _, d := range append([]string{o.TargetHost()}, o.Config.Hosts.DNSTestDomains...) {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d == "" || seen[d] || isIP(d) {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func isIP(s string) bool { return net.ParseIP(s) != nil }

func summariseResolver(s *ResolverStats) {
	var all, cold, warm []float64
	seenDomain := map[string]bool{}
	for _, q := range s.Queries {
		switch q.Rcode {
		case "NOERROR", "NXDOMAIN":
			s.Answered++
		case "SERVFAIL":
			s.ServFail++
			s.Failures++
		case "TIMEOUT":
			s.Timeouts++
			s.Failures++
		default:
			s.Failures++
		}
		if q.Rcode == "NXDOMAIN" {
			s.NXDomain++
		}
		if q.Type == "AAAA" {
			if len(q.Answers) > 0 {
				s.AAAA++
			}
			continue
		}
		if q.Rcode != "NOERROR" && q.Rcode != "NXDOMAIN" {
			continue
		}
		all = append(all, q.Ms)
		if !seenDomain[q.Domain] {
			seenDomain[q.Domain] = true
			cold = append(cold, q.Ms)
		} else {
			warm = append(warm, q.Ms)
		}
	}
	st := probe.Summarise(len(all), all)
	s.AvgMs, s.MinMs, s.MaxMs, s.P95Ms = st.AvgMs, st.MinMs, st.MaxMs, st.P95Ms
	s.ColdAvgMs, s.WarmAvgMs = probe.Mean(cold), probe.Mean(warm)
}

// compareAnswers flags disagreements between the system resolver and public
// resolvers that a CDN would not explain.
func compareAnswers(res *DNSResult) {
	sys := res.System()
	if sys == nil {
		return
	}
	firstA := func(s *ResolverStats, domain string) *probe.DNSQuery {
		for i := range s.Queries {
			q := &s.Queries[i]
			if q.Domain == domain && q.Type == "A" && (q.Rcode == "NOERROR" || q.Rcode == "NXDOMAIN") {
				return q
			}
		}
		return nil
	}
	for _, d := range res.Domains {
		sq := firstA(sys, d)
		if sq == nil {
			continue
		}
		cdn := false
		for i := range res.Resolvers {
			pub := &res.Resolvers[i]
			if pub.System {
				continue
			}
			pq := firstA(pub, d)
			if pq == nil {
				continue
			}
			switch {
			case sq.Rcode == "NXDOMAIN" && len(pq.Answers) > 0:
				res.Differences = append(res.Differences, fmt.Sprintf("%s: system resolver says it does not exist; %s returns %s", d, pub.Name, pq.Answers[0]))
			case len(sq.Answers) == 0 && len(pq.Answers) > 0:
				res.Differences = append(res.Differences, fmt.Sprintf("%s: system resolver returned no addresses; %s returns %s", d, pub.Name, pq.Answers[0]))
			case allBogon(sq.Answers) && !allBogon(pq.Answers):
				res.Differences = append(res.Differences, fmt.Sprintf("%s: system resolver returns %s (private/blocked address); %s returns %s", d, sq.Answers[0], pub.Name, pq.Answers[0]))
			case !overlap(sq.Answers, pq.Answers):
				cdn = true
			default:
				continue
			}
			break // one difference per domain is enough
		}
		if cdn {
			res.CDNDiffers++
		}
	}
}

func allBogon(answers []string) bool {
	if len(answers) == 0 {
		return false
	}
	for _, a := range answers {
		if !probe.IsBogon(a) {
			return false
		}
	}
	return true
}

func overlap(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}
