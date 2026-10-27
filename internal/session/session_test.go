package session

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/helpnet/helpnet/internal/checks"
	"github.com/helpnet/helpnet/internal/config"
	"github.com/helpnet/helpnet/internal/interpret"
	"github.com/helpnet/helpnet/internal/probe"
	"github.com/helpnet/helpnet/internal/report"
	"github.com/helpnet/helpnet/internal/sysinfo"
)

// startDNS runs a local DNS server that answers every A query with
// 127.0.0.1 after delay, and returns its address.
func startDNS(t *testing.T, delay time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(delay)
		m := new(dns.Msg)
		m.SetReply(r)
		if q := r.Question[0]; q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Name + " 60 IN A 127.0.0.1")
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

type env struct {
	params Params
}

// newEnv wires a full workflow to localhost: loopback "gateway" and
// "internet" hosts, a TLS test server as the HTTP target, local DNS
// servers, and a captive-portal endpoint that answers 204.
func newEnv(t *testing.T, systemDNSDelay time.Duration) env {
	t.Helper()
	if probe.LookPath("ping") == "" {
		t.Skip("system ping not available")
	}
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>hello</html>"))
	}))
	t.Cleanup(site.Close)
	captive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(captive.Close)

	cfg := config.Default()
	cfg.Samples = 3
	cfg.Timeout.Duration = time.Second
	cfg.Hosts.Internet = []string{"127.0.0.1"}
	cfg.Hosts.DNSPublic = []string{startDNS(t, 0)}
	cfg.Hosts.DNSTestDomains = []string{"example.test", "helpnet.test"}
	cfg.Hosts.CaptiveURL = captive.URL

	return env{params: Params{
		Version: "test",
		Plan:    []checks.ID{checks.Local, checks.Gateway, checks.Internet, checks.DNS, checks.HTTP},
		Opts: checks.Options{
			Config:         cfg,
			Target:         site.URL,
			TLSConfig:      site.Client().Transport.(*http.Transport).TLSClientConfig,
			SystemResolver: startDNS(t, systemDNSDelay),
			Detect: func(context.Context) (sysinfo.Info, error) {
				return sysinfo.Info{Interface: "lo", Type: sysinfo.TypeEthernet, IPv4: []string{"127.0.0.1"}, Gateway: "127.0.0.1"}, nil
			},
		},
	}}
}

// collect drains a run, checking that updates stream in order.
func collect(t *testing.T, ch <-chan Update) (*report.Report, []Update) {
	t.Helper()
	var ups []Update
	var rep *report.Report
	for u := range ch {
		ups = append(ups, u)
		if u.Done {
			rep = u.Report
		}
	}
	if rep == nil {
		t.Fatal("no final report")
	}
	return rep, ups
}

func TestWorkflowHealthyLocalhost(t *testing.T) {
	e := newEnv(t, 0)
	start := time.Now()
	rep, ups := collect(t, Start(context.Background(), e.params))
	if el := time.Since(start); el > 15*time.Second {
		t.Errorf("workflow took %v", el)
	}
	for _, c := range rep.Checks {
		if c.State.Outcome != checks.OutcomeOK {
			t.Errorf("%s: %s %s%s", c.ID, c.State.Outcome, c.State.Error, c.State.SkipReason)
		}
	}
	if rep.Primary == nil || rep.Primary.Rule != interpret.RuleHealthy {
		t.Fatalf("primary = %+v\nfindings: %+v", rep.Primary, rep.Findings)
	}
	if rep.ExitCode != 0 || rep.Rating.Grade != "Excellent" {
		t.Errorf("exit %d, rating %+v", rep.ExitCode, rep.Rating)
	}
	h := rep.Results.HTTP
	if h.OK != 3 || h.Status != 200 || h.TLSVersion == "" || h.TLSMs <= 0 || h.ConnectMs <= 0 {
		t.Errorf("http result %+v", h)
	}
	// Each check streams Started then Finished, in layer order.
	var order []checks.ID
	for _, u := range ups {
		if u.Event.Type == checks.EventFinished {
			order = append(order, u.Event.ID)
			if u.Results == nil || u.Results.States[u.Event.ID].Outcome == "" {
				t.Errorf("finished update for %s lacks a results snapshot", u.Event.ID)
			}
		}
	}
	if len(order) != 5 || order[0] != checks.Local || order[4] != checks.HTTP {
		t.Errorf("finish order %v", order)
	}
	if _, err := report.JSON(*rep); err != nil {
		t.Errorf("JSON: %v", err)
	}
}

func TestWorkflowSlowSystemDNS(t *testing.T) {
	e := newEnv(t, 350*time.Millisecond)
	rep, ups := collect(t, Start(context.Background(), e.params))
	if rep.Primary == nil || rep.Primary.Rule != interpret.RuleDNSSystemSlow {
		t.Fatalf("primary = %+v\nfindings: %+v", rep.Primary, rep.Findings)
	}
	if rep.ExitCode != 2 {
		t.Errorf("exit code %d", rep.ExitCode)
	}
	// The DNS finding streams in when DNS finishes, before HTTP runs.
	streamed := false
	for _, u := range ups {
		if u.Event.Type == checks.EventFinished && u.Event.ID == checks.DNS {
			for _, f := range u.Findings {
				streamed = streamed || f.Rule == interpret.RuleDNSSystemSlow
			}
		}
	}
	if !streamed {
		t.Error("DNS finding was not streamed when the DNS check finished")
	}
}

func TestWorkflowNoNetwork(t *testing.T) {
	e := newEnv(t, 0)
	e.params.Opts.Detect = func(context.Context) (sysinfo.Info, error) { return sysinfo.Info{}, sysinfo.ErrNoRoute }
	start := time.Now()
	rep, _ := collect(t, Start(context.Background(), e.params))
	if time.Since(start) > 2*time.Second {
		t.Errorf("no-network run should be instant, took %v", time.Since(start))
	}
	if rep.Primary == nil || rep.Primary.Rule != interpret.RuleNoNetwork {
		t.Fatalf("primary = %+v", rep.Primary)
	}
	for _, c := range rep.Checks[1:] {
		if c.Status != interpret.StatusSkipped || c.State.SkipReason != "no network connection" {
			t.Errorf("%s: %s (%s)", c.ID, c.Status, c.State.SkipReason)
		}
	}
	if rep.Rating.Grade != "Down" {
		t.Errorf("rating %+v", rep.Rating)
	}
}

func TestCancellationStopsQuickly(t *testing.T) {
	e := newEnv(t, 0)
	e.params.Opts.Config.Samples = 50 // long enough to be mid-ping when cancelled
	ctx, cancel := context.WithCancel(context.Background())
	ch := Start(ctx, e.params)
	for u := range ch {
		if u.Event.Type == checks.EventStarted && u.Event.ID == checks.Gateway {
			break
		}
	}
	time.Sleep(300 * time.Millisecond)
	cancelled := time.Now()
	cancel()
	rep, _ := collect(t, ch)
	if el := time.Since(cancelled); el > time.Second {
		t.Errorf("run took %v to stop after cancel", el)
	}
	if rep.Complete {
		t.Error("cancelled report should be marked incomplete")
	}
	for _, id := range []checks.ID{checks.Internet, checks.DNS, checks.HTTP} {
		if st := rep.Results.States[id]; st.Outcome != checks.OutcomeSkipped || st.SkipReason != "cancelled" {
			t.Errorf("%s: %+v", id, st)
		}
	}
}

func TestPartialRerunKeepsEarlierResults(t *testing.T) {
	e := newEnv(t, 0)
	first, _ := collect(t, Start(context.Background(), e.params))
	p := e.params
	p.Prev = first.Results
	p.Plan = []checks.ID{checks.DNS}
	p.Opts.DNSDomain = "only.test"
	second, _ := collect(t, Start(context.Background(), p))
	if second.Results.Gateway != first.Results.Gateway || second.Results.HTTP != first.Results.HTTP {
		t.Error("partial re-run should reuse earlier results")
	}
	if d := second.Results.DNS.Domains; len(d) != 1 || d[0] != "only.test" {
		t.Errorf("dns domains %v", d)
	}
}

func TestJSONReportIsValid(t *testing.T) {
	e := newEnv(t, 0)
	rep, _ := collect(t, Start(context.Background(), e.params))
	data, err := report.JSON(*rep)
	if err != nil || !json.Valid(data) {
		t.Fatalf("invalid JSON report: %v", err)
	}
}
