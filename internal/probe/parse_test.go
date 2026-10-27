package probe

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func approx(a, b float64) bool { return math.Abs(a-b) < 0.01 }

func TestParsePingOutput(t *testing.T) {
	tests := []struct {
		file string
		want []float64
	}{
		{"ping_darwin.txt", []float64{18.345, 17.902, 21.118, 19.004}},
		{"ping_windows.txt", []float64{3, 1, 12}},
		{"ping_windows_de.txt", []float64{14, 15}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got := ParsePingOutput(readFixture(t, tt.file))
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if !approx(got[i], tt.want[i]) {
					t.Errorf("sample %d = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
	t.Run("ping_linux.txt", func(t *testing.T) {
		out := readFixture(t, "ping_linux.txt")
		got := ParsePingOutput(out)
		if len(got) == 0 || len(got) > 5 {
			t.Fatalf("got %d samples from captured Linux output", len(got))
		}
		if !looksLikePingRan(out) {
			t.Error("looksLikePingRan = false for real ping output")
		}
	})
}

func TestSummarise(t *testing.T) {
	s := Summarise(5, []float64{10, 20, 10, 40})
	if s.LossPct != 20 || s.MinMs != 10 || s.MaxMs != 40 || s.AvgMs != 20 {
		t.Fatalf("unexpected stats %+v", s)
	}
	// Jitter: mean(|20-10|, |10-20|, |40-10|) = 50/3.
	if !approx(s.JitterMs, 50.0/3) {
		t.Errorf("jitter = %v", s.JitterMs)
	}
	if s.P95Ms != 40 {
		t.Errorf("p95 = %v", s.P95Ms)
	}
	empty := Summarise(3, nil)
	if empty.LossPct != 100 || empty.AvgMs != 0 {
		t.Errorf("all-lost stats %+v", empty)
	}
}

func TestParseTracerouteLinux(t *testing.T) {
	hops := ParseTraceroute(readFixture(t, "traceroute_linux.txt"))
	if len(hops) < 3 {
		t.Fatalf("got %d hops", len(hops))
	}
	if hops[0].TTL != 1 || len(hops[0].Hosts) != 1 || hops[0].Received != 3 {
		t.Errorf("hop 1 = %+v", hops[0])
	}
	for i, h := range hops {
		if h.TTL != i+1 {
			t.Errorf("hop %d has TTL %d", i+1, h.TTL)
		}
		if h.Sent == 0 {
			t.Errorf("hop %d has no probes", h.TTL)
		}
	}
}

func TestParseTracerouteDarwin(t *testing.T) {
	hops := ParseTraceroute(readFixture(t, "traceroute_darwin.txt"))
	if len(hops) != 5 {
		t.Fatalf("got %d hops, want 5", len(hops))
	}
	if hops[2].Responded() || hops[2].LossPct != 100 {
		t.Errorf("hop 3 should be all stars: %+v", hops[2])
	}
	// Hop 4 spans a continuation line: two hosts, 3 probes, 1 lost.
	h4 := hops[3]
	if len(h4.Hosts) != 2 || h4.Sent != 3 || h4.Received != 2 {
		t.Errorf("hop 4 = %+v", h4)
	}
	if !approx(hops[4].AvgMs, (14.210+13.871+14.002)/3) {
		t.Errorf("hop 5 avg = %v", hops[4].AvgMs)
	}
}

func TestParseTracert(t *testing.T) {
	hops := ParseTracert(readFixture(t, "tracert_windows.txt"))
	if len(hops) != 5 {
		t.Fatalf("got %d hops, want 5: %+v", len(hops), hops)
	}
	if hops[0].Hosts[0] != "192.168.1.1" || hops[0].Received != 3 || hops[0].AvgMs != 0.5 {
		t.Errorf("hop 1 = %+v", hops[0])
	}
	if hops[2].Responded() {
		t.Errorf("hop 3 should have timed out: %+v", hops[2])
	}
	if hops[3].Received != 2 || hops[3].Sent != 3 {
		t.Errorf("hop 4 = %+v", hops[3])
	}
}

func TestParseTrippyJSON(t *testing.T) {
	hops, err := ParseTrippyJSON("warning: something\n" + readFixture(t, "trippy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 4 {
		t.Fatalf("got %d hops", len(hops))
	}
	if hops[0].Name != "router.lan" || hops[0].AvgMs != 1.92 || hops[0].Received != 5 {
		t.Errorf("hop 1 = %+v", hops[0])
	}
	if hops[1].Responded() {
		t.Errorf("hop 2 should be silent: %+v", hops[1])
	}
	if hops[2].Name != "" {
		t.Errorf("hostname equal to IP should be dropped, got %q", hops[2].Name)
	}
	if hops[3].LossPct != 20 {
		t.Errorf("hop 4 loss = %v", hops[3].LossPct)
	}
}

func TestParseLibrespeedJSON(t *testing.T) {
	s, err := ParseLibrespeedJSON(readFixture(t, "librespeed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !approx(s.DownloadMbps, 312.66) || !approx(s.UploadMbps, 41.21) || s.PingMs != 12.4 || s.Server == "" {
		t.Errorf("unexpected %+v", s)
	}
	single, err := ParseLibrespeedJSON(`{"server":{"name":"x"},"download":5,"upload":1,"ping":3,"jitter":1}`)
	if err != nil || single.DownloadMbps != 5 {
		t.Errorf("single object: %+v, %v", single, err)
	}
	if _, err := ParseLibrespeedJSON("[]"); err == nil {
		t.Error("empty array should be an error")
	}
}

func TestIsBogon(t *testing.T) {
	for _, ip := range []string{"0.0.0.0", "127.0.0.1", "10.1.2.3", "192.168.0.1", "::1", "fe80::1"} {
		if !IsBogon(ip) {
			t.Errorf("%s should be bogon", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "142.250.1.1", "2606:4700::1111"} {
		if IsBogon(ip) {
			t.Errorf("%s should not be bogon", ip)
		}
	}
}

func TestSystemPingArgs(t *testing.T) {
	opt := PingOptions{Count: 10, Interval: 100e6, Timeout: 3e9}
	_, linux := systemPingArgs("linux", "h", opt)
	want := []string{"-n", "-c", "10", "-i", "0.2", "-W", "3", "h"}
	if len(linux) != len(want) {
		t.Fatalf("linux args %v", linux)
	}
	for i := range want {
		if linux[i] != want[i] {
			t.Errorf("linux arg %d = %q, want %q", i, linux[i], want[i])
		}
	}
	_, win := systemPingArgs("windows", "h", opt)
	if win[0] != "-n" || win[3] != "3000" {
		t.Errorf("windows args %v", win)
	}
}
