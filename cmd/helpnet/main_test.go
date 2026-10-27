package main

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/samcjohns/helpnet/internal/checks"
	"github.com/samcjohns/helpnet/internal/fixtures"
	"github.com/samcjohns/helpnet/internal/report"
)

func TestReorderArgs(t *testing.T) {
	got := reorderArgs([]string{"example.com", "--quick", "-n", "5", "--export=r.md", "--timeout", "2s"})
	want := []string{"--quick", "-n", "5", "--export=r.md", "--timeout", "2s", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseFlags(t *testing.T) {
	f, pos, err := parseFlags([]string{"example.com", "--speed", "-t", "https://x.test", "--samples", "4", "--timeout", "500ms", "--json"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !f.speed || !f.json || f.target != "https://x.test" || f.samples != 4 || f.timeout != 500*time.Millisecond {
		t.Errorf("flags %+v", f)
	}
	if len(pos) != 1 || pos[0] != "example.com" {
		t.Errorf("positional %v", pos)
	}
	if f, _, _ := parseFlags([]string{"-v"}, io.Discard); !f.verbose {
		t.Error("-v should set verbose")
	}
	if _, _, err := parseFlags([]string{"--bogus"}, io.Discard); err == nil {
		t.Error("unknown flag should error")
	}
}

func TestBadInvocationsExit3(t *testing.T) {
	for _, args := range [][]string{{"--bogus"}, {"a.com", "b.com"}, {"--samples", "0"}, {"--config", "/nonexistent/helpnet.toml"}} {
		if code := run(args); code != exitError {
			t.Errorf("run(%v) = %d, want %d", args, code, exitError)
		}
	}
	if code := run([]string{"--version"}); code != 0 {
		t.Errorf("--version exit %d", code)
	}
}

func TestPrintDetailsUsesStoredResults(t *testing.T) {
	r := fixtures.Healthy()
	for _, id := range []checks.ID{checks.Local, checks.Gateway, checks.HTTP} {
		var b bytes.Buffer
		printDetails(&b, report.Colors{}, id, r)
		want := report.Details(id, r)
		if len(want) == 0 {
			t.Fatalf("%s: fixture has no details", id)
		}
		for _, d := range want {
			if !strings.Contains(b.String(), "      "+d+"\n") {
				t.Errorf("%s: missing %q in:\n%s", id, d, b.String())
			}
		}
	}
}
