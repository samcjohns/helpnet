package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestDefaultsWorkWithoutFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.toml"), false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != "https://www.google.com" || cfg.Samples != 10 || cfg.Timeout.Duration != 3*time.Second {
		t.Errorf("defaults: %+v", cfg)
	}
	if cfg.Thresholds.DNSWarnMs != 100 || cfg.Thresholds.DownloadFailMbps != 5 {
		t.Errorf("default thresholds: %+v", cfg.Thresholds)
	}
}

func TestExplicitMissingFileIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.toml"), true); err == nil {
		t.Error("expected error for explicitly requested missing config")
	}
}

func TestLoadOverridesOnlyGivenKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(path, []byte(`
target = "https://example.com"
timeout = "5s"

[hosts]
internet = ["9.9.9.9"]

[thresholds]
dns_warn_ms = 50

[ui]
theme = "light"
`), 0o644)
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != "https://example.com" || cfg.Timeout.Duration != 5*time.Second || cfg.UI.Theme != "light" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.Thresholds.DNSWarnMs != 50 || cfg.Thresholds.DNSFailMs != 300 {
		t.Errorf("threshold merge: %+v", cfg.Thresholds)
	}
	if len(cfg.Hosts.Internet) != 1 || len(cfg.Hosts.DNSPublic) != 2 || cfg.Samples != 10 {
		t.Errorf("host merge: %+v", cfg.Hosts)
	}
}

func TestValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.toml")
	for _, body := range []string{`samples = 0`, `timeout = "-1s"`, `[ui]` + "\n" + `theme = "neon"`, `timeout = "soon"`} {
		os.WriteFile(path, []byte(body), 0o644)
		if _, err := Load(path, true); err == nil {
			t.Errorf("expected error for %q", body)
		}
	}
}

// The documented example must stay in sync with the built-in defaults.
func TestExampleConfigMatchesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "docs", "config.example.toml"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Errorf("docs/config.example.toml differs from Default():\n got %+v\nwant %+v", cfg, Default())
	}
}
