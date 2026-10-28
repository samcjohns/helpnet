// Package config loads nethelp settings from an optional TOML file and
// provides defaults for every value, so nethelp works with no config at all.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
)

// Duration wraps time.Duration so it can be written as "3s" in TOML.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

type Hosts struct {
	Internet       []string `toml:"internet"`
	DNSPublic      []string `toml:"dns_public"`
	DNSTestDomains []string `toml:"dns_test_domains"`
	CaptiveURL     string   `toml:"captive_url"`
}

// Thresholds holds every warn/fail limit used by the interpretation engine.
// Latencies are in milliseconds, losses in percent, speeds in Mbps.
type Thresholds struct {
	GatewayWiFiWarnMs     float64 `toml:"gateway_wifi_warn_ms"`
	GatewayWiFiFailMs     float64 `toml:"gateway_wifi_fail_ms"`
	GatewayEthernetWarnMs float64 `toml:"gateway_ethernet_warn_ms"`
	GatewayEthernetFailMs float64 `toml:"gateway_ethernet_fail_ms"`
	GatewayLossWarnPct    float64 `toml:"gateway_loss_warn_pct"`
	GatewayLossFailPct    float64 `toml:"gateway_loss_fail_pct"`
	InternetWarnMs        float64 `toml:"internet_warn_ms"`
	InternetFailMs        float64 `toml:"internet_fail_ms"`
	InternetLossWarnPct   float64 `toml:"internet_loss_warn_pct"`
	InternetLossFailPct   float64 `toml:"internet_loss_fail_pct"`
	JitterWarnMs          float64 `toml:"jitter_warn_ms"`
	JitterFailMs          float64 `toml:"jitter_fail_ms"`
	DNSWarnMs             float64 `toml:"dns_warn_ms"`
	DNSFailMs             float64 `toml:"dns_fail_ms"`
	TCPWarnMs             float64 `toml:"tcp_warn_ms"`
	TCPFailMs             float64 `toml:"tcp_fail_ms"`
	TLSWarnMs             float64 `toml:"tls_warn_ms"`
	TLSFailMs             float64 `toml:"tls_fail_ms"`
	TTFBWarnMs            float64 `toml:"ttfb_warn_ms"`
	TTFBFailMs            float64 `toml:"ttfb_fail_ms"`
	DownloadWarnMbps      float64 `toml:"download_warn_mbps"`
	DownloadFailMbps      float64 `toml:"download_fail_mbps"`
}

type UI struct {
	Theme string `toml:"theme"` // auto | dark | light
}

type Config struct {
	Target     string     `toml:"target"`
	Samples    int        `toml:"samples"`
	Timeout    Duration   `toml:"timeout"`
	Hosts      Hosts      `toml:"hosts"`
	Thresholds Thresholds `toml:"thresholds"`
	UI         UI         `toml:"ui"`
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		GatewayWiFiWarnMs: 20, GatewayWiFiFailMs: 80,
		GatewayEthernetWarnMs: 5, GatewayEthernetFailMs: 30,
		GatewayLossWarnPct: 1, GatewayLossFailPct: 5,
		InternetWarnMs: 80, InternetFailMs: 200,
		InternetLossWarnPct: 1, InternetLossFailPct: 5,
		JitterWarnMs: 20, JitterFailMs: 50,
		DNSWarnMs: 100, DNSFailMs: 300,
		TCPWarnMs: 150, TCPFailMs: 500,
		TLSWarnMs: 250, TLSFailMs: 800,
		TTFBWarnMs: 600, TTFBFailMs: 2000,
		DownloadWarnMbps: 25, DownloadFailMbps: 5,
	}
}

func Default() Config {
	return Config{
		Target:  "https://www.google.com",
		Samples: 10,
		Timeout: Duration{3 * time.Second},
		Hosts: Hosts{
			Internet:       []string{"1.1.1.1", "8.8.8.8"},
			DNSPublic:      []string{"1.1.1.1", "9.9.9.9"},
			DNSTestDomains: []string{"google.com", "cloudflare.com", "wikipedia.org"},
			CaptiveURL:     "http://connectivitycheck.gstatic.com/generate_204",
		},
		Thresholds: DefaultThresholds(),
		UI:         UI{Theme: "auto"},
	}
}

// DefaultPath returns the per-OS config file location.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "nethelp", "config.toml")
		}
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" && runtime.GOOS != "windows" {
		return filepath.Join(xdg, "nethelp", "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "nethelp", "config.toml")
}

// Load reads the config at path on top of the defaults. A missing file at the
// default location is not an error; a missing explicitly-requested file is.
func Load(path string, explicit bool) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config: %w", err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	if c.Samples < 1 || c.Samples > 100 {
		return fmt.Errorf("samples must be between 1 and 100, got %d", c.Samples)
	}
	if c.Timeout.Duration <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	switch c.UI.Theme {
	case "", "auto", "dark", "light":
	default:
		return fmt.Errorf("ui.theme must be auto, dark or light, got %q", c.UI.Theme)
	}
	if len(c.Hosts.Internet) == 0 {
		return fmt.Errorf("hosts.internet must list at least one host")
	}
	return nil
}
