package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// SpeedResult is a parsed LibreSpeed CLI run.
type SpeedResult struct {
	Tool         string  `json:"tool"`
	Server       string  `json:"server,omitempty"`
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
	PingMs       float64 `json:"ping_ms"`
	JitterMs     float64 `json:"jitter_ms"`
	Raw          string  `json:"raw,omitempty"`
}

// SpeedToolAvailable reports whether librespeed-cli is on PATH.
func SpeedToolAvailable() bool { return LookPath("librespeed-cli") != "" }

// SpeedInstallHint explains how to install librespeed-cli.
func SpeedInstallHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "install librespeed-cli (brew install librespeed-cli)"
	default:
		return "install librespeed-cli from https://github.com/librespeed/speedtest-cli/releases"
	}
}

// SpeedTest runs librespeed-cli and parses its JSON report.
func SpeedTest(ctx context.Context) (SpeedResult, error) {
	res := SpeedResult{Tool: "librespeed-cli"}
	if !SpeedToolAvailable() {
		return res, fmt.Errorf("librespeed-cli not found; %s", SpeedInstallHint())
	}
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	out, err := RunCommand(cctx, "librespeed-cli", "--json")
	res.Raw = out
	if err != nil {
		return res, fmt.Errorf("librespeed-cli: %v", firstLine(out, err))
	}
	parsed, err := ParseLibrespeedJSON(out)
	if err != nil {
		return res, err
	}
	parsed.Raw = out
	return parsed, nil
}

// ParseLibrespeedJSON parses `librespeed-cli --json` output, which is either
// a single object or an array of per-server results (the first is used).
func ParseLibrespeedJSON(out string) (SpeedResult, error) {
	type entry struct {
		Server struct {
			Name string `json:"name"`
		} `json:"server"`
		Ping     float64 `json:"ping"`
		Jitter   float64 `json:"jitter"`
		Download float64 `json:"download"`
		Upload   float64 `json:"upload"`
	}
	out = strings.TrimSpace(out)
	if i := strings.IndexAny(out, "[{"); i > 0 {
		out = out[i:]
	}
	var entries []entry
	if strings.HasPrefix(out, "[") {
		if err := json.Unmarshal([]byte(out), &entries); err != nil {
			return SpeedResult{}, fmt.Errorf("parsing librespeed output: %w", err)
		}
	} else {
		var e entry
		if err := json.Unmarshal([]byte(out), &e); err != nil {
			return SpeedResult{}, fmt.Errorf("parsing librespeed output: %w", err)
		}
		entries = []entry{e}
	}
	if len(entries) == 0 {
		return SpeedResult{}, fmt.Errorf("librespeed returned no results")
	}
	e := entries[0]
	return SpeedResult{
		Tool: "librespeed-cli", Server: e.Server.Name,
		DownloadMbps: e.Download, UploadMbps: e.Upload, PingMs: e.Ping, JitterMs: e.Jitter,
	}, nil
}
