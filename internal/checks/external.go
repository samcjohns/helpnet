package checks

import (
	"context"
	"errors"
	"time"

	"github.com/samcjohns/nethelp/internal/probe"
)

// Layer 5 — route trace via Trippy or the OS traceroute.
type traceCheck struct{}

func (traceCheck) ID() ID { return Trace }

const traceMaxHops = 20

func (traceCheck) Run(ctx context.Context, rc *RunContext) (any, error) {
	tool := probe.TraceTool()
	if tool == "" {
		return nil, &SkipError{Reason: "no route trace tool installed", Hint: probe.TraceInstallHint()}
	}
	host := rc.Opts.TraceHost
	if host == "" {
		host = rc.Opts.TargetHost()
	}
	rc.Progress("tracing route to %s with %s…", host, tool)
	tr, err := probe.Trace(ctx, host, traceMaxHops)
	if tr.Note != "" {
		rc.Note("%s", tr.Note)
	}
	if err != nil {
		return &tr, err
	}
	return &tr, nil
}

// Layer 6 — bandwidth via librespeed-cli.
type speedCheck struct{}

func (speedCheck) ID() ID { return Speed }

func (speedCheck) Run(ctx context.Context, rc *RunContext) (any, error) {
	if !probe.SpeedToolAvailable() {
		return nil, &SkipError{Reason: "librespeed-cli not installed", Hint: probe.SpeedInstallHint()}
	}
	rc.Progress("running librespeed-cli (this takes ~30s)…")
	s, err := probe.SpeedTest(ctx)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Layer 7 — Tailscale's own view via its CLI: peer connection paths from
// `tailscale status` and NAT/UDP facts from `tailscale netcheck`.
type tailscaleCheck struct{}

func (tailscaleCheck) ID() ID { return Tailscale }

// tailscaleTimeout bounds netcheck, which probes Tailscale's relay servers.
const tailscaleTimeout = 15 * time.Second

func (tailscaleCheck) Run(ctx context.Context, rc *RunContext) (any, error) {
	if !probe.TailscaleInstalled() {
		return nil, &SkipError{Reason: "Tailscale not installed"}
	}
	ctx, cancel := context.WithTimeout(ctx, tailscaleTimeout)
	defer cancel()
	rc.Progress("reading tailscale status…")
	st, err := probe.TailscaleStatusOf(ctx)
	if errors.Is(err, probe.ErrTailscaleNotRunning) {
		return nil, &SkipError{Reason: "Tailscale is installed but tailscaled is not running"}
	}
	if err != nil {
		return nil, err
	}
	res := &probe.TailscaleResult{Status: st}
	rc.Progress("running tailscale netcheck…")
	nc, err := probe.TailscaleNetcheckOf(ctx)
	if err != nil {
		rc.Note("tailscale netcheck failed: %v", err)
		return res, nil
	}
	res.Netcheck = &nc
	return res, nil
}
