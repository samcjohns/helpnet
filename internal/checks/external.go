package checks

import (
	"context"

	"github.com/helpnet/helpnet/internal/probe"
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
