package probe

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// RunCommand runs an external program and returns its combined output. The
// process is killed when ctx is cancelled; WaitDelay bounds how long we wait
// for its pipes to close afterwards so quitting never hangs.
func RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.WaitDelay = 500 * time.Millisecond
	err := cmd.Run()
	if ctx.Err() != nil {
		return buf.String(), ctx.Err()
	}
	return buf.String(), err
}

// RunCommandStdout is RunCommand for tools that log to stderr while writing
// machine-readable output to stdout; the two are returned separately.
func RunCommandStdout(ctx context.Context, name string, args ...string) (stdout, stderr string, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	cmd.WaitDelay = 500 * time.Millisecond
	err = cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return out.String(), errBuf.String(), err
}

// LookPath reports the full path of an executable on PATH, or "".
func LookPath(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}
