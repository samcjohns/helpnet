// Command helpnet diagnoses why web browsing is slow: it tests the network
// layer by layer and explains where the bottleneck is.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/samcjohns/helpnet/internal/checks"
	"github.com/samcjohns/helpnet/internal/config"
	"github.com/samcjohns/helpnet/internal/report"
	"github.com/samcjohns/helpnet/internal/session"
	"github.com/samcjohns/helpnet/internal/tui"
)

// version is overridden at release time with -ldflags "-X main.version=…".
var version = "0.1.0"

const exitError = 3

type cliFlags struct {
	target     string
	samples    int
	timeout    time.Duration
	quick      bool
	speed      bool
	noTUI      bool
	verbose    bool
	json       bool
	export     string
	configPath string
	version    bool
	set        map[string]bool // flags given explicitly
}

const usage = `helpnet — find out why your browser is slow

Usage:
  helpnet [flags] [url]

Examples:
  helpnet                         launch the TUI and run the full workflow
  helpnet example.com             use example.com as the HTTP target
  helpnet --quick                 skip route trace and bandwidth test
  helpnet --speed                 include the bandwidth test
  helpnet --no-tui                plain streaming text output
  helpnet --no-tui -v             plain output with every check's details
  helpnet --json                  print a JSON report to stdout
  helpnet --export report.md      run and save the report (.json for JSON)

Flags:
  -t, --target <url>     HTTP timing target (default https://www.google.com)
  -n, --samples <int>    ping samples per host (default 10)
      --timeout <dur>    per-probe timeout (default 3s)
      --quick            skip slow checks (route trace, bandwidth)
      --speed            include the bandwidth test (needs librespeed-cli)
      --no-tui           line-based output (automatic when stdout isn't a TTY)
      --json             machine-readable output; implies --no-tui
  -v, --verbose          show per-check details and raw tool output
      --export <path>    write the report when the run ends
      --config <path>    alternate config file (default %s)
      --version          print the version
  -h, --help             show this help

Exit codes: 0 all checks passed · 1 warnings · 2 failures · 3 helpnet error
`

// valueFlags lists flags that take an argument, so positional arguments can
// appear anywhere on the command line.
var valueFlags = map[string]bool{"t": true, "target": true, "n": true, "samples": true, "timeout": true, "export": true, "config": true}

// reorderArgs moves positional arguments after all flags, since the flag
// package stops parsing at the first non-flag.
func reorderArgs(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if !strings.Contains(name, "=") && valueFlags[name] && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, pos...)
}

func parseFlags(args []string, stderr io.Writer) (cliFlags, []string, error) {
	var f cliFlags
	fs := flag.NewFlagSet("helpnet", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.target, "target", "", "")
	fs.StringVar(&f.target, "t", "", "")
	fs.IntVar(&f.samples, "samples", 0, "")
	fs.IntVar(&f.samples, "n", 0, "")
	fs.DurationVar(&f.timeout, "timeout", 0, "")
	fs.BoolVar(&f.quick, "quick", false, "")
	fs.BoolVar(&f.speed, "speed", false, "")
	fs.BoolVar(&f.noTUI, "no-tui", false, "")
	fs.BoolVar(&f.verbose, "verbose", false, "")
	fs.BoolVar(&f.verbose, "v", false, "")
	fs.BoolVar(&f.json, "json", false, "")
	fs.StringVar(&f.export, "export", "", "")
	fs.StringVar(&f.configPath, "config", "", "")
	fs.BoolVar(&f.version, "version", false, "")
	err := fs.Parse(reorderArgs(args))
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprintf(stderr, usage, config.DefaultPath())
		return f, nil, err
	}
	f.set = map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return f, fs.Args(), err
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	f, pos, err := parseFlags(args, os.Stdout)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "helpnet: %v\nRun 'helpnet --help' for usage.\n", err)
		return exitError
	}
	if f.version {
		fmt.Println("helpnet", version)
		return 0
	}
	if len(pos) > 1 {
		fmt.Fprintf(os.Stderr, "helpnet: expected at most one URL, got %d\n", len(pos))
		return exitError
	}

	cfgPath, explicit := f.configPath, f.configPath != ""
	if !explicit {
		cfgPath = config.DefaultPath()
	}
	cfg, err := config.Load(cfgPath, explicit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helpnet: %v\n", err)
		return exitError
	}
	if f.set["samples"] || f.set["n"] {
		cfg.Samples = f.samples
	}
	if f.set["timeout"] {
		cfg.Timeout.Duration = f.timeout
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "helpnet: %v\n", err)
		return exitError
	}
	target := cfg.Target
	if len(pos) == 1 {
		target = pos[0]
	}
	if f.target != "" {
		target = f.target
	}
	target = checks.NormalizeTarget(target)

	params := session.Params{
		Opts:    checks.Options{Config: cfg, Target: target},
		Plan:    checks.WithInstalled(checks.Plan(f.quick, f.speed)),
		Version: version,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tty := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	var rep *report.Report
	switch {
	case f.json:
		rep = runJSON(ctx, params)
	case f.noTUI || !tty:
		rep = runPlain(ctx, params, os.Stdout, tty, f.verbose)
	default:
		stop() // the TUI handles ctrl+c itself
		var err error
		rep, err = tui.Run(tui.Options{Params: params, Theme: cfg.UI.Theme, Version: version, ExportPath: f.export, Verbose: f.verbose})
		if err != nil {
			fmt.Fprintf(os.Stderr, "helpnet: %v\n", err)
			return exitError
		}
		if rep == nil {
			return 0 // quit before any check finished
		}
	}
	if rep == nil {
		return exitError
	}
	if f.export != "" {
		if err := report.Export(*rep, f.export); err != nil {
			fmt.Fprintf(os.Stderr, "helpnet: export failed: %v\n", err)
			return exitError
		}
		if !f.json {
			fmt.Fprintf(os.Stderr, "Report saved to %s\n", f.export)
		}
	}
	return rep.ExitCode
}

func runJSON(ctx context.Context, p session.Params) *report.Report {
	var rep *report.Report
	for u := range session.Start(ctx, p) {
		if u.Done {
			rep = u.Report
		}
	}
	if rep == nil {
		return nil
	}
	data, err := report.JSON(*rep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helpnet: %v\n", err)
		return nil
	}
	os.Stdout.Write(data)
	return rep
}
