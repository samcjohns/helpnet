# AGENTS.md

Guidance for AI agents (and humans) working on helpnet. Read `README.md` for what the tool does and `helpnet.md` for the original product spec. This file covers what neither of them says: design rules, deliberate deviations from the spec, test hooks and known gaps.

## Quick start

```sh
make test        # all tests (unit, parser, snapshot, localhost integration)
make race        # same with -race — run before finishing any change
make lint        # go vet + gofmt check
go run ./cmd/helpnet            # TUI against the real network
go run ./cmd/helpnet --no-tui   # plain output; easiest way to eyeball a change
```

Go module: `github.com/samcjohns/helpnet`. Go version comes from `go.mod`. No cgo; release builds use `CGO_ENABLED=0`.

## Architecture in one paragraph

`checks.Run` executes the layers in order (`local → gateway → internet → dns → http → trace → speed → tailscale`; the plan decides which run) and emits `checks.Event`s. `session.Start` wraps it. After every finished check it takes a snapshot of the results and re-runs `interpret.Analyze` on it, so findings stream in as soon as their inputs exist. It sends `session.Update`s on a channel and finishes with a `report.Report`. Every frontend consumes that same stream: the TUI (`internal/tui`), plain text (`cmd/helpnet/plain.go`) and JSON (`cmd/helpnet/main.go`). `report` turns results and findings into the conclusion, statistics, rating and the Markdown/JSON/text output.

## Rules to preserve

- **`internal/interpret` is pure.** No I/O, no clocks, no globals. It is called on partial results many times per run, so every rule must cope with missing layers (nil results or no `States` entry).
- **Finished results are immutable.** `checks.Results` holds pointers to typed results that are never mutated after their check finishes. Only the `States` map is copied (`Results.Clone`). Partial re-runs (`R`, `/dns`, `/target` …) pass `Prev` and work on a copy. Never mutate a snapshot you received from a channel; clone it first (see `tui.start`).
- **Checks are UI-agnostic.** A check reports through `rc.Progress` (live line), `rc.Note` (detail line) and its return value. Return `&SkipError{Reason, Hint}` when an optional tool is missing. A missing tool is a skip, never an error.
- **Everything is cancellable and bounded.** Pass `ctx` through and run subprocesses via `probe.RunCommand` (it uses `CommandContext` and `WaitDelay`). Quitting must stop everything within 1s. `TestCancellationStopsQuickly` guards this.
- **Never require privileges.** Never call sudo. Fall back (e.g. pro-bing → system `ping`, `trip --unprivileged` → `traceroute`) and record the fallback with `rc.Note`.
- **Per-OS code goes behind build tags** (`sysinfo_<os>.go`). Put text parsers in OS-neutral files (`sysinfo/parse.go`, `probe/*.go`) so they can be tested on any platform.
- **Privacy:** reports contain network diagnostics only. No username or machine hostname; proxy credentials are redacted (`sysinfo.RedactProxy`). The same goes for other machines: no Tailscale peer names, tailnet name or public addresses, and no raw `tailscale` output in `Raw`. Test fixtures must not contain real public IPs; use RFC 5737 ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), plus made-up 100.64.0.0/10 addresses for CGNAT and tailnet cases.

## Deliberate deviations from `helpnet.md` — do not "fix" these

1. **Gateway unreachable does not skip downstream checks.** Many routers ignore ICMP, so skipping would misdiagnose working networks. Only *no network* (local check errors) or *internet unreachable* (no ping **and** no TCP 443 to any host) skips later layers. A detected captive portal does not skip them. See `checks.blockedBy`.
2. **Extra rule: router deprioritises pings to itself.** If loss or latency to the gateway is bad but traffic *through* it to the internet is clean, this is reported as harmless info and excluded from scoring (`gatewayDeprioritized`). For the same reason, gateway findings wait until the internet check has a state (`gatewayReady`), so they appear slightly later in the stream.
3. **Downstream symptoms never outrank their cause.** When the gateway is bad, internet, DNS and HTTP findings are capped at the gateway's severity with low confidence (`minSev(...)`). This keeps the primary diagnosis at the lowest failing layer.
4. **VPN suppresses the ISP finding.** If the default route goes through a VPN and latency is elevated, the `vpn-latency` finding (layer local) replaces `isp`.
5. **The ISP finding names the metric that fired:** loss (high confidence), then latency (medium), then jitter (low). A single spike can push jitter over 20 ms.
6. **DNS "answers differ" fires only for differences a CDN can't explain:** NXDOMAIN or empty vs real answers, or private/blocked addresses. Plain differing public IPs are only counted (`cdn_differs`).
7. **Trace hops are named by reverse DNS only.** There is no ASN lookup, because that would mean querying an outside service, which conflicts with "fully local".
8. **Healthy finding** (`RuleHealthy`) appears only once layers 0–4 all have a state and nothing is warn/fail.
9. **Tailscale is layer 7 and only planned when its CLI is installed** (`checks.WithInstalled`). Without it, the check is left out of the plan, the TUI and the report rather than shown as skipped. It is not scored. It comes after bandwidth so the spec's layer numbers 0–6 stay put.
10. **CGNAT is detected locally, without STUN.** The signals are this device's address or gateway in 100.64.0.0/10, or a trace hop in that range before any public hop. Tailnet addresses use the same range, so trace-based detection is off when a VPN carries the default route (`findTraceNAT`, `localCGNAT`). Double NAT needs a private hop 2 within 2 ms of hop 1; a farther private hop is usually the ISP's own router.
11. **Ping interval is 200 ms** (the unprivileged minimum), so 10 samples take about 2 s per host and the full run stays well under 30 s.
12. **Watch mode (`/watch`) is outside the check pipeline.** `internal/watch` samples once a second, and `interpret.AnalyzeWatch` (pure) turns the samples into events, incidents and a verdict. It applies rules 2 and 3 in its own form. An incident is blamed on the lowest layer that failed in it. A gateway-only incident while the internet stayed clean is `CauseRouter`: harmless and not counted. A spike means a probe above the layer's *fail* threshold, and a probe unanswered within 0.9 s counts as lost. The DNS probe looks up a random label so caches can't hide an outage; NXDOMAIN counts as success. The TUI blocks other checks while a watch runs, because their traffic would show up as spikes.

## Adding things

**A new interpretation rule:** add a `Rule…` constant and logic in `internal/interpret/rules.go`, then a test in `rules_test.go` using `internal/fixtures` (start from `fixtures.Healthy()` and break one thing). Check that the expected primary diagnosis still holds for the existing tests. If report output changes, run `make snapshots` and review the diff of `internal/report/testdata/`.

**A new check/layer:** add an ID in `checks/types.go` (`Order`, `Title`) and a typed result field on `Results` (plus `set`). Register it in `checks/runner.go`, then add `report.Line`, `report.Details` and (if relevant) `Statistics` and the score weight. Extend `docs/report-schema.json`; `TestReportsMatchSchema` will fail until the schema matches. Add an entry to `tui.pendingText` if it is optional.

**A new config key:** add it to `config.Config` with a default in `Default()`, and add it to `docs/config.example.toml`. `TestExampleConfigMatchesDefaults` enforces that the two match.

**A new slash command:** add it to `commands` in `tui/commands.go` (it drives autocomplete and help), handle it in `model.exec`, add a test in `tui_test.go` and update the README table.

## Test hooks

| Hook | Purpose |
|---|---|
| `checks.Options.Detect` | Replace interface detection (integration tests use loopback as the "gateway") |
| `checks.Options.SystemResolver` | Query a given DNS server in place of the OS resolver path |
| `checks.Options.TLSConfig` | Trust a self-signed `httptest` server |
| `go test ./internal/report -update` | Regenerate golden `report.md` / `report.json` |
| `HELPNET_TUI_DEMO=1 go test ./internal/tui -run LiveDemo -v` | Drive the real TUI model against the network and print frames (`make demo`) |
| `HELPNET_REPORT=/abs/path.json go test ./internal/report -run FileMatches` | Validate any real `--json` output against the schema |
| `watch.Options.Probe` | Replace the per-layer measurement in watch mode; `tui/watch_test.go` feeds `watchMsg`s directly instead |
| Fake tools on `PATH` | `checks/external_test.go` shows how to stand in for `trip` / `traceroute` / `librespeed-cli` with shell scripts |

TUI tests drive the Bubble Tea model directly (`fixtureModel` feeds synthetic `updateMsg`s, then they assert on `View()`). They also check that every line fits the terminal width. To test the real binary in a terminal, run it under a pty that has a window size **and** answers the terminal's startup queries (`ESC]11;?` background colour and `ESC[6n` cursor position). Otherwise the first keypress is swallowed as the reply. Plain `script` gives a 0×0 pty and appears to hang.

## Known gaps / unverified

- **macOS and Windows have never been run**, only cross-compiled and tested against representative sample outputs (`internal/probe/testdata`, `sysinfo/parse_test.go`). CI (`.github/workflows/ci.yml`) runs the test suite on both. Verify `sysinfo_darwin.go` / `sysinfo_windows.go` detection on real machines.
- **Trippy:** the JSON parser (`probe.ParseTrippyJSON`) and the flags (`--mode json --report-cycles --max-ttl --unprivileged --dns-resolve-method`) are based on documentation knowledge, not a captured run. Capture a real `trip --mode json` output into `testdata/` and adjust.
- **Tailscale:** `tailscale netcheck --format=json` is marked unstable by Tailscale. The parser (`probe.ParseTailscaleNetcheck`) tolerates missing fields, and its optional booleans may be JSON booleans, strings or null. The fixtures in `probe/testdata/tailscale_*.json` are based on Tailscale 1.102 on Linux. Detecting a stopped `tailscaled` matches English error text. Privacy: keep `TailscaleResult` free of peer names, the tailnet name and the `GlobalV4`/`GlobalV6` addresses; `TestParseTailscaleStatus` checks this.
- **LibreSpeed:** tested only via a fake script that uses the documented `--json` array format.
- **Wi-Fi on macOS** uses `system_profiler SPAirPortDataType` (slow, about 2–5 s; capped at 6 s). On macOS, `wdutil` needs sudo and `airport` was removed.
- **Ping fallback parsing on non-English Windows** matches on `TTL=` and an `ms` value; only English and German samples are tested.
- **Clipboard:** `c` uses the system clipboard tool and falls back to OSC 52; it is untested over SSH.

## Release

Tag `vX.Y.Z` and push. `.github/workflows/release.yml` runs the tests, then GoReleaser (`.goreleaser.yaml`) builds linux/darwin/windows × amd64/arm64 and injects `main.version`. All linked Go dependencies are MIT or BSD-3; re-check licenses when adding a dependency (the README states this). External tools are never bundled.
