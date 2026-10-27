# helpnet — Product Specification

> A local, open-source network diagnostic tool with an interactive terminal UI. Run `helpnet` when your browser is slow or pages hang, and within ~30 seconds get a layered diagnosis of *where* the problem is, *what* it probably is, and *what to do about it*.

---

## 1. Problem

When a browser loads slowly, it rarely says why. The cause could be Wi-Fi, the router, the ISP, DNS, a VPN or proxy, the remote server, or raw bandwidth — and each requires a different fix. Existing tools (ping, traceroute, dig, speed tests, browser DevTools) each answer one piece of the question, require knowing which to run, and leave interpretation to the user.

**helpnet** runs the right checks in the right order, interprets the results, and explains the likely bottleneck in plain English.

## 2. Goals

1. **One command.** `helpnet` launches the TUI and starts the diagnostic workflow immediately.
2. **Layered diagnosis.** Test from closest to farthest (machine → gateway → internet → DNS → HTTP → bandwidth) so the first failing layer identifies the problem.
3. **Interpretation, not just numbers.** A rule-based engine turns raw results into findings ("DNS is slow: 420 ms average via your router's resolver") with suggested fixes.
4. **Final summary.** Every run ends with a conclusion, statistics, and a performance rating.
5. **Fully local.** No accounts, no telemetry, no cloud services beyond the test targets themselves. Interpretation runs locally with no AI/LLM dependency.
6. **Cross-platform.** macOS, Linux, and Windows.
7. **Open source.** MIT or Apache-2.0 licensed.

## 3. Non-Goals (v1)

- Continuous background monitoring or historical dashboards (possible future feature).
- Packet capture or deep protocol analysis (that's Wireshark's job).
- Automatically changing system settings (helpnet suggests fixes; it never applies them).
- Managing multiple machines or a network fleet.

---

## 4. User Experience

### 4.1 UI Inspiration

Use the **OpenCode** project as the primary inspiration for the terminal interface: a full-screen, keyboard-driven TUI with a clean, modern look, a scrolling main pane of streamed output, a persistent input/command bar at the bottom, a status line, and themed colors. The feel should be close to Claude Code / OpenCode: calm, readable, and conversational, with structured blocks for each step rather than raw tool dumps.

Study OpenCode's layout, interaction patterns, and visual language. Do not copy its code; build an original implementation.

### 4.2 Layout

```
┌─ helpnet ─────────────────────────────────────────── v0.1.0 ─┐
│                                                              │
│  ● Local interface      en0 · Wi-Fi · 192.168.1.42     ✓     │
│  ● Gateway              192.168.1.1 · 3.1 ms · 0% loss ✓     │
│  ● Internet             1.1.1.1 · 18 ms · 0% loss      ✓     │
│  ◐ DNS                  resolving via 192.168.1.1 …          │
│  ○ HTTP timing          pending                              │
│  ○ Route trace          pending                              │
│  ○ Bandwidth            pending (optional)                   │
│                                                              │
│  ── Findings ──────────────────────────────────────────────  │
│  ⚠ DNS lookups are slow (avg 412 ms via router resolver).    │
│    Public resolver 1.1.1.1 answered in 14 ms.                │
│    → Try setting your DNS to 1.1.1.1 or 9.9.9.9.             │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ > _                                       /help · ctrl+c quit│
├──────────────────────────────────────────────────────────────┤
│ target: example.com · elapsed 12.4s · checks 3/7             │
└──────────────────────────────────────────────────────────────┘
```

- **Main pane:** a vertical list of check blocks. Each block shows a status icon (pending ○, running ◐ with spinner, pass ✓, warn ⚠, fail ✗, skipped –), a name, a one-line live result, and can be expanded to show details (per-sample timings, raw tool output).
- **Findings pane:** interpreted findings stream in as soon as they can be determined, not only at the end.
- **Command bar:** accepts slash commands (see 4.4).
- **Status line:** current target, elapsed time, progress, and whether optional tools were detected.
- Colors: green/yellow/red for pass/warn/fail; muted gray for metadata. Support light and dark terminals and respect `NO_COLOR`.

### 4.3 Keyboard

| Key | Action |
|---|---|
| `↑` / `↓` or `j` / `k` | Move between check blocks |
| `enter` / `space` | Expand/collapse selected block |
| `r` | Re-run the full workflow |
| `R` | Re-run only the selected check |
| `/` | Focus the command bar |
| `s` | Jump to the final summary |
| `c` | Copy the summary to clipboard |
| `?` | Help overlay |
| `q` / `ctrl+c` | Quit |

### 4.4 Slash Commands

| Command | Description |
|---|---|
| `/run` | Re-run the full workflow |
| `/quick` | Run only the fast checks (skip trace and bandwidth) |
| `/target <url>` | Change the HTTP target and re-run HTTP and trace checks |
| `/speed` | Run the bandwidth test now |
| `/trace [host]` | Run the per-hop route trace |
| `/dns [domain]` | Run DNS comparison on a specific domain |
| `/export [path]` | Save the report (Markdown by default; `.json` extension → JSON) |
| `/details` | Toggle raw output for all blocks |
| `/help` | List commands |
| `/quit` | Exit |

Include command autocomplete with a small popup, as OpenCode does.

---

## 5. Command-Line Interface

```
helpnet                         # launch TUI and run the full workflow
helpnet <url>                   # same, using <url> as the HTTP target
helpnet --quick                 # skip route trace and bandwidth test
helpnet --speed                 # include the bandwidth test (off by default)
helpnet --no-tui                # plain streaming text output, no full-screen UI
helpnet --json                  # run non-interactively, print JSON report to stdout
helpnet --export report.md      # run and save the report
helpnet --version
helpnet --help
```

Flags:

| Flag | Default | Description |
|---|---|---|
| `--target, -t <url>` | `https://www.google.com` | HTTP timing target (also positional arg) |
| `--samples, -n <int>` | `10` | Ping samples per host |
| `--timeout <dur>` | `3s` | Per-probe timeout |
| `--quick` | off | Skip slow checks |
| `--speed` | off | Include bandwidth test |
| `--no-tui` | off | Line-based output (auto-enabled when stdout isn't a TTY) |
| `--json` | off | Machine-readable output; implies `--no-tui` |
| `--export <path>` | — | Write report file at end of run |
| `--config <path>` | see §9 | Alternate config file |

Exit codes: `0` all checks passed, `1` warnings found, `2` failures found, `3` helpnet itself errored.

---

## 6. Diagnostic Workflow

Checks run in layers, nearest to farthest. Independent checks within a layer may run concurrently. If a lower layer fails hard (e.g., no gateway reachable), dependent checks are marked **skipped** with the reason, and the findings explain that everything beyond that point is unreachable.

### Layer 0 — Local Interface

- Detect the active network interface, its type (Wi-Fi / Ethernet / other), local IP addresses (IPv4/IPv6), and the default gateway.
- Detect VPN or tunnel interfaces (e.g., `utun*`, `tun*`, `wg*`, WireGuard/OpenVPN adapters) and whether the default route goes through one.
- Detect system or environment proxies (`HTTP_PROXY`, `HTTPS_PROXY`, OS proxy settings where feasible).
- Where cheaply available, read Wi-Fi signal strength / link rate (macOS `airport`/`wdutil` alternatives, Linux `iw`/`nmcli`, Windows `netsh wlan show interfaces`). Treat as optional; never fail if unavailable.

### Layer 1 — Gateway

- Ping the default gateway (`--samples` times).
- Metrics: min/avg/max/p95 latency, jitter (mean absolute difference between consecutive samples), packet loss %.

### Layer 2 — Internet Reachability

- Ping `1.1.1.1` and `8.8.8.8` (configurable).
- Same metrics as Layer 1.
- Also attempt a TCP connect to `1.1.1.1:443` so a network that blocks ICMP is not misdiagnosed as offline.
- Captive portal check: request a known plain-HTTP connectivity endpoint (e.g., `http://connectivitycheck.gstatic.com/generate_204`) and flag a redirect or unexpected body.

### Layer 3 — DNS

- Resolve the target's hostname (plus 2–3 well-known domains) using:
  - the system's configured resolver, and
  - public resolvers `1.1.1.1` and `9.9.9.9` queried directly.
- Do several queries per resolver; report the first (likely uncached) and subsequent timings separately.
- Metrics: per-resolver avg/min/max ms, failures, NXDOMAIN or SERVFAIL responses, and whether answers differ between resolvers (possible DNS hijacking or filtering — report neutrally).
- Test IPv4 (A) and IPv6 (AAAA) results.

### Layer 4 — HTTP Timing

- Perform 3 HTTPS GET requests to the target, with connection reuse disabled, and break each into phases:
  - DNS lookup
  - TCP connect
  - TLS handshake
  - Time to first byte (server processing + network)
  - Content transfer
  - Total
- Also record HTTP status, final URL after redirects, number of redirects, HTTP protocol version, TLS version, and the IP actually connected to.
- If the target has both IPv4 and IPv6 addresses, time one request over each to detect a broken IPv6 path (a classic cause of browser hangs before fallback).

### Layer 5 — Route Trace (skipped in `--quick`)

- If **Trippy** (`trip`) is installed, run it in non-interactive report mode against the target and parse per-hop latency and loss.
- Otherwise, fall back to the OS traceroute (`traceroute` / `tracert`) with a hop limit and timeout.
- Identify the first hop where latency jumps significantly or loss begins **and persists to the destination**. (Loss at a middle hop that does not continue downstream is usually ICMP rate-limiting, not a real problem — the interpreter must account for this.)

### Layer 6 — Bandwidth (only with `--speed` or `/speed`)

- If `librespeed-cli` is installed, run it with JSON output and parse download/upload Mbps, ping, and jitter.
- If not installed, show the block as skipped with install instructions. Do not bundle third-party binaries.

---

## 7. Interpretation Engine

A deterministic, rule-based engine that consumes all check results and produces **findings**. No AI/LLM.

### 7.1 Finding structure

Each finding has:

- `severity`: `info` | `warn` | `fail`
- `layer`: which layer it concerns
- `title`: one short sentence ("DNS lookups are slow")
- `evidence`: the specific numbers that triggered it
- `suggestion`: one or two concrete next steps
- `confidence`: `low` | `medium` | `high`

Findings stream into the UI as soon as their inputs are available.

### 7.2 Default thresholds

Thresholds live in config (§9) and can be overridden.

| Metric | Warn | Fail |
|---|---|---|
| Gateway avg latency (Wi-Fi) | > 20 ms | > 80 ms |
| Gateway avg latency (Ethernet) | > 5 ms | > 30 ms |
| Gateway packet loss | > 1% | > 5% |
| Internet avg latency | > 80 ms | > 200 ms |
| Internet packet loss | > 1% | > 5% |
| Jitter (any host) | > 20 ms | > 50 ms |
| DNS avg resolution | > 100 ms | > 300 ms |
| TCP connect | > 150 ms | > 500 ms |
| TLS handshake | > 250 ms | > 800 ms |
| Time to first byte | > 600 ms | > 2000 ms |
| Download speed (if tested) | < 25 Mbps | < 5 Mbps |

### 7.3 Example rules

The engine should reason across layers, not just flag individual metrics. Examples:

| Condition | Finding |
|---|---|
| Gateway loss/latency bad | Problem is on your local network (Wi-Fi signal, interference, router). Suggest moving closer, using Ethernet, or rebooting the router. |
| Gateway good, internet bad | Problem is between your router and the internet: likely your ISP or modem. Suggest rebooting the modem; if persistent, contact ISP with the stats. |
| ICMP fails but TCP 443 succeeds | ICMP is blocked on this network; not a connectivity problem. Downgrade ping-based findings. |
| System DNS slow, public DNS fast | Your configured DNS resolver is the bottleneck. Suggest switching to 1.1.1.1 / 9.9.9.9. |
| All DNS slow | General latency or packet loss is affecting DNS; see network findings. |
| DNS answers differ between resolvers | Note neutrally that your resolver returns different answers (could be filtering, a CDN, or interception). |
| Network and DNS good, TTFB high | The remote server is slow, not your connection. Suggest trying another site to confirm. |
| TLS slow, TCP fast | Possible TLS inspection by antivirus, a corporate proxy, or a VPN. |
| IPv6 request fails/hangs but IPv4 fast | Broken IPv6 path causing browser delays before fallback. Suggest checking router IPv6 settings or temporarily disabling IPv6. |
| VPN active and latency elevated | Traffic is routed through a VPN; latency may be added there. Suggest testing with VPN off. |
| Captive portal detected | You're behind a login page (hotel/airport Wi-Fi). Open a browser to sign in. |
| Trace: latency jump at hop N persisting to destination | Delay introduced at hop N (name the network/ASN if resolvable). |
| Everything passes | Your connection looks healthy right now. If browsing is still slow, the issue is likely the browser itself (extensions, cache) or the specific site. Suggest DevTools Network tab. |

### 7.4 Primary diagnosis

After all checks complete, select a single **primary diagnosis**: the highest-severity, highest-confidence finding at the lowest failing layer. This drives the conclusion in the summary.

---

## 8. Final Summary

Shown at the end of every run (TUI, `--no-tui`, export). Three parts:

### 8.1 Conclusion

One or two plain-English sentences stating the primary diagnosis and the single most useful next step. Example:

> **Likely cause: slow DNS.** Your network and internet connection are healthy, but your router's DNS resolver averages 412 ms per lookup versus 14 ms for 1.1.1.1. Switching your DNS server should make pages start loading noticeably faster.

### 8.2 Statistics

A compact table of key numbers per layer:

```
Layer        Target          Avg      p95     Jitter   Loss   Status
Gateway      192.168.1.1     3.1 ms   4.8 ms  0.6 ms   0%     ✓
Internet     1.1.1.1         18 ms    22 ms   1.9 ms   0%     ✓
Internet     8.8.8.8         21 ms    25 ms   2.2 ms   0%     ✓
DNS (system) 192.168.1.1     412 ms   590 ms   —       0 fail ✗
DNS (public) 1.1.1.1         14 ms    19 ms    —       0 fail ✓
HTTP         example.com     DNS 405 · TCP 19 · TLS 41 · TTFB 112 · total 590 ms  ⚠
Bandwidth    librespeed      ↓ 312 Mbps  ↑ 41 Mbps                          ✓
```

### 8.3 Performance Rating

An overall score from 0–100 plus a grade (Excellent / Good / Fair / Poor / Down), computed from weighted layer scores. Show the breakdown per layer so the rating is explainable. Document the weighting in the code.

### 8.4 Report export

`/export` and `--export` write the summary, all findings, and per-check details (including raw tool output) to Markdown or JSON. Include a timestamp, OS, helpnet version, and interface type. Never include anything beyond network diagnostics (no usernames, hostnames are optional and off by default).

---

## 9. Configuration

Optional file at:

- macOS/Linux: `~/.config/helpnet/config.toml`
- Windows: `%APPDATA%\helpnet\config.toml`

```toml
target = "https://www.google.com"
samples = 10
timeout = "3s"

[hosts]
internet = ["1.1.1.1", "8.8.8.8"]
dns_public = ["1.1.1.1", "9.9.9.9"]
dns_test_domains = ["google.com", "cloudflare.com", "wikipedia.org"]

[thresholds]
dns_warn_ms = 100
dns_fail_ms = 300
# … all thresholds from §7.2

[ui]
theme = "auto"   # auto | dark | light
```

All settings must have sensible defaults; helpnet must work with no config file.

---

## 10. Technical Approach

### 10.1 Recommended stack

- **Language:** Go, for a single static binary on every OS, good concurrency, and a strong TUI ecosystem.
- **TUI:** Bubble Tea + Bubbles + Lip Gloss (Charm). This matches the style of modern terminal agents like OpenCode.
- **Ping:** a pure-Go ICMP library (e.g., `pro-bing`) using unprivileged UDP-ICMP where the OS allows it; fall back to invoking the system `ping` and parsing its output when raw/unprivileged ICMP isn't permitted (notably Windows without admin, Linux without `net.ipv4.ping_group_range`).
- **DNS:** a Go DNS library (e.g., `miekg/dns`) for querying specific resolvers directly; the standard resolver for the system path.
- **HTTP timing:** `net/http` with `httptrace.ClientTrace` for per-phase timings; disable keep-alives for accurate measurements.
- **External tools:** detect `trip`, `traceroute`/`tracert`, and `librespeed-cli` on `PATH`; run as subprocesses with timeouts and parse output. Never vendor or redistribute them.

If you have a strong reason to choose differently (e.g., Python + Textual), explain the tradeoff before starting.

### 10.2 Architecture

```
cmd/helpnet/            main, flag parsing
internal/checks/        one package per layer; each implements a Check interface
internal/probe/         low-level ping, DNS, HTTP, traceroute, speed wrappers
internal/sysinfo/       interface, gateway, VPN, proxy, Wi-Fi detection (per-OS files)
internal/interpret/     rules engine, thresholds, primary diagnosis, scoring
internal/report/        summary model, Markdown/JSON/text renderers
internal/tui/           Bubble Tea app, components, theme, commands
internal/config/        config loading and defaults
```

Key design rules:

- **Checks are UI-agnostic.** Each check emits typed progress events and a typed result on a channel. The TUI, `--no-tui` renderer, and `--json` mode all consume the same event stream.
- **Interpretation is pure.** `interpret.Analyze(results, thresholds) → []Finding` has no I/O, making it easy to unit test.
- **Everything has a timeout and is cancellable** via `context.Context`. Quitting mid-run stops all probes and subprocesses cleanly.
- **Per-OS code** lives behind build tags (`_darwin.go`, `_linux.go`, `_windows.go`).

### 10.3 Privileges

helpnet must run without admin/root. When a probe needs privileges it doesn't have, use the fallback and note it in the block's details. Never prompt for `sudo`.

---

## 11. Testing

- **Unit tests** for the interpretation engine covering every rule in §7.3 with fixture results, including edge cases (ICMP blocked, mid-path loss that doesn't persist, partial results after cancellation).
- **Parser tests** for each external tool's output format using captured sample outputs from each OS.
- **Scoring tests** to confirm the rating is stable and explainable.
- **Integration test** that runs the full workflow against localhost fixtures (a local HTTP/TLS server and a local DNS server) so CI doesn't depend on the internet.
- **Snapshot tests** for the Markdown and JSON report formats.
- CI on macOS, Linux, and Windows.

---

## 12. Milestones

1. **Core engine, no UI:** sysinfo, gateway/internet ping, DNS comparison, HTTP timing; `--no-tui` and `--json` output.
2. **Interpretation:** rules engine, primary diagnosis, scoring, final summary, Markdown/JSON export.
3. **TUI:** OpenCode-inspired interface, live check blocks, findings pane, keyboard navigation, slash commands with autocomplete.
4. **External tools:** Trippy/traceroute integration and LibreSpeed bandwidth test.
5. **Polish:** config file, themes, IPv6 path test, captive portal and VPN/proxy detection, README with screenshots, release builds for all three OSes.

Complete and test each milestone before moving to the next.

---

## 13. Acceptance Criteria

- Running `helpnet` with no arguments on a healthy connection completes the default workflow (excluding bandwidth) in under 30 seconds and reports "healthy."
- Pointing the system resolver at a deliberately slow DNS server produces a primary diagnosis of slow DNS with a suggestion to switch resolvers.
- Disconnecting from the network produces a clear "no network connection" conclusion within the timeout, with downstream checks marked skipped rather than erroring.
- On a network that blocks ICMP, helpnet does not report the internet as down when TCP 443 succeeds.
- `helpnet --json` produces valid JSON matching a documented schema.
- Missing optional tools (`trip`, `librespeed-cli`) never cause errors; their blocks show as skipped with install hints.
- Works without admin/root on macOS, Linux, and Windows.
- `q` or `ctrl+c` exits within one second, terminating all subprocesses.

---

## 14. Licensing

- helpnet is released under MIT or Apache-2.0.
- Third-party CLIs (Trippy: Apache-2.0; LibreSpeed CLI: LGPL-3.0; system traceroute) are invoked as separate processes only and are never bundled or redistributed with helpnet.
- Verify the licenses of all Go dependencies are compatible before release.
