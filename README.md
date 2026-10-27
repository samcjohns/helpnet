# helpnet

**Find out why your browser is slow.** Run `helpnet` when pages hang. In a few seconds you get a layered diagnosis of *where* the problem is, *what* it probably is, and *what to do about it*.

```
  helpnet   why is my browser slow?                                                  v0.1.0

  ▌ ● Local interface    wlan0 · Wi-Fi · 192.168.1.42                                    ✓
    ● Gateway            192.168.1.1 · 3.0 ms · 0% loss                                  ✓
    ● Internet           1.1.1.1 18 ms 0% loss · 8.8.8.8 21 ms 0% loss                   ✓
    ● DNS                system 412 ms · 1.1.1.1 14 ms · 9.9.9.9 18 ms                   ✗
    ● HTTP timing        example.com · TTFB 112 ms · total 204 ms                        ✓
    ● Route trace        4 hops via traceroute · 18 ms to destination                    ✓
    ○ Bandwidth          optional · /speed to run

  ── Findings ────────────────────────────────────────────────────────────────────────────

  ✗ DNS lookups are slow  DNS · high confidence
      Lookups via your DNS resolver (192.168.1.1) average 412 ms (first lookup 412 ms);
      1.1.1.1 answered in 14 ms.
      → Your configured DNS resolver is the bottleneck. Switch your DNS server to 1.1.1.1
        or 9.9.9.9 in your OS or router settings.

  ── Summary ─────────────────────────────────────────────────────────────────────────────

    Likely cause: DNS lookups are slow. Lookups via your DNS resolver (192.168.1.1)
    average 412 ms (first lookup 412 ms); 1.1.1.1 answered in 14 ms. …

    Performance rating
    83/100 · Good
    Gateway      ████████████████████  100 weight 20 · avg latency 3.0 ms
    Internet     ████████████████████  100 weight 25 · avg latency 18 ms
    DNS          █████░░░░░░░░░░░░░░░   25 weight 20 · avg lookup 412 ms
╭──────────────────────────────────────────────────────────────────────────────────────────╮
│> type / for commands, or a URL to test                               /help · ctrl+c quit │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
 target: example.com · elapsed 6.1s · checks 6/6   trip ✗ · traceroute ✓ · librespeed-cli ✗
```

helpnet is local and private. It has no accounts and no telemetry, and the only network traffic is the probes themselves. Interpretation is a deterministic rule engine with no AI or LLM. It runs on macOS, Linux and Windows without admin rights.

## Install

```sh
go install github.com/helpnet/helpnet/cmd/helpnet@latest
```

Or download a binary from the releases page, or build from source with `make build`.

### Optional tools

helpnet works without these. When one is missing, its block shows as skipped along with an install hint.

| Tool | Used for | Install |
|---|---|---|
| [Trippy](https://trippy.rs) (`trip`) | Per-hop route trace (preferred) | `brew install trippy` · `cargo install trippy` · `winget install trippy` |
| `traceroute` / `tracert` | Route trace fallback | Ships with macOS and Windows; `apt install traceroute` on Linux |
| [`librespeed-cli`](https://github.com/librespeed/speedtest-cli) | Bandwidth test (`--speed`, `/speed`) | `brew install librespeed-cli` or a release binary |

These tools only ever run as separate processes. helpnet never bundles or redistributes them.

## Usage

```
helpnet                         # launch the TUI and run the full workflow
helpnet example.com             # use example.com as the HTTP target
helpnet --quick                 # skip route trace and bandwidth test
helpnet --speed                 # include the bandwidth test (off by default)
helpnet --no-tui                # plain streaming text output, no full-screen UI
helpnet --json                  # run non-interactively, print a JSON report
helpnet --export report.md      # run and save the report (.json → JSON)
```

| Flag | Default | Description |
|---|---|---|
| `-t, --target <url>` | `https://www.google.com` | HTTP timing target (also positional) |
| `-n, --samples <int>` | `10` | Ping samples per host |
| `--timeout <dur>` | `3s` | Per-probe timeout |
| `--quick` | off | Skip slow checks |
| `--speed` | off | Include the bandwidth test |
| `--no-tui` | off | Line-based output (automatic when stdout isn't a terminal) |
| `--json` | off | Machine-readable output; implies `--no-tui` |
| `--export <path>` | — | Write the report when the run ends |
| `--config <path>` | see below | Alternate config file |

**Exit codes:** `0` all checks passed · `1` warnings · `2` failures · `3` helpnet itself errored. Skipped optional checks don't count against the result.

### Keys

| Key | Action |
|---|---|
| `↑`/`↓` or `j`/`k` | Move between check blocks |
| `enter` / `space` | Expand/collapse the selected block (per-sample timings, details) |
| `r` | Re-run the full workflow |
| `R` | Re-run only the selected check |
| `/` | Focus the command bar |
| `s` | Jump to the final summary |
| `c` | Copy the summary to the clipboard (falls back to OSC 52 over SSH) |
| `?` | Help overlay |
| `q` / `ctrl+c` | Quit (stops all probes and subprocesses immediately) |

### Slash commands

As you type in the command bar, a popup suggests matching commands. Use `tab` to complete and `↑`/`↓` to choose. Typing a bare URL works the same as `/target <url>`.

| Command | Description |
|---|---|
| `/run` | Re-run the full workflow |
| `/quick` | Run only the fast checks |
| `/target <url>` | Change the HTTP target and re-run HTTP and trace |
| `/speed` | Run the bandwidth test now |
| `/trace [host]` | Run the per-hop route trace |
| `/dns [domain]` | Run the DNS comparison on a specific domain |
| `/export [path]` | Save the report (Markdown by default; `.json` → JSON) |
| `/details` | Toggle details and raw tool output for all blocks |
| `/help` | List commands |
| `/quit` | Exit |

## What it checks

Checks run from nearest to farthest, so the first failing layer points at the problem. If a lower layer fails hard (no network, internet unreachable), the checks that depend on it are marked **skipped** and the findings explain why.

| Layer | Check | Details |
|---|---|---|
| 0 | **Local interface** | Active interface and type (Wi-Fi/Ethernet), IPs, default gateway, DNS servers, VPN/tunnel interfaces and whether they carry the default route, proxy settings (environment and OS), and Wi-Fi signal and link rate where available |
| 1 | **Gateway** | Pings your router: min/avg/max/p95, jitter, loss. If ping gets no answer, TCP probes tell "ignores ping" apart from "down" |
| 2 | **Internet** | Pings 1.1.1.1 and 8.8.8.8, plus a TCP connect to port 443 so networks that block ICMP aren't misdiagnosed as offline, plus a captive-portal check |
| 3 | **DNS** | Resolves the target and well-known domains (A and AAAA) through your system resolver and directly through 1.1.1.1 and 9.9.9.9. Reports first (cold) and repeat lookups separately, failures and NXDOMAIN/SERVFAIL, and answers that disagree in ways a CDN wouldn't explain |
| 4 | **HTTP timing** | 3 HTTPS GETs with connection reuse off, split into DNS · TCP · TLS · time to first byte · transfer. Also records status, redirects, protocol, TLS version and connected IP, and times one request over IPv4 and one over IPv6 to catch a broken IPv6 path |
| 5 | **Route trace** | Trippy, or the OS traceroute as a fallback. Finds the hop where latency or loss starts *and persists to the destination*. Loss at a middle hop that clears up downstream is recognised as ICMP rate limiting |
| 6 | **Bandwidth** | `librespeed-cli`, only with `--speed` or `/speed` |

The default workflow (layers 0–5) usually finishes in under 10 seconds.

## How results are interpreted

A rule engine (`internal/interpret`) reasons *across* layers rather than flagging metrics one at a time. Some examples:

- **Gateway bad** → the problem is on your local network (Wi-Fi signal, interference, router). Internet slowness then counts as a knock-on effect, not a second problem.
- **Gateway fine, internet bad** → it's between your router and the internet: your modem or ISP.
- **Router drops pings to itself while traffic through it is clean** → the router is rate-limiting ICMP, which is harmless.
- **System DNS slow, public DNS fast** → your resolver is the bottleneck, so switch to 1.1.1.1 or 9.9.9.9.
- **Network and DNS fine, TTFB high** → the website is slow, not your connection.
- **TLS slow while TCP is fast** → possible TLS inspection by antivirus, a corporate proxy or a VPN.
- **IPv6 hangs while IPv4 is fast** → broken IPv6 path. This is a classic cause of browser stalls.
- **Captive portal, VPN latency, weak Wi-Fi, packet loss starting at hop N…**
- **Everything passes** → the connection is healthy. Look at the browser (extensions, cache) or the specific site using DevTools → Network.

Each finding has a severity (`info`/`warn`/`fail`), a layer, a title, the evidence (actual numbers), a suggestion, and a confidence level. Findings stream in as soon as their inputs are available. The **primary diagnosis** is the highest-severity finding at the lowest layer, and it drives the conclusion.

### Default thresholds

| Metric | Warn | Fail |
|---|---|---|
| Gateway avg latency (Wi-Fi) | > 20 ms | > 80 ms |
| Gateway avg latency (Ethernet) | > 5 ms | > 30 ms |
| Gateway / internet packet loss | > 1% | > 5% |
| Internet avg latency | > 80 ms | > 200 ms |
| Jitter (any host) | > 20 ms | > 50 ms |
| DNS avg resolution | > 100 ms | > 300 ms |
| TCP connect | > 150 ms | > 500 ms |
| TLS handshake | > 250 ms | > 800 ms |
| Time to first byte | > 600 ms | > 2000 ms |
| Download speed (if tested) | < 25 Mbps | < 5 Mbps |

### Performance rating

The overall 0–100 score is a weighted mean of per-layer scores: gateway 20, internet 25, DNS 20, HTTP 25, and bandwidth 10 when tested. Each layer scores its *worst* metric on a piecewise-linear curve: 100 up to half the warn threshold, 80 at warn, 40 at fail, and 0 at twice the fail threshold. The grades are Excellent ≥ 90, Good ≥ 75, Fair ≥ 50, Poor > 0, and Down when there is no connectivity. The summary shows the breakdown, including which metric set each layer's score, so you can always see why you got the rating. See `internal/interpret/score.go`.

## Reports

`/export` and `--export` write the conclusion, rating, statistics, all findings and per-check details, including raw tool output. Markdown is the default; a `.json` extension gives JSON. `--json` prints the same JSON to stdout.

The JSON format is documented as a JSON Schema in [`docs/report-schema.json`](docs/report-schema.json) (`"schema": "helpnet.report/v1"`), and the tests validate reports against it.

Reports contain network diagnostics only: a timestamp, OS, helpnet version, interface type and the measurements. They never include usernames or your machine's hostname, and proxy credentials are redacted.

## Configuration

helpnet needs no configuration file. To override anything, create one at:

- macOS/Linux: `~/.config/helpnet/config.toml` (or `$XDG_CONFIG_HOME/helpnet/config.toml`)
- Windows: `%APPDATA%\helpnet\config.toml`

See [`docs/config.example.toml`](docs/config.example.toml) for every setting with its default. That includes all thresholds, the hosts and resolvers used, and the UI theme (`auto`/`dark`/`light`). Set `NO_COLOR=1` to disable colour.

## Privileges

helpnet never needs root or admin, and it never asks for `sudo`. It prefers unprivileged in-process ICMP. When the OS doesn't allow that (Windows, or Linux without `net.ipv4.ping_group_range`), it falls back to the system `ping` and says so in the block's details. Trippy is tried in unprivileged mode first, and if that isn't permitted, helpnet falls back to `traceroute`.

## Development

```
cmd/helpnet/         CLI entry point, flag parsing, plain/JSON output
internal/checks/     the layered workflow; each check emits typed events and results
internal/probe/      ping, TCP, DNS, HTTP timing, traceroute/Trippy, LibreSpeed (+ parsers)
internal/sysinfo/    interface, gateway, VPN, proxy, Wi-Fi detection (per-OS build tags)
internal/interpret/  pure rules engine, primary diagnosis, scoring
internal/report/     summary model; Markdown, JSON and text renderers
internal/session/    runs checks and streams results + findings to any frontend
internal/tui/        Bubble Tea interface
internal/config/     config loading and defaults
```

Checks don't depend on any UI. The TUI, `--no-tui` and `--json` all consume the same event stream from `internal/session`. `interpret.Analyze(results, thresholds)` does no I/O.

```sh
make test        # unit, parser, snapshot and localhost integration tests
make race        # same with the race detector
make snapshots   # regenerate golden report files after an intentional change
make demo        # drive the TUI model against the real network and print frames
```

The integration tests run the full workflow against a local TLS server, local DNS servers and a captive-portal stub, so CI never needs the internet. CI runs on Linux, macOS and Windows.

## License

MIT; see [LICENSE](LICENSE). All linked Go dependencies are MIT or BSD-3-Clause licensed. Trippy (Apache-2.0), LibreSpeed CLI (LGPL-3.0) and the system traceroute are invoked as separate processes only.
