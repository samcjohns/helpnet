# helpnet report

- **Date:** 2026-10-27 12:00:00 UTC
- **helpnet:** 0.1.0 (linux/amd64)
- **Interface type:** Wi-Fi
- **Target:** https://example.com
- **Duration:** 12.4s

## Conclusion

> **Likely cause: DNS lookups are slow.** Lookups via your DNS resolver (192.168.1.1) average 412 ms (first lookup 412 ms); 1.1.1.1 answered in 14 ms. Your configured DNS resolver is the bottleneck. Switch your DNS server to 1.1.1.1 or 9.9.9.9 in your OS or router settings.

## Performance rating

**83 / 100 — Good**

| Layer | Score | Weight | Based on |
|---|---:|---:|---|
| Gateway | 100 | 20 | avg latency 3.0 ms |
| Internet | 100 | 25 | avg latency 18 ms |
| DNS | 25 | 20 | avg lookup 412 ms |
| HTTP timing | 100 | 25 | TCP connect 19 ms |

## Statistics

| Layer | Target | Avg | p95 | Jitter | Loss | Status |
|---|---|---|---|---|---|---|
| Gateway | 192.168.1.1 | 3.0 ms | 3.0 ms | 0 ms | 0% | ✓ pass |
| Internet | 1.1.1.1 | 18 ms | 18 ms | 0 ms | 0% | ✓ pass |
| Internet | 8.8.8.8 | 21 ms | 21 ms | 0 ms | 0% | ✓ pass |
| DNS (system) | 192.168.1.1 | 412 ms | 412 ms | — | 0 fail | ✗ fail |
| DNS (public) | 1.1.1.1 | 14 ms | 14 ms | — | 0 fail | ✓ pass |
| DNS (public) | 9.9.9.9 | 18 ms | 18 ms | — | 0 fail | ✓ pass |
| HTTP | example.com | DNS 12 · TCP 19 · TLS 41 · TTFB 112 · total 204 ms |  |  |  | ✓ pass |
| Trace | example.com | 4 hops · 18 ms to destination · 0% loss |  |  |  | ✓ pass |

## Findings

- ✗ **DNS lookups are slow** _(fail · DNS · high confidence)_  
  Lookups via your DNS resolver (192.168.1.1) average 412 ms (first lookup 412 ms); 1.1.1.1 answered in 14 ms.  
  → Your configured DNS resolver is the bottleneck. Switch your DNS server to 1.1.1.1 or 9.9.9.9 in your OS or router settings.

## Checks

### ✓ Local interface

wlan0 · Wi-Fi · 192.168.1.42

- interface wlan0 (Wi-Fi)
- IPv4 192.168.1.42
- gateway 192.168.1.1
- DNS servers 192.168.1.1
- Wi-Fi signal 90% (-55 dBm), link rate 433 Mbps [via iw]
- no VPN detected
- no proxy configured
- took 0.1s

### ✓ Gateway

192.168.1.1 · 3.0 ms · 0% loss

- 192.168.1.1: min 3.0 ms · avg 3.0 ms · max 3.0 ms · p95 3.0 ms · jitter 0 ms · 0% loss (10/10, icmp)
-   samples (ms): 3.0 3.0 3.0 3.0 3.0 3.0 3.0 3.0 3.0 3.0
- took 0.1s

<details><summary>Raw output</summary>

```
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=3.0 ms
```

</details>

### ✓ Internet

1.1.1.1 18 ms 0% loss · 8.8.8.8 21 ms 0% loss

- 1.1.1.1: min 18 ms · avg 18 ms · max 18 ms · p95 18 ms · jitter 0 ms · 0% loss (10/10, icmp)
-   samples (ms): 18.0 18.0 18.0 18.0 18.0 18.0 18.0 18.0 18.0 18.0
- 8.8.8.8: min 21 ms · avg 21 ms · max 21 ms · p95 21 ms · jitter 0 ms · 0% loss (10/10, icmp)
-   samples (ms): 21.0 21.0 21.0 21.0 21.0 21.0 21.0 21.0 21.0 21.0
- TCP 1.1.1.1:443: 3/3 connected, avg 19 ms
- TCP 8.8.8.8:443: 3/3 connected, avg 22 ms
- captive-portal check: HTTP 204 — no portal
- took 0.1s

### ✗ DNS

system 412 ms · 1.1.1.1 14 ms · 9.9.9.9 18 ms

- domains: example.com, google.com
- system (192.168.1.1): avg 412 ms · min 412 ms · max 412 ms · first lookups 412 ms · repeats 412 ms · 0 failed · 0 NXDOMAIN · 0 AAAA answers
- 1.1.1.1: avg 14 ms · min 14 ms · max 14 ms · first lookups 14 ms · repeats 14 ms · 0 failed · 0 NXDOMAIN · 0 AAAA answers
- 9.9.9.9: avg 18 ms · min 18 ms · max 18 ms · first lookups 18 ms · repeats 18 ms · 0 failed · 0 NXDOMAIN · 0 AAAA answers
- took 0.1s

### ✓ HTTP timing

example.com · TTFB 112 ms · total 204 ms

- #1 DNS 12 ms · TCP 19 ms · TLS 41 ms · TTFB 112 ms · transfer 20 ms · total 204 ms · HTTP 200 via 93.184.215.14:443
- #2 DNS 12 ms · TCP 19 ms · TLS 41 ms · TTFB 112 ms · transfer 20 ms · total 204 ms · HTTP 200 via 93.184.215.14:443
- #3 DNS 12 ms · TCP 19 ms · TLS 41 ms · TTFB 112 ms · transfer 20 ms · total 204 ms · HTTP 200 via 93.184.215.14:443
- status 200 · HTTP/2.0 · TLS 1.3 · connected to 93.184.215.14:443 · 0 redirect(s) → https://example.com
- took 0.1s

### ✓ Route trace

4 hops via traceroute · 18 ms to destination

-  1  192.168.1.1  avg 3.0 ms  best 3.0 ms  worst 3.0 ms  loss 0%
-  2  10.0.0.1  avg 9.0 ms  best 9.0 ms  worst 9.0 ms  loss 0%
-  3  72.14.215.85  avg 15 ms  best 15 ms  worst 15 ms  loss 0%
-  4  93.184.215.14  avg 18 ms  best 18 ms  worst 18 ms  loss 0%
- took 0.1s

