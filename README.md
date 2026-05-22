# ddos-sim

A DDoS attack simulator for stress-testing your own infrastructure's DDoS protection (Cloudflare, AWS Shield, Akamai, etc.).

---

## ⚠️ WARNING — READ BEFORE USE

> **This tool is designed exclusively for authorized security testing of infrastructure you own or have explicit written permission to test.**

- **Unauthorized use is illegal.** Launching DDoS attacks against systems you do not own or have permission to test violates the Computer Fraud and Abuse Act (CFAA) in the US, the Computer Misuse Act in the UK, and equivalent laws in virtually every jurisdiction worldwide. Penalties include **felony charges, prison time, and civil liability**.
- **You are responsible.** The authors of this tool accept zero liability for misuse. By downloading and using this software, you acknowledge full legal responsibility for how it is deployed.
- **Cloud providers will act.** Running this against unauthorized targets will trigger abuse reports. Your hosting provider, ISP, or cloud account **will be suspended or terminated**.
- **Test only what you own.** This means your own servers, your own domains, your own Cloudflare/WAF zones — with proof of ownership or a signed authorization letter from the owner.
- **Coordinate with your provider.** Even when testing your own infrastructure, notify your hosting/CDN provider beforehand. Cloudflare, AWS, and others have penetration testing policies that require advance notice.
- **Do not use on shared infrastructure** without explicit consent from all affected parties.

**Legitimate use cases:**

- Validating your Cloudflare/WAF rate-limiting rules actually work
- Stress-testing your API gateway under high load before launch
- Benchmarking your auto-scaling configuration
- Red team exercises with documented authorization

---

## Installation

```bash
git clone https://github.com/tachRoutine/ddos-sim.git
cd ddos-sim
go mod tidy
go build -o ddos-sim .
```

**Requirements:** Go 1.21+

---

## Usage

```
ddos-sim <url> [duration] [workers] [rps] [total] [mode]
```

All arguments after `url` are positional and optional. Use `0` to skip a parameter and keep its default.

| Parameter  | Description            | Default | Notes                                                         |
| ---------- | ---------------------- | ------- | ------------------------------------------------------------- |
| `url`      | Target URL (required)  | —       | Must include scheme (`https://...`)                           |
| `duration` | Test duration          | `30s`   | Go duration format: `30s`, `5m`, `1h`. `0` = run until Ctrl+C |
| `workers`  | Concurrent connections | `10`    | Each worker gets its own TLS session + cookie jar             |
| `rps`      | Max requests/sec       | `50`    | `0` = unlimited (as fast as possible)                         |
| `total`    | Total requests to send | `0`     | `0` = unlimited (run for full duration)                       |
| `mode`     | Attack mode            | `flood` | See Attack Modes below                                        |

### How arguments work together

- **Duration only:** `ddos-sim https://target.com 60s 100 0` — runs for 60 seconds
- **Total only:** `ddos-sim https://target.com 0 100 0 5000` — sends exactly 5000 requests then stops
- **Both:** `ddos-sim https://target.com 60s 100 0 5000` — stops at whichever limit is hit first
- **Neither (both 0):** runs indefinitely until you press Ctrl+C

---

## Attack Modes

| Mode        | Speed    | Stealth | Description                                                                                                                                                                                            |
| ----------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `flood`     | Maximum  | Low     | Raw speed with rotated headers and cache busting. Best for testing rate limits and basic WAF rules.                                                                                                    |
| `stealth`   | Moderate | High    | Mimics real browser traffic — human-like timing jitter (20-200ms + occasional pauses), full browser fingerprint with `sec-ch-ua`, `Sec-Fetch-*`, `DNT`. Best for testing behavioral detection.         |
| `ramp`      | Gradual  | Medium  | Starts at 10% of workers, adds a batch every 3 seconds until full capacity. Best for finding the exact threshold where protection kicks in.                                                            |
| `slowloris` | Slow     | High    | Opens raw TCP connections and sends HTTP headers one byte at a time with 3-10s delays. Exhausts server connection slots without triggering rate limits. Best for testing connection-limit protections. |

### Choosing the right mode

```
Want to test rate limiting?          → flood
Want to test behavioral detection?   → stealth
Want to find the breaking point?     → ramp
Want to test connection exhaustion?  → slowloris
```

---

## Evasion Techniques

The simulator uses multiple layers to appear as legitimate traffic:

| Technique                     | Description                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------ |
| **User-Agent rotation**       | 14 real browser strings (Chrome, Firefox, Safari, Edge, mobile)                |
| **Header randomization**      | Randomizes Accept, Accept-Language, Accept-Encoding, Referer, Cache-Control    |
| **TLS fingerprint diversity** | 3 cipher suite configurations (Chrome/Firefox/Safari-like) across workers      |
| **HTTP/2**                    | Uses H2 like real browsers (HTTP/1.1 only is a detection signal)               |
| **Cookie jar**                | Each worker accepts and resends Cloudflare cookies (`__cf_bm`, `cf_clearance`) |
| **Session warmup**            | Workers do a slow initial request to collect CF cookies before flooding        |
| **Session rotation**          | Workers create fresh TLS sessions + cookies every 500-1000 requests            |
| **Cache busting**             | Randomized query params (`?v=`, `?t=`, `?cb=`) with short natural values       |
| **Path variation**            | Hits multiple endpoints (`/`, `/api`, `/robots.txt`, `/favicon.ico`, etc.)     |
| **Adaptive throttling**       | Auto-slows when block rate rises, speeds up when it drops                      |
| **Stealth fingerprint**       | `sec-ch-ua`, `Sec-Fetch-Dest/Mode/Site/User`, `Upgrade-Insecure-Requests`      |
| **Retry with backoff**        | Transient TCP errors retried 2x with 10-20ms backoff                           |

---

## Examples

```bash
# Quick flood — 30s, 100 workers, unlimited RPS
ddos-sim https://mysite.com 30s 100 0

# Heavy flood — 3 minutes, 500 workers, no limits
ddos-sim https://mysite.com 3m 500 0

# Send exactly 10000 requests in stealth mode
ddos-sim https://mysite.com 0 50 0 10000 stealth

# Ramp up 500 workers gradually over 2 minutes
ddos-sim https://mysite.com 2m 500 0 0 ramp

# Slowloris — hold 1000 connections open for 60s
ddos-sim https://mysite.com 60s 1000 0 0 slowloris

# Rate-limited test — 200 RPS cap for 5 minutes
ddos-sim https://mysite.com 5m 100 200

# Run indefinitely until Ctrl+C, 200 workers
ddos-sim https://mysite.com 0 200 0
```

---

## Understanding the Output

### Live progress (every 5 seconds)

```
[2m5s] RPS: 7689 (avg 4584) | Total: 573050 | Blocked: 56896 | PARTIAL 10%
```

| Field       | Meaning                                              |
| ----------- | ---------------------------------------------------- |
| `[2m5s]`    | Time elapsed since test started                      |
| `RPS: 7689` | Requests sent in the last 5-second interval          |
| `avg 4584`  | Overall average RPS since start                      |
| `Total`     | Total requests sent so far                           |
| `Blocked`   | Requests that got 403/429/503 (protection triggered) |
| Status      | `OK` (<10%), `PARTIAL` (10-50%), `BLOCKED` (>50%)    |

### Adaptive throttle messages

```
[adaptive] Block rate 22% -> throttling (level 3)
[adaptive] Block rate 6% -> easing (level 0)
```

The simulator automatically slows down when getting blocked and speeds back up when blocks decrease. Levels 1-5 add increasing delays (5ms to 150ms + jitter).

### Summary

After the test completes (or you press Ctrl+C), a full summary is printed:

- **Total / Successful / Failed** — request counts and success rate percentage
- **Protection Detection** — blocked count and block rate with severity label
- **Response Times** — min, max, and average latency
- **Status Codes** — with labels: `403 (BLOCKED)`, `429 (RATE LIMITED)`, `503 (CHALLENGE/DOWN)`, `5xx (SERVER ERROR)`
- **Connection Errors** — grouped by type (e.g., `write tcp (broken pipe): 42`) instead of listing every URL
- **Requests/sec** — overall throughput and total duration

---

## System Tuning

For high worker counts (500+), you may need to raise file descriptor limits:

```bash
# Check current limit
ulimit -n

# Raise for current session
ulimit -n 65536
```

The tool auto-raises `ulimit` at startup, but the OS hard limit may cap it.

**macOS note:** Worker counts above ~2000 may cause kernel-level TCP stack issues (`invalid return from write`). For extreme concurrency, use Linux.

**Network note:** At high RPS from a single IP, your ISP or upstream router may throttle or drop packets before they even reach the target. If you see high error rates with low block rates, the bottleneck is likely your local network, not the target's protection.

---

## License

Use responsibly. This tool is provided as-is for authorized security testing only.
