# ddos-sim

DDoS attack simulator for testing your own infrastructure's DDoS protection.

## Installation

```bash
git clone https://github.com/tachRoutine/ddos-sim.git
cd ddos-sim
go mod tidy
go build -o ddos-sim .
```

## Usage

```
ddos-sim <url> [duration] [workers] [rps] [total] [mode]
```

| Parameter  | Description                                         | Default |
| ---------- | --------------------------------------------------- | ------- |
| `url`      | Target URL (required)                               | —       |
| `duration` | Test duration (e.g. `30s`, `5m`, `0` for unlimited) | `30s`   |
| `workers`  | Concurrent connections                              | `10`    |
| `rps`      | Max requests/sec (`0` for unlimited)                | `50`    |
| `total`    | Total requests to send (`0` for unlimited)          | `0`     |
| `mode`     | Attack mode                                         | `flood` |

## Attack Modes

| Mode        | Description                                                      |
| ----------- | ---------------------------------------------------------------- |
| `flood`     | Max speed with rotated user-agents, cache busting, random paths  |
| `stealth`   | Realistic browser traffic — jitter, full fingerprint, sec-fetch  |
| `ramp`      | Gradually increases workers over 30s to find the tipping point   |
| `slowloris` | Holds connections open with slow partial headers (L7 exhaustion) |

## Evasion Techniques

- Rotates through 14 real browser User-Agent strings (Chrome, Firefox, Safari, Edge, mobile)
- Randomizes Accept, Accept-Language, Accept-Encoding, Referer, Cache-Control
- Cache-busting query params to bypass CDN caching
- Hits multiple paths (`/`, `/favicon.ico`, `/robots.txt`, etc.)
- Stealth mode adds `sec-ch-ua`, `Sec-Fetch-*`, `DNT` headers matching the UA
- Forced HTTP/1.1 (one TCP connection per worker instead of multiplexed HTTP/2)

## Examples

```bash
# Quick flood — 30s, 100 workers, unlimited RPS
ddos-sim https://mysite.com 30s 100 0

# Send exactly 10000 requests in stealth mode
ddos-sim https://mysite.com 0 50 0 10000 stealth

# Ramp up 500 workers gradually over 2 minutes
ddos-sim https://mysite.com 2m 500 0 0 ramp

# Slowloris — hold 1000 connections open
ddos-sim https://mysite.com 60s 1000 0 0 slowloris

# Rate-limited test — 200 RPS cap
ddos-sim https://mysite.com 60s 100 200
```

## Output

Live progress every 5 seconds showing current RPS, total requests, blocked count, and protection status.

Summary includes:

- Total / successful / failed / blocked requests
- Protection detection (block rate with severity indicator)
- Response times (min / max / avg)
- Status codes with labels (BLOCKED, RATE LIMITED, CHALLENGE)
- Connection errors breakdown
- Overall requests/sec
