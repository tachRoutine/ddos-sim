# ddos-sim

DDoS attack simulator in Go.

## Installation

```bash
git clone https://github.com/tachRoutine/ddos-sim.git
cd ddos-sim
go mod tidy
```

## Usage

```
go run main.go <target_url> [duration] [workers] [rps] [total_requests]
```

| Parameter        | Description                                          | Default |
| ---------------- | ---------------------------------------------------- | ------- |
| `target_url`     | URL to send requests to (required)                   | —       |
| `duration`       | Test duration (e.g. `30s`, `1m`, `0` for unlimited)  | `30s`   |
| `workers`        | Number of concurrent workers                         | `10`    |
| `rps`            | Max requests per second (`0` for unlimited)          | `50`    |
| `total_requests` | Total number of requests to send (`0` for unlimited) | `0`     |

## Examples

```bash
# Basic test — 30s, 10 workers, 50 RPS
go run main.go http://localhost:8080/api

# Custom duration and concurrency
go run main.go http://localhost:8080/api 1m 20 200

# Send exactly 1000 requests, no rate limit
go run main.go http://localhost:8080/api 0 10 0 1000

# Send 500 requests with a 100 RPS cap, 20 workers
go run main.go http://localhost:8080/api 30s 20 100 500
```

The test stops when whichever limit is hit first — total requests or duration.

## Output

- Live progress updates every 5 seconds
- Final summary with:
  - Total / successful / failed requests
  - Success rate
  - Min / max / avg response times
  - Status code breakdown
  - Requests per second
