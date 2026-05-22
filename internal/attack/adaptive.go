package attack

import (
	"math/rand"
	"sync/atomic"
	"time"

	"ddos-sim/internal/metrics"

	"github.com/fatih/color"
)

// AdaptiveController monitors block rate and automatically adjusts throughput.
type AdaptiveController struct {
	throttleFactor int64 // 0 = full speed, 1-5 = increasingly throttled
	lastBlockRate  float64
}

// GetDelay returns the current throttle delay based on block rate.
func (a *AdaptiveController) GetDelay() time.Duration {
	f := atomic.LoadInt64(&a.throttleFactor)
	if f <= 0 {
		return 0
	}
	delays := []time.Duration{5, 15, 40, 80, 150}
	idx := int(f) - 1
	if idx >= len(delays) {
		idx = len(delays) - 1
	}
	base := delays[idx] * time.Millisecond
	jitter := time.Duration(rand.Intn(int(base/2) + 1))
	return base + jitter
}

// Update recalculates the throttle level from current metrics.
func (a *AdaptiveController) Update(m *metrics.Metrics) {
	total := atomic.LoadInt64(&m.TotalRequests)
	blocked := atomic.LoadInt64(&m.BlockedRequests)
	if total < 100 {
		return
	}
	blockRate := float64(blocked) / float64(total) * 100

	var newFactor int64
	switch {
	case blockRate > 60:
		newFactor = 5
	case blockRate > 40:
		newFactor = 4
	case blockRate > 25:
		newFactor = 3
	case blockRate > 15:
		newFactor = 2
	case blockRate > 8:
		newFactor = 1
	default:
		newFactor = 0
	}

	old := atomic.LoadInt64(&a.throttleFactor)
	if newFactor != old {
		atomic.StoreInt64(&a.throttleFactor, newFactor)
		if newFactor > old {
			color.Yellow("  [adaptive] Block rate %.0f%% -> throttling (level %d)", blockRate, newFactor)
		} else {
			color.Green("  [adaptive] Block rate %.0f%% -> easing (level %d)", blockRate, newFactor)
		}
	}
	a.lastBlockRate = blockRate
}
