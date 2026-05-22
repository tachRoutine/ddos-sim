package metrics

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// RequestResult captures the outcome of a single HTTP request.
type RequestResult struct {
	Duration   time.Duration
	StatusCode int
	Error      error
}

// Metrics collects aggregate statistics during a load test.
type Metrics struct {
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	ErrorCount         int64
	BlockedRequests    int64
	TotalResponseTime  int64
	TotalDuration      time.Duration
	MinResponseTime    time.Duration
	MaxResponseTime    time.Duration
	StatusCodes        map[int]int64
	Errors             map[string]int64
	mutex              sync.RWMutex
}

// New creates a Metrics instance with initialized maps.
func New() *Metrics {
	return &Metrics{
		StatusCodes:     make(map[int]int64),
		Errors:          make(map[string]int64),
		MinResponseTime: time.Hour,
	}
}

// classifyError maps raw error strings into short categories for aggregated display.
func classifyError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "write tcp"):
		return "write tcp (connection reset / broken pipe)"
	case strings.Contains(msg, "read tcp"):
		return "read tcp (connection reset by peer)"
	case strings.Contains(msg, "dial tcp"):
		if strings.Contains(msg, "connect: connection refused") {
			return "dial tcp (connection refused)"
		}
		if strings.Contains(msg, "i/o timeout") {
			return "dial tcp (timeout)"
		}
		return "dial tcp (connection failed)"
	case strings.Contains(msg, "context deadline exceeded"):
		return "request timeout"
	case strings.Contains(msg, "context canceled"):
		return "context canceled"
	case strings.Contains(msg, "EOF"):
		return "unexpected EOF"
	case strings.Contains(msg, "too many open files"):
		return "too many open files (fd exhaustion)"
	default:
		if len(msg) > 60 {
			return msg[:60]
		}
		return msg
	}
}

// Update records the result of a single request into aggregate metrics.
func (m *Metrics) Update(result RequestResult) {
	atomic.AddInt64(&m.TotalRequests, 1)

	if result.Error != nil {
		atomic.AddInt64(&m.FailedRequests, 1)
		atomic.AddInt64(&m.ErrorCount, 1)
	} else if result.StatusCode >= 500 {
		atomic.AddInt64(&m.FailedRequests, 1)
	} else {
		atomic.AddInt64(&m.SuccessfulRequests, 1)
	}

	if result.StatusCode == 403 || result.StatusCode == 429 || result.StatusCode == 503 {
		atomic.AddInt64(&m.BlockedRequests, 1)
	}

	atomic.AddInt64(&m.TotalResponseTime, int64(result.Duration))

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if result.Error != nil {
		errCat := classifyError(result.Error)
		m.Errors[errCat]++
	} else {
		m.StatusCodes[result.StatusCode]++
	}

	if result.Duration < m.MinResponseTime {
		m.MinResponseTime = result.Duration
	}
	if result.Duration > m.MaxResponseTime {
		m.MaxResponseTime = result.Duration
	}
}

// PrintSummary outputs the final test results to stdout.
func (m *Metrics) PrintSummary() {
	total := atomic.LoadInt64(&m.TotalRequests)
	successful := atomic.LoadInt64(&m.SuccessfulRequests)
	failed := atomic.LoadInt64(&m.FailedRequests)
	blocked := atomic.LoadInt64(&m.BlockedRequests)
	errors := atomic.LoadInt64(&m.ErrorCount)

	color.Cyan("\n======================================")
	color.Cyan("         LOAD TEST SUMMARY            ")
	color.Cyan("======================================")

	color.White("\n  Total Requests:    %d", total)
	color.Green("  Successful:        %d", successful)
	color.Red("  Failed:            %d", failed)

	if total > 0 {
		successRate := float64(successful) / float64(total) * 100
		color.Yellow("  Success Rate:      %.2f%%", successRate)
	}

	color.Cyan("\n-- Protection Detection --")
	color.Yellow("  Blocked/Challenged: %d", blocked)
	if total > 0 {
		blockRate := float64(blocked) / float64(total) * 100
		if blockRate > 50 {
			color.Red("  Block Rate:         %.2f%% -- Protection is active!", blockRate)
		} else if blockRate > 10 {
			color.Yellow("  Block Rate:         %.2f%% -- Protection partially engaged", blockRate)
		} else if blockRate > 0 {
			color.Green("  Block Rate:         %.2f%% -- Minimal blocking", blockRate)
		} else {
			color.Green("  Block Rate:         0.00%% -- No blocking detected")
		}
	}

	if errors > 0 {
		color.Red("  Connection Errors:  %d", errors)
	}

	color.Cyan("\n-- Response Times --")
	color.White("  Min: %v", m.MinResponseTime)
	color.White("  Max: %v", m.MaxResponseTime)
	if total > 0 {
		avg := time.Duration(m.TotalResponseTime / total)
		color.White("  Avg: %v", avg)
	}

	color.Cyan("\n-- Status Codes --")
	m.mutex.RLock()
	for code, count := range m.StatusCodes {
		label := ""
		switch {
		case code == 403:
			label = " (BLOCKED)"
		case code == 429:
			label = " (RATE LIMITED)"
		case code == 503:
			label = " (CHALLENGE/DOWN)"
		case code >= 500:
			label = " (SERVER ERROR)"
		}
		color.White("  %d: %d%s", code, count, label)
	}

	if len(m.Errors) > 0 {
		color.Cyan("\n-- Connection Errors --")
		for errMsg, count := range m.Errors {
			color.Red("  %s: %d", errMsg, count)
		}
	}
	m.mutex.RUnlock()

	if m.TotalDuration.Seconds() > 0 {
		rps := float64(total) / m.TotalDuration.Seconds()
		color.Yellow("\n  Requests/sec: %.2f", rps)
		color.White("  Duration:     %v", m.TotalDuration.Round(time.Millisecond))
	}
}
