package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"golang.org/x/time/rate"
)

type TestConfig struct {
	URL                string
	Duration           time.Duration
	ConcurrentWorkers  int
	RequestsPerSecond  int
	TotalRequests      int64
	Method             string
	Headers            map[string]string
	Body               string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

type Metrics struct {
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	ErrorCount         int64
	TotalResponseTime  int64 // nanoseconds, sum of all response durations
	TotalDuration      time.Duration
	MinResponseTime    time.Duration
	MaxResponseTime    time.Duration
	StatusCodes        map[int]int64
	Errors             map[string]int64
	mutex              sync.RWMutex
}

type RequestResult struct {
	Duration   time.Duration
	StatusCode int
	Error      error
}

func NewMetrics() *Metrics {
	return &Metrics{
		StatusCodes:     make(map[int]int64),
		Errors:          make(map[string]int64),
		MinResponseTime: time.Hour,
	}
}

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

	atomic.AddInt64(&m.TotalResponseTime, int64(result.Duration))

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if result.Error != nil {
		m.Errors[result.Error.Error()]++
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

func (m *Metrics) PrintSummary() {
	color.Cyan("\n=== LOAD TEST SUMMARY ===")
	color.Green("Total Requests: %d", m.TotalRequests)
	color.Green("Successful: %d", m.SuccessfulRequests)
	color.Red("Failed: %d", m.FailedRequests)

	successRate := float64(m.SuccessfulRequests) / float64(m.TotalRequests) * 100
	color.Yellow("Success Rate: %.2f%%", successRate)

	color.Cyan("\nResponse Times:")
	color.White("Min: %v", m.MinResponseTime)
	color.White("Max: %v", m.MaxResponseTime)
	avg := time.Duration(m.TotalResponseTime / m.TotalRequests)
	color.White("Avg: %v", avg)

	color.Cyan("\nStatus Codes:")
	for code, count := range m.StatusCodes {
		color.White("  %d: %d", code, count)
	}

	if len(m.Errors) > 0 {
		color.Cyan("\nConnection Errors: %d", m.ErrorCount)
		for errMsg, count := range m.Errors {
			if len(errMsg) > 80 {
				errMsg = errMsg[:80] + "..."
			}
			color.Red("  %s: %d", errMsg, count)
		}
	}

	rps := float64(m.TotalRequests) / m.TotalDuration.Seconds()
	color.Yellow("\nRequests per Second: %.2f", rps)
}

type DynamicPayload struct {
	UserID    int    `json:"user_id"`
	Timestamp int64  `json:"timestamp"`
	Data      string `json:"data"`
	Sequence  int    `json:"sequence"`
}

func generateDynamicPayload(seq int) string {
	payload := DynamicPayload{
		UserID:    rand.Intn(10000) + 1,
		Timestamp: time.Now().UnixNano(),
		Data:      fmt.Sprintf("test_data_%d_%d", seq, rand.Intn(1000)),
		Sequence:  seq,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return `{"default": "payload"}`
	}
	return string(data)
}

func makeRequest(client *http.Client, config *TestConfig, sequence int) RequestResult {
	start := time.Now()

	var body io.Reader
	if config.Method != "GET" && config.Body != "" {
		if config.Body == "dynamic" {
			dynamicBody := generateDynamicPayload(sequence)
			body = bytes.NewBufferString(dynamicBody)
		} else {
			body = bytes.NewBufferString(config.Body)
		}
	}

	req, err := http.NewRequest(config.Method, config.URL, body)
	if err != nil {
		return RequestResult{Duration: time.Since(start), Error: err}
	}

	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return RequestResult{Duration: time.Since(start), Error: err}
	}
	io.CopyN(io.Discard, resp.Body, 8192)
	resp.Body.Close()

	return RequestResult{
		Duration:   time.Since(start),
		StatusCode: resp.StatusCode,
	}
}

func worker(id int, config *TestConfig, metrics *Metrics, wg *sync.WaitGroup,
	ctx context.Context, rateLimiter *rate.Limiter, requestCounter *int64, client *http.Client) {
	defer wg.Done()

	sequence := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Check total request limit
			if config.TotalRequests > 0 {
				current := atomic.AddInt64(requestCounter, 1)
				if current > config.TotalRequests {
					return
				}
			}

			if rateLimiter != nil {
				rateLimiter.Wait(ctx)
			}

			sequence++
			result := makeRequest(client, config, sequence)
			metrics.Update(result)

			if id < 5 && sequence%1000 == 0 {
				color.Magenta("Worker %d: Completed %d requests", id, sequence)
			}
		}
	}
}

func startLoadTest(config *TestConfig) {
	color.Yellow("Starting advanced load test...")
	color.White("Target: %s", config.URL)
	if config.TotalRequests > 0 {
		color.White("Total Requests: %d", config.TotalRequests)
	}
	color.White("Duration: %v", config.Duration)
	color.White("Concurrent Workers: %d", config.ConcurrentWorkers)
	color.White("Rate Limit: %d RPS", config.RequestsPerSecond)

	metrics := NewMetrics()
	var wg sync.WaitGroup
	var requestCounter int64

	ctx, cancel := context.WithTimeout(context.Background(), config.Duration)
	defer cancel()

	// Rate limiting
	var rateLimiter *rate.Limiter
	if config.RequestsPerSecond > 0 {
		burst := config.RequestsPerSecond
		if burst > 1000 {
			burst = 1000
		}
		rateLimiter = rate.NewLimiter(rate.Limit(config.RequestsPerSecond), burst)
	}

	// Shared transport and client for all workers
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
		MaxIdleConns:        config.ConcurrentWorkers + 10,
		MaxIdleConnsPerHost: config.ConcurrentWorkers + 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		WriteBufferSize:     4096,
		ReadBufferSize:      4096,
	}
	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	startTime := time.Now()

	// Start workers
	for i := 0; i < config.ConcurrentWorkers; i++ {
		wg.Add(1)
		go worker(i, config, metrics, &wg, ctx, rateLimiter, &requestCounter, client)
	}

	// Progress monitoring
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				currentRPS := float64(atomic.LoadInt64(&metrics.TotalRequests)) / time.Since(startTime).Seconds()
				color.Cyan("Current RPS: %.2f, Total Requests: %d", currentRPS, atomic.LoadInt64(&metrics.TotalRequests))
			case <-done:
				return
			}
		}
	}()

	// Wait for completion
	wg.Wait()
	close(done)
	cancel()
	metrics.TotalDuration = time.Since(startTime)

	metrics.PrintSummary()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <target_url> [duration] [workers] [rps] [total_requests]")
		fmt.Println("Example: go run main.go http://localhost:8080/api 30s 10 100")
		fmt.Println("Example: go run main.go http://localhost:8080/api 0 10 0 1000  # send exactly 1000 requests")
		return
	}

	url := os.Args[1]

	// Default configuration with overrides from command line
	config := &TestConfig{
		URL:               url,
		Duration:          30 * time.Second,
		ConcurrentWorkers: 10,
		RequestsPerSecond: 50,
		Method:            "GET",
		Headers: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Apple silcon Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Connection":      "keep-alive",
		},
		Body:               "dynamic", // Use "dynamic" for generated payloads
		InsecureSkipVerify: true,
		Timeout:            10 * time.Second,
	}

	if len(os.Args) > 2 {
		if duration, err := time.ParseDuration(os.Args[2]); err == nil {
			config.Duration = duration
		}
	}

	if len(os.Args) > 3 {
		if workers, err := strconv.Atoi(os.Args[3]); err == nil {
			config.ConcurrentWorkers = workers
		}
	}

	if len(os.Args) > 4 {
		if rps, err := strconv.Atoi(os.Args[4]); err == nil {
			config.RequestsPerSecond = rps
		}
	}

	if len(os.Args) > 5 {
		if total, err := strconv.ParseInt(os.Args[5], 10, 64); err == nil {
			config.TotalRequests = total
		}
	}

	// If total requests is set but duration is 0, use a very long duration as fallback
	if config.TotalRequests > 0 && config.Duration == 0 {
		config.Duration = 24 * time.Hour
	}

	// Safety checks
	if config.ConcurrentWorkers > 1000 {
		color.Red("Warning: High concurrency may impact system performance")
	}

	if config.RequestsPerSecond > 1000 {
		color.Red("Warning: High request rate may overwhelm target system")
	}

	// Confirm before starting
	color.Yellow("\nPress Enter to start load test or Ctrl+C to cancel...")
	fmt.Scanln()

	startLoadTest(config)
}
