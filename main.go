package main

import (
    "bytes"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "math/rand"
    "net/http"
    "sync"
    "sync/atomic"
    "time"
    "os"
    "strconv"
    "context"
    
    "github.com/fatih/color"
    "golang.org/x/time/rate"
)

type TestConfig struct {
    URL                string
    Duration           time.Duration
    ConcurrentWorkers  int
    RequestsPerSecond  int
    Method             string
    Headers            map[string]string
    Body               string
    EnableTLS          bool
    InsecureSkipVerify bool
    Timeout            time.Duration
}

type Metrics struct {
    TotalRequests      int64
    SuccessfulRequests int64
    FailedRequests     int64
    TotalDuration      time.Duration
    MinResponseTime    time.Duration
    MaxResponseTime    time.Duration
    StatusCodes        map[int]int64
    mutex              sync.RWMutex
}

type RequestResult struct {
    Duration   time.Duration
    StatusCode int
    Error      error
}

func NewMetrics() *Metrics {
    return &Metrics{
        StatusCodes: make(map[int]int64),
        MinResponseTime: time.Hour,
    }
}

func (m *Metrics) Update(result RequestResult) {
    atomic.AddInt64(&m.TotalRequests, 1)
    
    if result.Error != nil || result.StatusCode >= 400 {
        atomic.AddInt64(&m.FailedRequests, 1)
    } else {
        atomic.AddInt64(&m.SuccessfulRequests, 1)
    }
    
    m.mutex.Lock()
    defer m.mutex.Unlock()
    
    m.StatusCodes[result.StatusCode]++
    
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
    avg := time.Duration(float64(m.TotalDuration) / float64(m.TotalRequests))
    color.White("Avg: %v", avg)
    
    color.Cyan("\nStatus Codes:")
    for code, count := range m.StatusCodes {
        color.White("  %d: %d", code, count)
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
    if config.Body != "" {
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
    defer resp.Body.Close()
    
    io.Copy(io.Discard, resp.Body)
    
    return RequestResult{
        Duration:   time.Since(start),
        StatusCode: resp.StatusCode,
    }
}

func worker(id int, config *TestConfig, metrics *Metrics, wg *sync.WaitGroup, 
    ctx context.Context, rateLimiter *rate.Limiter) {
    defer wg.Done()
    
    client := &http.Client{
        Timeout: config.Timeout,
    }
    
    if config.EnableTLS {
        client.Transport = &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: config.InsecureSkipVerify,
            },
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 100,
            IdleConnTimeout:     90 * time.Second,
        }
    }
    
    sequence := 0
    
    for {
        select {
        case <-ctx.Done():
            return
        default:
            if rateLimiter != nil {
                rateLimiter.Wait(ctx)
            }
            
            sequence++
            result := makeRequest(client, config, sequence)
            metrics.Update(result)
            
            if id < 5 && sequence%100 == 0 {
                color.Magenta("Worker %d: Completed %d requests", id, sequence)
            }
        }
    }
}

func startLoadTest(config *TestConfig) {
    color.Yellow("Starting advanced load test...")
    color.White("Target: %s", config.URL)
    color.White("Duration: %v", config.Duration)
    color.White("Concurrent Workers: %d", config.ConcurrentWorkers)
    color.White("Rate Limit: %d RPS", config.RequestsPerSecond)
    
    metrics := NewMetrics()
    var wg sync.WaitGroup
    
    ctx, cancel := context.WithTimeout(context.Background(), config.Duration)
    defer cancel()
    
    // Rate limiting
    var rateLimiter *rate.Limiter
    if config.RequestsPerSecond > 0 {
        rateLimiter = rate.NewLimiter(rate.Limit(config.RequestsPerSecond), config.RequestsPerSecond)
    }
    
    startTime := time.Now()
    
    // Start workers
    for i := 0; i < config.ConcurrentWorkers; i++ {
        wg.Add(1)
        go worker(i, config, metrics, &wg, ctx, rateLimiter)
    }
    
    // Progress monitoring
    go func() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                currentRPS := float64(atomic.LoadInt64(&metrics.TotalRequests)) / time.Since(startTime).Seconds()
                color.Cyan("Current RPS: %.2f, Total Requests: %d", currentRPS, atomic.LoadInt64(&metrics.TotalRequests))
            case <-ctx.Done():
                return
            }
        }
    }()
    
    // Wait for completion
    wg.Wait()
    metrics.TotalDuration = time.Since(startTime)
    
    metrics.PrintSummary()
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: go run load_test.go <target_url> [duration] [workers] [rps]")
        fmt.Println("Example: go run load_test.go http://localhost:8080/api 30s 10 100")
        return
    }
    
    url := os.Args[1]
    
    // Default configuration with overrides from command line
    config := &TestConfig{
        URL:               url,
        Duration:          30 * time.Second,
        ConcurrentWorkers: 10,
        RequestsPerSecond: 50,
        Method:           "GET",
        Headers: map[string]string{
            "User-Agent": "AdvancedLoadTester/1.0",
            "Content-Type": "application/json",
        },
        Body:               "dynamic", // Use "dynamic" for generated payloads
        EnableTLS:          false,
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
    
    // Advanced configuration options
    config.Headers["X-Load-Test"] = "true"
    config.Headers["X-Request-ID"] = fmt.Sprintf("test-%d", time.Now().Unix())
    
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