package attack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"

	"ddos-sim/internal/config"
	"ddos-sim/internal/evasion"
	"ddos-sim/internal/metrics"

	"net/http"
)

// DynamicPayload is a randomized JSON body for POST requests.
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

// MakeRequest sends a single HTTP request with evasion, retrying on transient errors.
func MakeRequest(client *http.Client, cfg *config.TestConfig, sequence int) metrics.RequestResult {
	const maxRetries = 2
	stealth := cfg.Mode == config.ModeStealth

	for attempt := 0; attempt <= maxRetries; attempt++ {
		start := time.Now()

		targetURL := evasion.PickTarget(cfg)
		if cfg.Method == "GET" {
			targetURL = evasion.CacheBustURL(targetURL)
		}

		var body io.Reader
		if cfg.Method != "GET" && cfg.Body != "" {
			if cfg.Body == "dynamic" {
				body = bytes.NewBufferString(generateDynamicPayload(sequence))
			} else {
				body = bytes.NewBufferString(cfg.Body)
			}
		}

		req, err := evasion.BuildRequest(cfg.Method, targetURL, body, stealth)
		if err != nil {
			return metrics.RequestResult{Duration: time.Since(start), Error: err}
		}

		resp, err := client.Do(req)
		if err != nil {
			if attempt < maxRetries && isRetryable(err) {
				time.Sleep(time.Duration(10*(attempt+1)) * time.Millisecond)
				continue
			}
			return metrics.RequestResult{Duration: time.Since(start), Error: err}
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		return metrics.RequestResult{
			Duration:   time.Since(start),
			StatusCode: resp.StatusCode,
		}
	}

	return metrics.RequestResult{Error: fmt.Errorf("max retries exceeded")}
}
