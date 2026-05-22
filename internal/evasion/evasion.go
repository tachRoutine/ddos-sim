package evasion

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"ddos-sim/internal/config"
)

// --- Header pools ---

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

var cbParams = []string{"_", "v", "t", "cb", "nc", "r"}

// TLSConfigs provides varied cipher suite configurations to mimic different browsers.
var TLSConfigs = []*tls.Config{
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

// --- Public functions ---

// RandomUA returns a random browser User-Agent string.
func RandomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// BuildRequest creates an HTTP request with randomized browser-like headers.
func BuildRequest(method, targetURL string, body io.Reader, stealth bool) (*http.Request, error) {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}

	ua := RandomUA()
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
			req.Header.Set("sec-ch-ua", `"Chromium";v="125", "Google Chrome";v="125", "Not=A?Brand";v="24"`)
			req.Header.Set("sec-ch-ua-mobile", "?0")
			req.Header.Set("sec-ch-ua-platform", `"macOS"`)
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

// CacheBustURL appends a random query parameter to bypass CDN caching.
func CacheBustURL(baseURL string) string {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	param := cbParams[rand.Intn(len(cbParams))]
	val := rand.Intn(999999)
	return fmt.Sprintf("%s%s%s=%d", baseURL, sep, param, val)
}

// PickTarget selects a random target URL from the config's path list.
func PickTarget(cfg *config.TestConfig) string {
	if len(cfg.Paths) > 0 && rand.Intn(3) > 0 {
		parsed, err := url.Parse(cfg.URL)
		if err == nil {
			path := cfg.Paths[rand.Intn(len(cfg.Paths))]
			parsed.Path = path
			return parsed.String()
		}
	}
	return cfg.URL
}
