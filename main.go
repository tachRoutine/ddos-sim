package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ddos-sim/internal/attack"
	"ddos-sim/internal/config"

	"github.com/fatih/color"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	cfg := &config.TestConfig{
		URL:                os.Args[1],
		Duration:           30 * time.Second,
		ConcurrentWorkers:  10,
		RequestsPerSecond:  50,
		Method:             "GET",
		Body:               "dynamic",
		InsecureSkipVerify: true,
		Timeout:            10 * time.Second,
		Mode:               config.ModeFlood,
		Methods:            []string{"GET", "GET", "GET", "HEAD", "OPTIONS"},
		Paths: []string{
			"/", "/", "/",
			"/favicon.ico",
			"/robots.txt",
			"/sitemap.xml",
			"/api",
			"/api/v1",
			"/api/v2",
			"/api/v1/users",
			"/api/v1/products",
			"/api/v1/orders",
			"/api/v1/search",
			"/api/v1/auth/login",
			"/api/v1/auth/register",
			"/api/v1/health",
			"/api/v1/status",
			"/health",
			"/healthz",
			"/ready",
			"/metrics",
			"/graphql",
			"/ws",
			"/webhook",
			"/.well-known/security.txt",
			"/.well-known/openid-configuration",
			"/swagger.json",
			"/openapi.json",
			"/docs",
		},
	}

	if len(os.Args) > 2 {
		if d, err := time.ParseDuration(os.Args[2]); err == nil {
			cfg.Duration = d
		}
	}
	if len(os.Args) > 3 {
		if w, err := strconv.Atoi(os.Args[3]); err == nil {
			cfg.ConcurrentWorkers = w
		}
	}
	if len(os.Args) > 4 {
		if r, err := strconv.Atoi(os.Args[4]); err == nil {
			cfg.RequestsPerSecond = r
		}
	}
	if len(os.Args) > 5 {
		if t, err := strconv.ParseInt(os.Args[5], 10, 64); err == nil {
			cfg.TotalRequests = t
		}
	}
	if len(os.Args) > 6 {
		mode := strings.ToLower(os.Args[6])
		switch mode {
		case config.ModeFlood, config.ModeStealth, config.ModeRamp, config.ModeSlowloris:
			cfg.Mode = mode
		default:
			color.Red("Unknown mode: %s. Using flood.", mode)
		}
	}

	if cfg.Duration == 0 {
		cfg.Duration = 24 * time.Hour
	}

	raiseFileDescriptorLimit(cfg.ConcurrentWorkers)

	if cfg.ConcurrentWorkers > 5000 {
		color.Red("  Warning: Very high concurrency may crash your system")
	}

	// Trap Ctrl+C for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		color.Yellow("\n  Caught interrupt, shutting down gracefully...")
		cancel()
	}()

	color.Yellow("\n  Press Enter to start or Ctrl+C to cancel...")
	fmt.Scanln()

	attack.StartLoadTest(ctx, cfg)
}

func raiseFileDescriptorLimit(workers int) {
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		needed := uint64(workers*2 + 100)
		if rlimit.Cur < needed {
			rlimit.Cur = min(needed, rlimit.Max)
			if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
				color.Red("  Warning: File descriptor limit too low. Run: ulimit -n %d", needed)
			} else {
				color.Green("  Raised file descriptor limit to %d", rlimit.Cur)
			}
		}
	}
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
