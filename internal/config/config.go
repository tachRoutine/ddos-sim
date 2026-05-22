package config

import "time"

// Attack modes
const (
	ModeFlood     = "flood"
	ModeStealth   = "stealth"
	ModeRamp      = "ramp"
	ModeSlowloris = "slowloris"
)

// TestConfig holds all parameters for a load test run.
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
