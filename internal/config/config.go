package config

import (
	"math/rand"
	"time"
)

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
	Methods            []string
	Body               string
	InsecureSkipVerify bool
	Timeout            time.Duration
	Mode               string
	Paths              []string
}

// PickMethod returns a random method from Methods, or falls back to Method.
func (c *TestConfig) PickMethod() string {
	if len(c.Methods) > 0 {
		return c.Methods[rand.Intn(len(c.Methods))]
	}
	return c.Method
}
