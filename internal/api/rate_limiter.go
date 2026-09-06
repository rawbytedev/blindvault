// Package api provides request handling, middleware, and rate limiting for BlindVault.
package api

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides per-IP rate limiting using a token bucket.
type RateLimiter struct {
	mu      sync.RWMutex
	limit   rate.Limit
	burst   int
	clients map[string]*LimitClient
}

type LimitClient struct {
	Client      string
	Limit       *rate.Limiter
	LastUpdated time.Time
}

// NewRateLimiter creates a rate limiter with:
//   - requestsPerMinute: max requests per minute per IP
//   - burst: max burst size (should be <= requestsPerMinute, but can be larger for spikes)
func NewRateLimiter(requestsPerMinute int, burst int) *RateLimiter {
	if requestsPerMinute == 0 && burst == 0 {
		return &RateLimiter{}
	}
	if burst < 0 {
		burst = requestsPerMinute
	}
	return &RateLimiter{
		limit:   rate.Limit(float64(requestsPerMinute) / 60.0), // per second
		burst:   burst,
		clients: make(map[string]*LimitClient),
	}
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.clients == nil {
		return true
	}
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}
	limiter, exists := rl.clients[ip]
	if !exists {
		limiter = &LimitClient{ // Allocate the struct first!
			Client:      ip,
			Limit:       rate.NewLimiter(rl.limit, rl.burst),
			LastUpdated: time.Now(),
		}
		rl.clients[ip] = limiter
	}
	limiter.LastUpdated = time.Now()
	return limiter.Limit.Allow()
}

// Cleanup removes expired limiters to prevent memory leaks.
// Call this periodically (e.g., every 10 minutes).
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for key, client := range rl.clients {
		if time.Now().Sub(client.LastUpdated) > 10*time.Minute {
			delete(rl.clients, key)
		}
	}
}
