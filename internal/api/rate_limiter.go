package api

import (
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter provides per-IP rate limiting using a token bucket.
type RateLimiter struct {
	mu      sync.RWMutex
	limit   rate.Limit
	burst   int
	clients map[string]*rate.Limiter
}

// NewRateLimiter creates a rate limiter with:
//   - requestsPerMinute: max requests per minute per IP
//   - burst: max burst size (should be <= requestsPerMinute, but can be larger for spikes)
func NewRateLimiter(requestsPerMinute int, burst int) *RateLimiter {
	if burst < 0 {
		burst = requestsPerMinute
	}
	return &RateLimiter{
		limit:   rate.Limit(float64(requestsPerMinute) / 60.0), // per second
		burst:   burst,
		clients: make(map[string]*rate.Limiter),
	}
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.clients[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.limit, rl.burst)
		rl.clients[ip] = limiter
	}

	return limiter.Allow()
}

// Cleanup removes expired limiters to prevent memory leaks.
// Call this periodically (e.g., every 10 minutes).
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.clients = make(map[string]*rate.Limiter)
}
