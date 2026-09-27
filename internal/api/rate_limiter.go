// Package api provides request handling, middleware, and rate limiting for BlindVault.
package api

import (
	"net"
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
	// cap maximum number of tracked clients to prevent unbounded memory growth
	maxClients int
}

type LimitClient struct {
	Client      string
	Limit       *rate.Limiter
	LastUpdated time.Time
}

// NewRateLimiter creates a rate limiter with:
//   - requestsPerMinute: max requests per minute per IP
//   - burst: max burst size (should be <= requestsPerMinute, but can be larger for spikes)
func NewRateLimiter(requestsPerMinute int, burst int, maxClients int) *RateLimiter {
	if requestsPerMinute == 0 && burst == 0 {
		return &RateLimiter{}
	}
	if burst < 0 {
		burst = requestsPerMinute
	}
	return &RateLimiter{
		limit:      rate.Limit(float64(requestsPerMinute) / 60.0), // per second
		burst:      burst,
		clients:    make(map[string]*LimitClient),
		maxClients: maxClients,
	}
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.clients == nil {
		return true
	}
	// Normalize host:strip port if present using SplitHostPort
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	limiter, exists := rl.clients[ip]
	if !exists {
		// If we've reached max clients, evict the oldest entry
		if rl.maxClients > 0 && len(rl.clients) >= rl.maxClients {
			var oldestKey string
			var oldest time.Time = time.Now()
			for k, c := range rl.clients {
				if c.LastUpdated.Before(oldest) {
					oldest = c.LastUpdated
					oldestKey = k
				}
			}
			if oldestKey != "" {
				delete(rl.clients, oldestKey)
			}
		}
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
		if time.Since(client.LastUpdated) > 10*time.Minute {
			delete(rl.clients, key)
		}
	}
}
