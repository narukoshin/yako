package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a sliding-window rate limiter per IP.
// Each IP gets a fixed number of requests per time window. Exceed it and you wait —
// I'm not that easy.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
	cleanup  time.Duration
	stop     chan struct{}
}

// NewRateLimiter creates a rate limiter that allows `limit` requests per `window` duration per IP.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		cleanup:  time.Minute,
		stop:     make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Stop shuts down the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stop)
}

// Allow checks if an IP has remaining capacity in the current window.
// Returns false and sets Retry-After header via [Middleware] when rate-limited.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	entries := rl.attempts[ip]
	var filtered []time.Time
	for _, t := range entries {
		if t.After(windowStart) {
			filtered = append(filtered, t)
		}
	}

	if len(filtered) >= rl.limit {
		rl.attempts[ip] = filtered
		return false
	}

	filtered = append(filtered, now)
	rl.attempts[ip] = filtered
	return true
}

// cleanupLoop periodically purges expired entries from the rate limiter map.
//
//	Runs every minute in the background until [RateLimiter.Stop] is called.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.window)
			for ip, entries := range rl.attempts {
				var filtered []time.Time
				for _, t := range entries {
					if t.After(cutoff) {
						filtered = append(filtered, t)
					}
				}
				if len(filtered) == 0 {
					delete(rl.attempts, ip)
				} else {
					rl.attempts[ip] = filtered
				}
			}
			rl.mu.Unlock()
		case <-rl.stop:
			return
		}
	}
}

// Middleware wraps an HTTP handler with rate limiting. Returns 429 with Retry-After
// when the client exceeds the limit — patience is a virtue, but I'll enforce it.
func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next(w, r)
	}
}
