package sctx

import (
	"sync"
	"time"
)

// RateLimiter provides simple rate limiting functionality
type RateLimiter struct {
	requests map[string]*requestTracker
	mu       sync.Mutex
	
	// Configuration
	maxRequests  int
	window       time.Duration
	cleanupInterval time.Duration
	
	// Shutdown
	shutdown chan struct{}
	wg       sync.WaitGroup
}

type requestTracker struct {
	count       int
	firstRequest time.Time
}

// newRateLimiter creates a new rate limiter (private)
func newRateLimiter(maxRequests int, window time.Duration, shutdown chan struct{}, wg *sync.WaitGroup) *RateLimiter {
	rl := &RateLimiter{
		requests:        make(map[string]*requestTracker),
		maxRequests:     maxRequests,
		window:          window,
		cleanupInterval: window * 2,
		shutdown:        shutdown,
	}
	
	// Start cleanup goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		rl.cleanup()
	}()
	
	return rl
}

// Allow checks if a request from the given identity should be allowed
func (rl *RateLimiter) Allow(identity string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	tracker, exists := rl.requests[identity]
	
	if !exists {
		rl.requests[identity] = &requestTracker{
			count:        1,
			firstRequest: now,
		}
		return true
	}
	
	// Check if window has expired
	if now.Sub(tracker.firstRequest) > rl.window {
		tracker.count = 1
		tracker.firstRequest = now
		return true
	}
	
	// Check if under limit
	if tracker.count < rl.maxRequests {
		tracker.count++
		return true
	}
	
	return false
}

// cleanup removes old entries to prevent memory leak
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-rl.shutdown:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for identity, tracker := range rl.requests {
				if now.Sub(tracker.firstRequest) > rl.window*2 {
					delete(rl.requests, identity)
				}
			}
			rl.mu.Unlock()
		}
	}
}