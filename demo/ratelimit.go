package main

import (
	"sync"
	"time"
)

// SimpleRateLimiter implements a basic rate limiter for demo purposes
type SimpleRateLimiter struct {
	mu           sync.Mutex
	requests     map[string][]time.Time
	maxRequests  int
	window       time.Duration
}

// NewSimpleRateLimiter creates a new rate limiter
func NewSimpleRateLimiter(maxRequests int, window time.Duration) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		requests:    make(map[string][]time.Time),
		maxRequests: maxRequests,
		window:      window,
	}
}

// Allow checks if a request should be allowed
func (r *SimpleRateLimiter) Allow(identity string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	
	// Get existing requests for this identity
	requests, exists := r.requests[identity]
	if !exists {
		r.requests[identity] = []time.Time{now}
		return true
	}

	// Remove old requests outside the window
	validRequests := []time.Time{}
	for _, t := range requests {
		if now.Sub(t) < r.window {
			validRequests = append(validRequests, t)
		}
	}

	// Check if we're at the limit
	if len(validRequests) >= r.maxRequests {
		r.requests[identity] = validRequests
		return false
	}

	// Add the new request
	validRequests = append(validRequests, now)
	r.requests[identity] = validRequests
	return true
}