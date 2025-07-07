package sctx

import (
	"sync"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	
	rl := NewRateLimiter(10, time.Second, shutdown, &wg)
	
	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	
	if rl.maxRequests != 10 {
		t.Errorf("maxRequests = %d, want 10", rl.maxRequests)
	}
	
	if rl.window != time.Second {
		t.Errorf("window = %v, want %v", rl.window, time.Second)
	}
	
	// Cleanup
	close(shutdown)
	wg.Wait()
}

func TestRateLimiter_Allow_FirstRequest(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(shutdown)
		wg.Wait()
	}()
	
	rl := NewRateLimiter(5, time.Second, shutdown, &wg)
	
	// First request should always be allowed
	if !rl.Allow("user1") {
		t.Error("First request should be allowed")
	}
}

func TestRateLimiter_Allow_UnderLimit(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(shutdown)
		wg.Wait()
	}()
	
	rl := NewRateLimiter(5, time.Second, shutdown, &wg)
	
	// Make 5 requests (the limit)
	for i := 0; i < 5; i++ {
		if !rl.Allow("user1") {
			t.Errorf("Request %d should be allowed (under limit)", i+1)
		}
	}
	
	// 6th request should be denied
	if rl.Allow("user1") {
		t.Error("6th request should be denied (over limit)")
	}
}

func TestRateLimiter_Allow_WindowExpiry(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(shutdown)
		wg.Wait()
	}()
	
	// Use a short window for testing
	rl := NewRateLimiter(2, 100*time.Millisecond, shutdown, &wg)
	
	// Make 2 requests (hit the limit)
	rl.Allow("user1")
	rl.Allow("user1")
	
	// 3rd request should be denied
	if rl.Allow("user1") {
		t.Error("3rd request should be denied")
	}
	
	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)
	
	// Now request should be allowed again
	if !rl.Allow("user1") {
		t.Error("Request should be allowed after window expiry")
	}
}

func TestRateLimiter_Allow_MultipleIdentities(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(shutdown)
		wg.Wait()
	}()
	
	rl := NewRateLimiter(2, time.Second, shutdown, &wg)
	
	// Each identity should have its own limit
	identities := []string{"user1", "user2", "user3"}
	
	for _, id := range identities {
		// First two requests should be allowed for each identity
		if !rl.Allow(id) {
			t.Errorf("First request for %s should be allowed", id)
		}
		if !rl.Allow(id) {
			t.Errorf("Second request for %s should be allowed", id)
		}
		// Third should be denied
		if rl.Allow(id) {
			t.Errorf("Third request for %s should be denied", id)
		}
	}
}

func TestRateLimiter_ConcurrentRequests(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(shutdown)
		wg.Wait()
	}()
	
	rl := NewRateLimiter(100, time.Second, shutdown, &wg)
	
	// Test concurrent access from multiple goroutines
	var testWg sync.WaitGroup
	allowed := make(chan bool, 200)
	
	// Launch 200 concurrent requests for the same identity
	for i := 0; i < 200; i++ {
		testWg.Add(1)
		go func() {
			defer testWg.Done()
			allowed <- rl.Allow("concurrent-user")
		}()
	}
	
	testWg.Wait()
	close(allowed)
	
	// Count allowed requests
	allowedCount := 0
	for wasAllowed := range allowed {
		if wasAllowed {
			allowedCount++
		}
	}
	
	// Should have exactly 100 allowed requests
	if allowedCount != 100 {
		t.Errorf("Expected exactly 100 allowed requests, got %d", allowedCount)
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	
	// Use very short intervals for testing
	rl := &RateLimiter{
		requests:        make(map[string]*requestTracker),
		maxRequests:     2,
		window:          50 * time.Millisecond,
		cleanupInterval: 100 * time.Millisecond,
		shutdown:        shutdown,
	}
	
	// Start cleanup goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		rl.cleanup()
	}()
	
	// Add some requests
	rl.Allow("user1")
	rl.Allow("user2")
	
	// Verify entries exist
	rl.mu.Lock()
	if len(rl.requests) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(rl.requests))
	}
	rl.mu.Unlock()
	
	// Wait for cleanup to run (window*2 + buffer)
	time.Sleep(200 * time.Millisecond)
	
	// Entries should be cleaned up
	rl.mu.Lock()
	entriesAfterCleanup := len(rl.requests)
	rl.mu.Unlock()
	
	if entriesAfterCleanup != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", entriesAfterCleanup)
	}
	
	// Shutdown
	close(shutdown)
	wg.Wait()
}

func TestRateLimiter_ShutdownGracefully(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	
	rl := NewRateLimiter(10, time.Second, shutdown, &wg)
	
	// Make some requests
	rl.Allow("user1")
	rl.Allow("user2")
	
	// Shutdown should complete without hanging
	done := make(chan bool)
	go func() {
		close(shutdown)
		wg.Wait()
		done <- true
	}()
	
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("Shutdown did not complete within 1 second")
	}
}

func TestRateLimiter_ZeroLimit(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(shutdown)
		wg.Wait()
	}()
	
	// Zero limit should block all requests after the first
	rl := NewRateLimiter(0, time.Second, shutdown, &wg)
	
	// First request creates the tracker with count=1, which is > 0, so subsequent requests fail
	// This is a quirk of the implementation where first request always succeeds
	if !rl.Allow("user1") {
		t.Error("First request is always allowed due to implementation")
	}
	
	// Second request should be denied
	if rl.Allow("user1") {
		t.Error("Second request should be denied with zero limit")
	}
}

func TestRateLimiter_EdgeCases(t *testing.T) {
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(shutdown)
		wg.Wait()
	}()
	
	rl := NewRateLimiter(5, time.Second, shutdown, &wg)
	
	// Test empty identity
	if !rl.Allow("") {
		t.Error("Empty identity should be allowed (treated as valid identity)")
	}
	
	// Test very long identity
	longIdentity := make([]byte, 1000)
	for i := range longIdentity {
		longIdentity[i] = 'a'
	}
	if !rl.Allow(string(longIdentity)) {
		t.Error("Long identity should be allowed")
	}
}