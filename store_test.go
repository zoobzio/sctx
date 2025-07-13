package sctx

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test helper to create a sample active token
func createSampleToken(fingerprint, identity string, expiresAt time.Time) *activeToken {
	return &activeToken{
		ContextID:              "test-ctx-" + identity,
		CertificateFingerprint: fingerprint,
		IssuedAt:               time.Now().Add(-5 * time.Minute),
		ExpiresAt:              expiresAt,
		Identity:               identity,
		Permissions:            []string{"read", "write"},
		FactoryID:              "",
		RefreshCount:           0,
		SignedContext:          Context("signed-context-data"),
	}
}

func TestNewMemoryTokenStore(t *testing.T) {
	tests := []struct {
		name                    string
		cleanupInterval         time.Duration
		expectedCleanupInterval time.Duration
	}{
		{
			name:                    "with custom interval",
			cleanupInterval:         10 * time.Second,
			expectedCleanupInterval: 10 * time.Second,
		},
		{
			name:                    "with zero interval - should use default",
			cleanupInterval:         0,
			expectedCleanupInterval: 5 * time.Minute,
		},
		{
			name:                    "with negative interval - kept as-is",
			cleanupInterval:         -1 * time.Second,
			expectedCleanupInterval: -1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMemoryTokenStore(tt.cleanupInterval)
			if store == nil {
				t.Fatal("newMemoryTokenStore returned nil")
			}

			// Check that it implements TokenStore interface
			var _ TokenStore = store

			// Test initial state
			memStore := store.(*memoryTokenStore)
			if memStore.cleanupInterval != tt.expectedCleanupInterval {
				t.Errorf("Expected cleanup interval %v, got %v", tt.expectedCleanupInterval, memStore.cleanupInterval)
			}

			if memStore.Count() != 0 {
				t.Errorf("Expected 0 tokens in new store, got %d", memStore.Count())
			}
		})
	}
}

func TestMemoryTokenStore_SetAndGet(t *testing.T) {
	store := newMemoryTokenStore(time.Minute)
	fingerprint := "test-fingerprint"
	token := createSampleToken(fingerprint, "test-user", time.Now().Add(time.Hour))

	// Initially should not exist
	_, exists := store.Get(fingerprint)
	if exists {
		t.Error("Token should not exist initially")
	}

	// Set the token
	err := store.Set(fingerprint, token)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should now exist
	retrieved, exists := store.Get(fingerprint)
	if !exists {
		t.Error("Token should exist after Set")
	}

	if retrieved == nil {
		t.Fatal("Retrieved token is nil")
	}

	// Verify token fields
	if retrieved.ContextID != token.ContextID {
		t.Errorf("Expected ContextID %s, got %s", token.ContextID, retrieved.ContextID)
	}

	if retrieved.Identity != token.Identity {
		t.Errorf("Expected Identity %s, got %s", token.Identity, retrieved.Identity)
	}

	if retrieved.CertificateFingerprint != fingerprint {
		t.Errorf("Expected fingerprint %s, got %s", fingerprint, retrieved.CertificateFingerprint)
	}

	// Test overwriting existing token
	newToken := createSampleToken(fingerprint, "updated-user", time.Now().Add(2*time.Hour))
	err = store.Set(fingerprint, newToken)
	if err != nil {
		t.Fatalf("Set update failed: %v", err)
	}

	updated, exists := store.Get(fingerprint)
	if !exists {
		t.Error("Updated token should exist")
	}

	if updated.Identity != "updated-user" {
		t.Errorf("Expected updated identity 'updated-user', got %s", updated.Identity)
	}
}

func TestMemoryTokenStore_Delete(t *testing.T) {
	store := newMemoryTokenStore(time.Minute)
	fingerprint := "delete-test"
	token := createSampleToken(fingerprint, "test-user", time.Now().Add(time.Hour))

	// Delete non-existent token (should not error)
	err := store.Delete(fingerprint)
	if err != nil {
		t.Errorf("Delete of non-existent token failed: %v", err)
	}

	// Add token
	store.Set(fingerprint, token)

	// Verify it exists
	_, exists := store.Get(fingerprint)
	if !exists {
		t.Error("Token should exist before delete")
	}

	// Delete it
	err = store.Delete(fingerprint)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	_, exists = store.Get(fingerprint)
	if exists {
		t.Error("Token should not exist after delete")
	}
}

func TestMemoryTokenStore_Count(t *testing.T) {
	store := newMemoryTokenStore(time.Minute)
	memStore := store.(*memoryTokenStore)

	// Initially empty
	if memStore.Count() != 0 {
		t.Errorf("Expected count 0, got %d", memStore.Count())
	}

	// Add tokens
	tokens := []struct {
		fingerprint string
		identity    string
	}{
		{"fp1", "user1"},
		{"fp2", "user2"},
		{"fp3", "user3"},
	}

	for i, token := range tokens {
		store.Set(token.fingerprint, createSampleToken(token.fingerprint, token.identity, time.Now().Add(time.Hour)))
		
		expectedCount := i + 1
		if memStore.Count() != expectedCount {
			t.Errorf("After adding token %d, expected count %d, got %d", i+1, expectedCount, memStore.Count())
		}
	}

	// Delete tokens
	for i, token := range tokens {
		store.Delete(token.fingerprint)
		
		expectedCount := len(tokens) - i - 1
		if memStore.Count() != expectedCount {
			t.Errorf("After deleting token %d, expected count %d, got %d", i+1, expectedCount, memStore.Count())
		}
	}
}

func TestMemoryTokenStore_MultipleFingerprintsOneUser(t *testing.T) {
	store := newMemoryTokenStore(time.Minute)
	identity := "multi-cert-user"

	// Same user with multiple certificates/fingerprints
	fingerprints := []string{"cert1-fp", "cert2-fp", "cert3-fp"}

	for _, fp := range fingerprints {
		token := createSampleToken(fp, identity, time.Now().Add(time.Hour))
		store.Set(fp, token)
	}

	// All should be stored separately
	memStore := store.(*memoryTokenStore)
	if memStore.Count() != len(fingerprints) {
		t.Errorf("Expected %d tokens, got %d", len(fingerprints), memStore.Count())
	}

	// Each should be retrievable by its fingerprint
	for _, fp := range fingerprints {
		token, exists := store.Get(fp)
		if !exists {
			t.Errorf("Token with fingerprint %s should exist", fp)
		}
		if token.Identity != identity {
			t.Errorf("Expected identity %s, got %s", identity, token.Identity)
		}
		if token.CertificateFingerprint != fp {
			t.Errorf("Expected fingerprint %s, got %s", fp, token.CertificateFingerprint)
		}
	}
}

func TestMemoryTokenStore_CleanupExpiredTokens(t *testing.T) {
	// Use shorter cleanup interval for faster testing
	cleanupInterval := 50 * time.Millisecond
	store := newMemoryTokenStore(cleanupInterval)
	memStore := store.(*memoryTokenStore)

	// Create tokens with different expiration times
	now := time.Now()
	tokens := []struct {
		fingerprint string
		expiresAt   time.Time
		shouldExist bool
	}{
		{"expired1", now.Add(-1 * time.Hour), false},      // Already expired
		{"expired2", now.Add(-1 * time.Minute), false},   // Already expired
		{"valid1", now.Add(1 * time.Hour), true},         // Valid for 1 hour
		{"valid2", now.Add(1 * time.Minute), true},       // Valid for 1 minute
		{"expiring", now.Add(10 * time.Millisecond), false}, // Will expire soon
	}

	// Add all tokens
	for _, token := range tokens {
		activeToken := createSampleToken(token.fingerprint, "user", token.expiresAt)
		store.Set(token.fingerprint, activeToken)
	}

	// Should have all tokens initially
	if memStore.Count() != len(tokens) {
		t.Errorf("Expected %d tokens initially, got %d", len(tokens), memStore.Count())
	}

	// Start cleanup
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	store.Start(shutdown, &wg)

	// Wait for cleanup to run (longer than cleanup interval and expiring token time)
	time.Sleep(200 * time.Millisecond)

	// Check which tokens still exist
	for _, token := range tokens {
		_, exists := store.Get(token.fingerprint)
		if exists != token.shouldExist {
			t.Errorf("Token %s: expected exists=%v, got exists=%v", token.fingerprint, token.shouldExist, exists)
		}
	}

	// Should only have valid tokens remaining
	expectedRemaining := 0
	for _, token := range tokens {
		if token.shouldExist {
			expectedRemaining++
		}
	}

	if memStore.Count() != expectedRemaining {
		t.Errorf("Expected %d tokens after cleanup, got %d", expectedRemaining, memStore.Count())
	}

	// Shutdown cleanup
	close(shutdown)
	wg.Wait()
}

func TestMemoryTokenStore_CleanupShutdown(t *testing.T) {
	store := newMemoryTokenStore(10 * time.Millisecond)
	
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	
	// Start cleanup
	store.Start(shutdown, &wg)
	
	// Let it run briefly
	time.Sleep(50 * time.Millisecond)
	
	// Shutdown
	close(shutdown)
	
	// Should complete within reasonable time
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// Good, cleanup shut down
	case <-time.After(1 * time.Second):
		t.Error("Cleanup goroutine did not shut down within 1 second")
	}
}

func TestMemoryTokenStore_ConcurrentAccess(t *testing.T) {
	store := newMemoryTokenStore(time.Minute)
	
	var wg sync.WaitGroup
	errors := make(chan error, 100)
	
	// Number of concurrent operations
	numGoroutines := 10
	numOperationsPerGoroutine := 50
	
	// Concurrent writers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < numOperationsPerGoroutine; j++ {
				fingerprint := fmt.Sprintf("concurrent-%d-%d", id, j)
				token := createSampleToken(fingerprint, fmt.Sprintf("user-%d-%d", id, j), time.Now().Add(time.Hour))
				
				err := store.Set(fingerprint, token)
				if err != nil {
					errors <- err
					return
				}
			}
		}(i)
	}
	
	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < numOperationsPerGoroutine; j++ {
				fingerprint := fmt.Sprintf("concurrent-%d-%d", id, j)
				
				// Try to read (may or may not exist depending on timing)
				token, exists := store.Get(fingerprint)
				if exists && token == nil {
					errors <- fmt.Errorf("got nil token for existing fingerprint %s", fingerprint)
					return
				}
			}
		}(i)
	}
	
	// Concurrent deleters
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < numOperationsPerGoroutine/2; j++ {
				fingerprint := fmt.Sprintf("concurrent-%d-%d", id, j)
				
				err := store.Delete(fingerprint)
				if err != nil {
					errors <- err
					return
				}
			}
		}(i)
	}
	
	// Concurrent counters
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for j := 0; j < numOperationsPerGoroutine; j++ {
				count := store.(*memoryTokenStore).Count()
				if count < 0 {
					errors <- fmt.Errorf("negative count: %d", count)
					return
				}
			}
		}()
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
	
	// Final state should be consistent
	finalCount := store.(*memoryTokenStore).Count()
	if finalCount < 0 {
		t.Errorf("Final count is negative: %d", finalCount)
	}
}

func TestMemoryTokenStore_ConcurrentCleanup(t *testing.T) {
	store := newMemoryTokenStore(10 * time.Millisecond)
	memStore := store.(*memoryTokenStore)
	
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	
	// Start cleanup
	store.Start(shutdown, &wg)
	
	// Concurrently add tokens while cleanup is running
	var opWg sync.WaitGroup
	for i := 0; i < 5; i++ {
		opWg.Add(1)
		go func(id int) {
			defer opWg.Done()
			
			for j := 0; j < 100; j++ {
				// Mix of expired and valid tokens
				var expiresAt time.Time
				if j%2 == 0 {
					expiresAt = time.Now().Add(-time.Minute) // Expired
				} else {
					expiresAt = time.Now().Add(time.Hour) // Valid
				}
				
				fingerprint := fmt.Sprintf("cleanup-concurrent-%d-%d", id, j)
				token := createSampleToken(fingerprint, fmt.Sprintf("user-%d-%d", id, j), expiresAt)
				store.Set(fingerprint, token)
				
				// Small delay to let cleanup run
				if j%10 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}(i)
	}
	
	opWg.Wait()
	
	// Let cleanup run a bit more
	time.Sleep(100 * time.Millisecond)
	
	// Should have some tokens (only non-expired ones)
	finalCount := memStore.Count()
	if finalCount < 0 {
		t.Errorf("Final count is negative: %d", finalCount)
	}
	
	// All remaining tokens should be valid (not expired)
	memStore.mu.RLock()
	now := time.Now()
	for fingerprint, token := range memStore.tokens {
		if now.After(token.ExpiresAt) {
			t.Errorf("Found expired token %s that should have been cleaned up", fingerprint)
		}
	}
	memStore.mu.RUnlock()
	
	// Shutdown
	close(shutdown)
	wg.Wait()
}

func TestMemoryTokenStore_EdgeCases(t *testing.T) {
	store := newMemoryTokenStore(time.Minute)
	
	t.Run("empty fingerprint", func(t *testing.T) {
		token := createSampleToken("", "user", time.Now().Add(time.Hour))
		
		err := store.Set("", token)
		if err != nil {
			t.Errorf("Set with empty fingerprint failed: %v", err)
		}
		
		retrieved, exists := store.Get("")
		if !exists {
			t.Error("Token with empty fingerprint should exist")
		}
		if retrieved.Identity != "user" {
			t.Errorf("Expected identity 'user', got %s", retrieved.Identity)
		}
		
		err = store.Delete("")
		if err != nil {
			t.Errorf("Delete with empty fingerprint failed: %v", err)
		}
	})
	
	t.Run("nil token", func(t *testing.T) {
		err := store.Set("nil-token", nil)
		if err != nil {
			t.Errorf("Set with nil token failed: %v", err)
		}
		
		retrieved, exists := store.Get("nil-token")
		if !exists {
			t.Error("Nil token should exist in store")
		}
		if retrieved != nil {
			t.Error("Retrieved token should be nil")
		}
	})
	
	t.Run("very long fingerprint", func(t *testing.T) {
		longFingerprint := strings.Repeat("a", 10000)
		token := createSampleToken(longFingerprint, "user", time.Now().Add(time.Hour))
		
		err := store.Set(longFingerprint, token)
		if err != nil {
			t.Errorf("Set with long fingerprint failed: %v", err)
		}
		
		_, exists := store.Get(longFingerprint)
		if !exists {
			t.Error("Token with long fingerprint should exist")
		}
	})
	
	t.Run("special characters in fingerprint", func(t *testing.T) {
		specialFingerprint := "fingerprint-with-special-chars-éñ-🔐-\n\t"
		token := createSampleToken(specialFingerprint, "user", time.Now().Add(time.Hour))
		
		err := store.Set(specialFingerprint, token)
		if err != nil {
			t.Errorf("Set with special characters failed: %v", err)
		}
		
		_, exists := store.Get(specialFingerprint)
		if !exists {
			t.Error("Token with special characters should exist")
		}
	})
}

func TestMemoryTokenStore_Interface(t *testing.T) {
	// Verify that memoryTokenStore implements TokenStore interface
	var store TokenStore = newMemoryTokenStore(time.Minute)
	
	// Test that all interface methods are available
	fingerprint := "interface-test"
	token := createSampleToken(fingerprint, "user", time.Now().Add(time.Hour))
	
	// Set
	err := store.Set(fingerprint, token)
	if err != nil {
		t.Errorf("Interface Set failed: %v", err)
	}
	
	// Get
	retrieved, exists := store.Get(fingerprint)
	if !exists {
		t.Error("Interface Get failed to find token")
	}
	if retrieved == nil {
		t.Error("Interface Get returned nil token")
	}
	
	// Delete
	err = store.Delete(fingerprint)
	if err != nil {
		t.Errorf("Interface Delete failed: %v", err)
	}
	
	// Start (should not panic)
	shutdown := make(chan struct{})
	var wg sync.WaitGroup
	store.Start(shutdown, &wg)
	
	close(shutdown)
	wg.Wait()
}