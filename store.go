package sctx

import (
	"sync"
	"time"
)

// TokenStore manages active tokens with automatic cleanup
type TokenStore interface {
	// Get retrieves an active token by certificate fingerprint
	Get(fingerprint string) (*activeToken, bool)

	// Set stores or updates an active token
	Set(fingerprint string, token *activeToken) error

	// Delete removes an active token
	Delete(fingerprint string) error

	// Start begins the cleanup goroutine
	Start(shutdown chan struct{}, wg *sync.WaitGroup)
}

// memoryTokenStore is an in-memory implementation of TokenStore
type memoryTokenStore struct {
	tokens          map[string]*activeToken
	mu              sync.RWMutex
	cleanupInterval time.Duration
}

// newMemoryTokenStore creates a new in-memory token store (private)
func newMemoryTokenStore(cleanupInterval time.Duration) TokenStore {
	if cleanupInterval == 0 {
		cleanupInterval = 5 * time.Minute
	}
	return &memoryTokenStore{
		tokens:          make(map[string]*activeToken),
		cleanupInterval: cleanupInterval,
	}
}

// Get retrieves an active token by certificate fingerprint
func (s *memoryTokenStore) Get(fingerprint string) (*activeToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.tokens[fingerprint]
	return token, exists
}

// Set stores or updates an active token
func (s *memoryTokenStore) Set(fingerprint string, token *activeToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[fingerprint] = token
	return nil
}

// Delete removes an active token
func (s *memoryTokenStore) Delete(fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, fingerprint)
	return nil
}

// Start begins the cleanup goroutine
func (s *memoryTokenStore) Start(shutdown chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.cleanupExpiredTokens(shutdown)
	}()
}

// cleanupExpiredTokens periodically removes expired tokens
func (s *memoryTokenStore) cleanupExpiredTokens(shutdown chan struct{}) {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for fingerprint, token := range s.tokens {
				if now.After(token.ExpiresAt) {
					delete(s.tokens, fingerprint)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Count returns the number of active tokens (useful for stats/testing)
func (s *memoryTokenStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}
