package sctx

import (
	"crypto/tls"
	"sync"
	"time"
)

// Token is a client-side wrapper for a security context.
// It provides a safe container for the opaque context string and metadata
// without exposing the internal context data.
type Token struct {
	value       string        // The opaque context string
	expiresAt   time.Time    // When the token expires
	fingerprint string        // Certificate fingerprint that requested this
	mu          sync.RWMutex
}

// newToken creates a new token wrapper (internal use only)
func newToken(ctx Context, expiresAt time.Time, fingerprint string) *Token {
	return &Token{
		value:       string(ctx),
		expiresAt:   expiresAt,
		fingerprint: fingerprint,
	}
}

// String returns the context value for passing to services
func (t *Token) String() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.value
}

// Context returns the context value as the Context type
func (t *Token) Context() Context {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Context(t.value)
}

// ExpiresAt returns when the token expires
func (t *Token) ExpiresAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.expiresAt
}

// IsExpired checks if the token has expired
func (t *Token) IsExpired() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return time.Now().After(t.expiresAt)
}

// NeedsRefresh checks if the token should be refreshed soon
func (t *Token) NeedsRefresh() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	// Refresh if less than 30 seconds remain
	return time.Until(t.expiresAt) < 30*time.Second
}

// TimeUntilExpiry returns how long until the token expires
func (t *Token) TimeUntilExpiry() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return time.Until(t.expiresAt)
}

// Fingerprint returns the certificate fingerprint that requested this token
func (t *Token) Fingerprint() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.fingerprint
}

// update replaces the token value (internal use only for refresh)
func (t *Token) update(ctx Context, expiresAt time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.value = string(ctx)
	t.expiresAt = expiresAt
}

// Refresh attempts to refresh this token using the provided service.
// The TLS connection state is required to prove ownership of the certificate.
// Returns an error if the token is invalid or cannot be refreshed.
func (t *Token) Refresh(service *ContextService, tlsState *tls.ConnectionState) error {
	return service.RefreshToken(t, tlsState)
}