package sctx

import (
	"errors"
	"time"
)

// adminOperations implements the Operations interface with full admin access
// Processors registered by admin get admin-level access to operations
type adminOperations[M any] struct {
	admin *ServiceAdmin[M]
}

// Token Operations

func (ops *adminOperations[M]) ShouldRefreshToken(fingerprint string) bool {
	// Check if token exists and needs refresh
	if ops.admin.service.tokenStore != nil {
		if token, ok := ops.admin.service.tokenStore.Get(fingerprint); ok {
			remaining := time.Until(token.ExpiresAt)
			total := token.ExpiresAt.Sub(token.IssuedAt)
			return remaining > 0 && remaining < total/5 // Less than 20% remaining
		}
	}
	return false
}

func (ops *adminOperations[M]) RevokeToken(fingerprint string, reason string) error {
	// Revoke the token
	if ops.admin.service.tokenStore != nil {
		return ops.admin.service.tokenStore.Delete(fingerprint)
	}
	return errors.New("token store not available")
}

func (ops *adminOperations[M]) IsTokenRevoked(fingerprint string) bool {
	// Check if token exists (if not, it's effectively revoked)
	if ops.admin.service.tokenStore != nil {
		_, exists := ops.admin.service.tokenStore.Get(fingerprint)
		return !exists
	}
	return true
}

func (ops *adminOperations[M]) GetTokenInfo(fingerprint string) (*TokenInfo, error) {
	if ops.admin.service.tokenStore != nil {
		if token, ok := ops.admin.service.tokenStore.Get(fingerprint); ok {
			// Return a safe copy of token information
			return &TokenInfo{
				ContextID:    token.ContextID,
				Identity:     token.Identity,
				IssuedAt:     token.IssuedAt,
				ExpiresAt:    token.ExpiresAt,
				RefreshCount: token.RefreshCount,
				FactoryID:    token.FactoryID,
				Permissions:  append([]string{}, token.Permissions...), // Copy slice
			}, nil
		}
	}
	return nil, errors.New("token not found")
}

func (ops *adminOperations[M]) TrackTokenUsage(fingerprint string) error {
	// For now, this is a no-op. In production, this would integrate with
	// metrics/observability systems
	return nil
}

// Security Operations

func (ops *adminOperations[M]) TriggerSecurityAlert(identity string, threat string, details map[string]string) error {
	// Create security event
	event := SecurityEvent{
		Timestamp: time.Now(),
		Identity:  identity,
		EventType: "security_alert",
		Threat:    threat,
		Severity:  "high",
		Details:   details,
	}

	// In production, this would send to security monitoring systems
	// For now, we'll log it (could integrate with admin's logging)
	return ops.RecordSecurityEvent(event)
}

func (ops *adminOperations[M]) BlacklistIdentity(identity string, duration time.Duration, reason string) error {
	// For now, this is a no-op. In production, this would integrate with
	// a blacklist store or security system
	return nil
}

func (ops *adminOperations[M]) IsIdentityBlacklisted(identity string) bool {
	// For now, no identities are blacklisted. In production, this would
	// check against a blacklist store
	return false
}

func (ops *adminOperations[M]) RecordSecurityEvent(event SecurityEvent) error {
	// For now, this is a no-op. In production, this would send to
	// security event logging systems
	return nil
}

// Registry Operations

func (ops *adminOperations[M]) LookupIdentity(identity string) (*RegistryEntry, error) {
	// Use the admin's registry access
	return ops.admin.service.registry.Lookup(identity)
}

func (ops *adminOperations[M]) RecordIdentityAccess(identity string, success bool, reason string) error {
	// For now, this is a no-op. In production, this would log access attempts
	return nil
}

// Metrics Operations

func (ops *adminOperations[M]) RecordMetric(name string, value float64, labels map[string]string) error {
	// For now, this is a no-op. In production, this would send to metrics systems
	return nil
}

func (ops *adminOperations[M]) IncrementCounter(name string, labels map[string]string) error {
	// For now, this is a no-op. In production, this would increment counters
	return nil
}

func (ops *adminOperations[M]) RecordLatency(operation string, duration time.Duration, labels map[string]string) error {
	// For now, this is a no-op. In production, this would record timing data
	return nil
}

func (ops *adminOperations[M]) RecordProcessorEvent(processorName string, event string, metadata map[string]interface{}) error {
	// For now, this is a no-op. In production, this would log processor events
	return nil
}