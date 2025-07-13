package sctx

import (
	"time"
)

// Operations provides scoped access to SCTX administrative functions.
// Processors receive operations interfaces based on their SCTX token permissions.
type Operations interface {
	TokenOperations
	SecurityOperations
	RegistryOperations
	MetricsOperations
}

// TokenOperations provides token lifecycle management capabilities.
type TokenOperations interface {
	// ShouldRefreshToken checks if a token needs refresh based on TTL
	ShouldRefreshToken(fingerprint string) bool
	
	// RevokeToken immediately revokes a token
	RevokeToken(fingerprint string, reason string) error
	
	// IsTokenRevoked checks if a token has been revoked
	IsTokenRevoked(fingerprint string) bool
	
	// GetTokenInfo returns basic token information without exposing internals
	GetTokenInfo(fingerprint string) (*TokenInfo, error)
	
	// TrackTokenUsage records token usage for analytics
	TrackTokenUsage(fingerprint string) error
}

// SecurityOperations provides security enforcement capabilities.
type SecurityOperations interface {
	// TriggerSecurityAlert raises a security alert
	TriggerSecurityAlert(identity string, threat string, details map[string]string) error
	
	// BlacklistIdentity temporarily blocks an identity
	BlacklistIdentity(identity string, duration time.Duration, reason string) error
	
	// IsIdentityBlacklisted checks if an identity is currently blacklisted
	IsIdentityBlacklisted(identity string) bool
	
	// RecordSecurityEvent logs a security event
	RecordSecurityEvent(event SecurityEvent) error
}

// RegistryOperations provides limited registry management capabilities.
type RegistryOperations interface {
	// LookupIdentity safely looks up an identity without exposing full registry access
	LookupIdentity(identity string) (*RegistryEntry, error)
	
	// RecordIdentityAccess logs access attempts for an identity
	RecordIdentityAccess(identity string, success bool, reason string) error
}

// MetricsOperations provides observability and metrics capabilities.
type MetricsOperations interface {
	// RecordMetric records a custom metric
	RecordMetric(name string, value float64, labels map[string]string) error
	
	// IncrementCounter increments a named counter
	IncrementCounter(name string, labels map[string]string) error
	
	// RecordLatency records timing information
	RecordLatency(operation string, duration time.Duration, labels map[string]string) error
	
	// RecordProcessorEvent logs processor-specific events
	RecordProcessorEvent(processorName string, event string, metadata map[string]interface{}) error
}

// TokenInfo provides safe read-only access to token information
type TokenInfo struct {
	ContextID    string
	Identity     string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	RefreshCount int
	FactoryID    string
	Permissions  []string // Copy, not reference to internal data
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	Timestamp   time.Time
	Identity    string
	EventType   string
	Threat      string
	Severity    string
	Details     map[string]string
	Fingerprint string
	RemoteAddr  string
}

