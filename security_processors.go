package sctx

import (
	"crypto/sha256"
	"encoding/base64"
	"log"
	"time"
)

// SecurityProcessor provides security-focused pipeline processors
type SecurityProcessor[M any] struct {
	ops Operations
}

// NewSecurityProcessor creates a new security processor with operations access
func NewSecurityProcessor[M any](ops Operations) *SecurityProcessor[M] {
	return &SecurityProcessor[M]{
		ops: ops,
	}
}

// CertificateValidator validates client certificates and extracts identity information.
// This processor should typically run first in the pipeline.
func (sp *SecurityProcessor[M]) CertificateValidator() PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Validate certificate exists
		if req.Certificate == nil {
			req.Allowed = false
			req.DenialReason = "no client certificate provided"
			return req, nil
		}

		// Validate certificate time bounds
		now := time.Now()
		if now.Before(req.Certificate.NotBefore) {
			req.Allowed = false
			req.DenialReason = "certificate not yet valid"
			return req, nil
		}
		if now.After(req.Certificate.NotAfter) {
			req.Allowed = false
			req.DenialReason = "certificate has expired"
			return req, nil
		}

		// Extract identity (priority: CN > DNS SAN > URI SAN > Serial)
		if req.Certificate.Subject.CommonName != "" {
			req.Identity = req.Certificate.Subject.CommonName
		} else if len(req.Certificate.DNSNames) > 0 {
			req.Identity = req.Certificate.DNSNames[0]
		} else if len(req.Certificate.URIs) > 0 {
			req.Identity = req.Certificate.URIs[0].String()
		} else {
			req.Identity = req.Certificate.SerialNumber.String()
		}

		// Generate fingerprint only if not already set
		if req.Fingerprint == "" {
			hash := sha256.Sum256(req.Certificate.Raw)
			req.Fingerprint = base64.StdEncoding.EncodeToString(hash[:])
		}

		return req, nil
	}
}

// RegistryLookup checks if the identity exists in the registry.
// If found, it sets the RegistryEntry and marks the request as allowed.
func (sp *SecurityProcessor[M]) RegistryLookup() PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Skip if already denied
		if req.DenialReason != "" {
			return req, nil
		}

		// Skip if no identity
		if req.Identity == "" {
			return req, nil
		}

		// Look up in registry using operations interface
		entry, err := sp.ops.LookupIdentity(req.Identity)
		if err == nil && entry != nil {
			req.RegistryEntry = entry
			req.Allowed = true
		}

		return req, nil
	}
}

// FactoryMatcher checks if any active factory matches the certificate.
// This provides dynamic authorization based on certificate patterns.
// Note: This processor requires factories to be passed in since they're not
// accessible through the operations interface for security reasons.
func (sp *SecurityProcessor[M]) FactoryMatcher(factories []*ContextFactory) PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Skip if already has authorization source
		if req.RegistryEntry != nil {
			return req, nil
		}

		// Skip if already denied
		if req.DenialReason != "" {
			return req, nil
		}

		// Skip if no certificate
		if req.Certificate == nil {
			return req, nil
		}

		// Check each factory
		for _, factory := range factories {
			if !factory.IsActive() {
				continue
			}

			matched, _ := factory.Match(req.Certificate)
			if matched {
				req.MatchedFactory = factory
				req.Allowed = true
				return req, nil
			}
		}

		return req, nil
	}
}

// RateLimiter enforces rate limits per certificate fingerprint.
// It prevents token request flooding and brute force attempts.
// The limiter parameter should implement an Allow(identity string) bool method.
func (sp *SecurityProcessor[M]) RateLimiter(limiter interface{ Allow(string) bool }) PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Skip if already denied
		if req.DenialReason != "" {
			return req, nil
		}

		// Skip if no fingerprint
		if req.Fingerprint == "" {
			return req, nil
		}

		// Check rate limit
		if !limiter.Allow(req.Fingerprint) {
			req.Allowed = false
			req.DenialReason = "rate limit exceeded"
		}

		return req, nil
	}
}

// AuditLogger logs all authentication attempts with relevant details.
// This processor should typically run early to capture all attempts.
func (sp *SecurityProcessor[M]) AuditLogger(logger *log.Logger) PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Log the attempt
		logger.Printf(
			"AUTH_ATTEMPT identity=%q fingerprint=%q remote=%q",
			req.Identity,
			req.Fingerprint,
			req.RemoteAddr,
		)

		return req, nil
	}
}

// AdminBootstrap handles the special one-time admin bootstrap process.
// The first connection with the admin identity gets elevated privileges.
func (sp *SecurityProcessor[M]) AdminBootstrap(adminIdentity string) PipelineProcessor[M] {
	bootstrapped := false

	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Skip if not admin identity
		if req.Identity != adminIdentity {
			return req, nil
		}

		// Skip if already bootstrapped
		if bootstrapped {
			return req, nil
		}

		// Check if admin already exists in registry using operations interface
		if _, err := sp.ops.LookupIdentity(adminIdentity); err == nil {
			bootstrapped = true
			return req, nil
		}

		// Grant bootstrap privileges
		req.RegistryEntry = &RegistryEntry{
			Type:        "admin",
			Permissions: []string{"sctx:register", "sctx:factory", "sctx:bootstrap"},
		}
		req.Allowed = true
		bootstrapped = true

		// Note: Registry registration would need to be handled by admin
		// since processors don't have direct registry write access

		return req, nil
	}
}

// DefaultDeny ensures that requests without explicit approval are denied.
// This processor should run last to implement fail-secure behavior.
func (sp *SecurityProcessor[M]) DefaultDeny() PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// If no authorization source found and not explicitly allowed
		if req.RegistryEntry == nil && req.MatchedFactory == nil && !req.Allowed {
			req.Allowed = false
			if req.DenialReason == "" {
				req.DenialReason = "unauthorized"
			}
		}

		return req, nil
	}
}

// ThreatDetector demonstrates a processor that takes security actions
// This shows how processors can use operations to revoke tokens and blacklist identities
func (sp *SecurityProcessor[M]) ThreatDetector() PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Example threat detection logic
		if detectsBruteForce(req) {
			// Take immediate security actions using operations interface
			sp.ops.RevokeToken(req.Fingerprint, "brute force attack detected")
			sp.ops.BlacklistIdentity(req.Identity, 1*time.Hour, "brute force pattern")
			sp.ops.TriggerSecurityAlert(req.Identity, "brute_force_attack", map[string]string{
				"fingerprint": req.Fingerprint,
				"remote_addr": req.RemoteAddr,
			})
			
			req.Allowed = false
			req.DenialReason = "security threat detected"
		}

		return req, nil
	}
}

// detectsBruteForce is a placeholder for threat detection logic
func detectsBruteForce[M any](req *ContextRequest[M]) bool {
	// In a real implementation, this would analyze request patterns,
	// frequency, geolocation, etc.
	return false
}