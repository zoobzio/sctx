package sctx

import (
	"crypto/x509"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ContextFactory defines a rule for automatically generating contexts based on certificate attributes.
// When a certificate matches the specified pattern, a context is generated with the defined type and permissions.
//
// Example Use Cases:
//
// 1. Multi-Tenant SaaS Platform
//    Factory that grants tenant-specific permissions based on organization name:
//    MatchField: "O", MatchPattern: "^Customer:Acme$"
//    Permissions: ["tenant:acme:read", "tenant:acme:write"]
//    Result: O="Customer:Acme" → ["tenant:acme:read", "tenant:acme:write"]
//
// 2. Microservice Mesh
//    Services get permissions based on service type:
//    MatchField: "CN", MatchPattern: "^svc-auth-.*$"
//    Permissions: ["service:auth:read", "metrics:write"]
//    Result: CN="svc-auth-prod" → ["service:auth:read", "metrics:write"]
//
// 3. CI/CD Pipeline
//    Build agents get fixed permissions:
//    MatchField: "CN", MatchPattern: "^build-agent-dev$"
//    Permissions: ["deploy:dev", "secrets:dev:read"]
//    Result: CN="build-agent-dev" → ["deploy:dev", "secrets:dev:read"]
//
// 4. IoT Device Fleet
//    Devices get permissions based on type:
//    MatchField: "CN", MatchPattern: "^device-sensor-.*$"
//    Permissions: ["telemetry:write", "config:sensor:read"]
//    Result: CN="device-sensor-uswest-123" → ["telemetry:write", "config:sensor:read"]
//
// 5. Partner API Access
//    Partners get tier-based permissions:
//    MatchField: "O", MatchPattern: "^Partner:.*:Tier:Premium$"
//    Permissions: ["api:premium", "api:ratelimit:1000"]
//    Result: O="Partner:Stripe:Tier:Premium" → ["api:premium", "api:ratelimit:1000"]
//
// 6. Temporary Contractor Access
//    Contractors get limited permissions:
//    MatchField: "OU", MatchPattern: "^Contractor-.*$"
//    Permissions: ["project:read", "docs:read"]
//    Result: OU="Contractor-2024-03" → ["project:read", "docs:read"]
//
// 7. Geographic Compliance
//    Location-based permissions for data residency:
//    MatchField: "C", MatchPattern: "^(DE|FR|IT)$"
//    Permissions: ["data:eu:*", "gdpr:request"]
//    Result: C="DE" → ["data:eu:*", "gdpr:request"]
type ContextFactory struct {
	// ID uniquely identifies this factory for management
	ID string
	
	// MatchField specifies which certificate field to match against
	// Common values: "CN" (Common Name), "O" (Organization), "OU" (Organizational Unit),
	// "C" (Country), "email", "serialNumber"
	MatchField string
	
	// MatchPattern is a regular expression pattern to match against the field value
	MatchPattern string
	
	// ContextType defines what type of context to create when matched
	ContextType ContextType
	
	// Permissions defines the permissions to grant when this factory matches
	Permissions []string
	
	// Priority determines which factory wins if multiple match (higher wins)
	// Default is 0
	Priority int
	
	// Lifecycle controls
	Enabled      bool           // Can be toggled by admin as kill switch
	ValidFrom    *time.Time     // Optional: when factory becomes active
	ValidUntil   *time.Time     // Optional: when factory expires
	MaxTokenTTL  *time.Duration // Optional: override default context TTL
	MaxIssuances *int           // Optional: limit total tokens issued
	
	// Refresh controls
	AllowRefresh   bool  // Whether contexts from this factory can be refreshed
	MaxRefreshes   *int  // Optional: limit number of times a context can be refreshed
	
	// Usage tracking
	IssuedCount int        // Number of contexts issued by this factory
	LastUsed    *time.Time // When this factory last issued a context
	
	// Internal fields
	regex *regexp.Regexp // compiled regex (internal use)
	mu    sync.Mutex     // protects IssuedCount and LastUsed
}

// Compile prepares the factory for use by compiling its regex pattern
func (f *ContextFactory) Compile() error {
	if f.MatchPattern == "" {
		return nil
	}
	
	regex, err := regexp.Compile(f.MatchPattern)
	if err != nil {
		return err
	}
	
	f.regex = regex
	return nil
}

// Match checks if a certificate matches this factory's pattern
func (f *ContextFactory) Match(cert *x509.Certificate) (bool, []string) {
	if f.regex == nil {
		return false, nil
	}
	
	fieldValue := extractCertField(cert, f.MatchField)
	if fieldValue == "" {
		return false, nil
	}
	
	matches := f.regex.FindStringSubmatch(fieldValue)
	return len(matches) > 0, matches
}

// IsActive checks if the factory is currently active based on lifecycle settings
func (f *ContextFactory) IsActive() bool {
	// Check if explicitly disabled
	if !f.Enabled {
		return false
	}
	
	now := time.Now()
	
	// Check ValidFrom
	if f.ValidFrom != nil && now.Before(*f.ValidFrom) {
		return false
	}
	
	// Check ValidUntil
	if f.ValidUntil != nil && now.After(*f.ValidUntil) {
		return false
	}
	
	// Check usage limit
	if f.MaxIssuances != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.IssuedCount >= *f.MaxIssuances {
			return false
		}
	}
	
	return true
}

// GenerateContext creates context data from this factory for the given certificate
func (f *ContextFactory) GenerateContext(cert *x509.Certificate, identity string, defaultTTL time.Duration) *ContextData {
	matched, _ := f.Match(cert)
	if !matched {
		return nil
	}
	
	// Check if factory is active
	if !f.IsActive() {
		return nil
	}
	
	// Update usage tracking
	f.mu.Lock()
	f.IssuedCount++
	now := time.Now()
	f.LastUsed = &now
	f.mu.Unlock()
	
	// Determine TTL
	ttl := defaultTTL
	if f.MaxTokenTTL != nil {
		ttl = *f.MaxTokenTTL
	}
	
	// Return context data with appropriate TTL
	return &ContextData{
		Type:        f.ContextType,
		ID:          identity,
		Permissions: f.Permissions,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
	}
}

// extractCertField extracts a specific field value from a certificate
func extractCertField(cert *x509.Certificate, field string) string {
	switch strings.ToLower(field) {
	case "cn", "commonname":
		return cert.Subject.CommonName
	case "o", "organization":
		if len(cert.Subject.Organization) > 0 {
			return cert.Subject.Organization[0]
		}
	case "ou", "organizationalunit":
		if len(cert.Subject.OrganizationalUnit) > 0 {
			return cert.Subject.OrganizationalUnit[0]
		}
	case "c", "country":
		if len(cert.Subject.Country) > 0 {
			return cert.Subject.Country[0]
		}
	case "l", "locality":
		if len(cert.Subject.Locality) > 0 {
			return cert.Subject.Locality[0]
		}
	case "st", "province":
		if len(cert.Subject.Province) > 0 {
			return cert.Subject.Province[0]
		}
	case "email":
		if len(cert.EmailAddresses) > 0 {
			return cert.EmailAddresses[0]
		}
	case "serialnumber":
		return cert.Subject.SerialNumber
	case "dns":
		if len(cert.DNSNames) > 0 {
			return cert.DNSNames[0]
		}
	}
	return ""
}

