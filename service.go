package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNoCertificate     = errors.New("no client certificate provided")
	ErrInvalidCertificate = errors.New("invalid client certificate")
	ErrUnregisteredService = errors.New("unauthorized")
)

// activeToken represents a currently valid token issued to a certificate
type activeToken struct {
	ContextID              string
	CertificateFingerprint string
	IssuedAt               time.Time
	ExpiresAt              time.Time
	Identity               string
	Permissions            []string
	FactoryID              string
	RefreshCount           int
}

// ContextService issues signed security contexts to authenticated clients.
// This service uses ECDSA P-256 (NIST P-256/secp256r1) for all cryptographic operations,
// providing NIST SP 800-186 and FIPS 186-4 compliance.
//
// To generate a compliant P-256 key pair:
//   openssl ecparam -genkey -name prime256v1 -out private.pem
//   openssl ec -in private.pem -pubout -out public.pem
type ContextService struct {
	// CA pool for validating client certificates
	caPool *x509.CertPool
	
	// Private key for signing contexts (ECDSA P-256)
	privateKey *ecdsa.PrivateKey
	
	// Public key for verification (derived from private key)
	publicKey *ecdsa.PublicKey
	
	// Registry for service permissions
	registry Registry
	
	// Context factories for automatic registration
	factories []*ContextFactory
	factoryRegistrationLocked bool
	factoriesMu sync.RWMutex // Protects factories slice
	
	// Admin bootstrap state
	adminIdentity         string
	adminBootstrapOnce    sync.Once
	adminBootstrapComplete bool
	
	// Active tokens indexed by certificate fingerprint
	// Only one token per certificate allowed
	activeTokens   map[string]*activeToken
	activeTokensMu sync.RWMutex
	
	// Service configuration
	issuerName string
	contextTTL time.Duration
	
	// Rate limiting
	rateLimiter *RateLimiter
	
	// Shutdown
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// ContextServiceConfig holds configuration for the context service
type ContextServiceConfig struct {
	CAPool        *x509.CertPool
	PrivateKey    *ecdsa.PrivateKey // ECDSA P-256 private key
	Registry      Registry
	IssuerName    string
	ContextTTL    time.Duration
	AdminIdentity string // Expected identity of the admin certificate for bootstrap
	
	// Optional rate limiting
	RateLimitRequests int           // Max requests per window (0 = no limit)
	RateLimitWindow   time.Duration // Time window for rate limiting
}

// NewContextService creates a new context service
func NewContextService(config ContextServiceConfig) (*ContextService, error) {
	if config.CAPool == nil {
		return nil, errors.New("CA pool is required")
	}
	if config.PrivateKey == nil {
		return nil, errors.New("private key is required")
	}
	
	// Validate key is P-256 for NIST compliance
	if config.PrivateKey.Curve != elliptic.P256() {
		return nil, errors.New("private key must use P-256 curve for NIST compliance")
	}
	if config.Registry == nil {
		return nil, errors.New("registry is required")
	}
	if config.ContextTTL == 0 {
		config.ContextTTL = 15 * time.Minute // default TTL
	}
	
	svc := &ContextService{
		caPool:          config.CAPool,
		privateKey:      config.PrivateKey,
		publicKey:       &config.PrivateKey.PublicKey,
		registry:        config.Registry,
		issuerName:      config.IssuerName,
		contextTTL:      config.ContextTTL,
		adminIdentity:   config.AdminIdentity,
		factories:       make([]*ContextFactory, 0),
		activeTokens:    make(map[string]*activeToken),
		shutdown:        make(chan struct{}),
	}
	
	// Setup rate limiting if configured
	if config.RateLimitRequests > 0 && config.RateLimitWindow > 0 {
		svc.rateLimiter = NewRateLimiter(config.RateLimitRequests, config.RateLimitWindow, svc.shutdown, &svc.wg)
	}
	
	// Start cleanup goroutine for expired tokens
	svc.wg.Add(1)
	go func() {
		defer svc.wg.Done()
		svc.cleanupExpiredTokens()
	}()
	
	return svc, nil
}

// RequestContext issues a signed context token for an authenticated client
func (cs *ContextService) RequestContext(tlsState *tls.ConnectionState) (*Token, error) {
	// Validate TLS connection state
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
		return nil, ErrNoCertificate
	}
	
	// Get the client certificate
	clientCert := tlsState.PeerCertificates[0]
	
	// Get certificate fingerprint
	fingerprint := getCertificateFingerprint(clientCert)
	
	// Check for existing active token for this certificate
	cs.activeTokensMu.Lock()
	if existing, exists := cs.activeTokens[fingerprint]; exists {
		// Certificate already has an active token
		if existing.ExpiresAt.After(time.Now()) {
			cs.activeTokensMu.Unlock()
			return nil, errors.New("certificate already has an active token")
		}
		// Expired token - remove it and continue
		delete(cs.activeTokens, fingerprint)
	}
	cs.activeTokensMu.Unlock()
	
	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         cs.caPool,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	
	// Add any intermediate certificates
	for _, cert := range tlsState.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	
	// Verify the certificate
	if _, err := clientCert.Verify(opts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	
	// Additional certificate validation
	now := time.Now()
	if now.Before(clientCert.NotBefore) {
		return nil, ErrInvalidCertificate
	}
	if now.After(clientCert.NotAfter) {
		return nil, ErrInvalidCertificate
	}
	
	// Check key usage
	if clientCert.ExtKeyUsage != nil && len(clientCert.ExtKeyUsage) > 0 {
		hasClientAuth := false
		for _, usage := range clientCert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth {
				hasClientAuth = true
				break
			}
		}
		if !hasClientAuth {
			return nil, ErrInvalidCertificate
		}
	}
	
	// Extract identity from certificate
	identity := extractIdentity(clientCert)
	
	// Rate limiting
	if cs.rateLimiter != nil && !cs.rateLimiter.Allow(identity) {
		return nil, errors.New("rate limit exceeded")
	}
	
	// Check if this is the admin during bootstrap
	if identity == cs.adminIdentity && !cs.adminBootstrapComplete {
		var adminToken *Token
		var adminErr error
		
		cs.adminBootstrapOnce.Do(func() {
			// Grant admin permissions for bootstrap (only once)
			contextID := generateContextID()
			data := &ContextData{
				Type:        "admin",
				ID:          identity,
				Permissions: []string{"sctx:register", "sctx:factory", "sctx:bootstrap"},
				IssuedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(cs.contextTTL),
				Issuer:      cs.issuerName,
				ContextID:   contextID,
			}
			ctx, err := encodeAndSign(data, cs.privateKey, fingerprint)
			if err != nil {
				adminErr = err
				return
			}
			adminToken = newToken(ctx, data.ExpiresAt, fingerprint)
			
			// Store active token
			cs.activeTokensMu.Lock()
			cs.activeTokens[fingerprint] = &activeToken{
				ContextID:              contextID,
				CertificateFingerprint: fingerprint,
				IssuedAt:               data.IssuedAt,
				ExpiresAt:              data.ExpiresAt,
				Identity:               identity,
				Permissions:            data.Permissions,
				FactoryID:              "",
				RefreshCount:           0,
			}
			cs.activeTokensMu.Unlock()
			
			cs.adminBootstrapComplete = true
		})
		
		if adminToken != nil {
			return adminToken, nil
		}
		if adminErr != nil {
			return nil, adminErr
		}
		// If we get here, admin was already created by another request
		// Fall through to normal processing
	}
	
	// Look up permissions in registry
	entry, err := cs.registry.Lookup(identity)
	if err == nil {
		// Found in registry - use registered permissions
		contextID := generateContextID()
		data := &ContextData{
			Type:        entry.Type,
			ID:          identity,
			Permissions: entry.Permissions,
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(cs.contextTTL),
			Issuer:      cs.issuerName,
			ContextID:   contextID,
		}
		ctx, err := encodeAndSign(data, cs.privateKey, fingerprint)
		if err != nil {
			return nil, err
		}
		
		// Store active token
		cs.activeTokensMu.Lock()
		cs.activeTokens[fingerprint] = &activeToken{
			ContextID:              contextID,
			CertificateFingerprint: fingerprint,
			IssuedAt:               data.IssuedAt,
			ExpiresAt:              data.ExpiresAt,
			Identity:               identity,
			Permissions:            data.Permissions,
			FactoryID:              "",
			RefreshCount:           0,
		}
		cs.activeTokensMu.Unlock()
		
		return newToken(ctx, data.ExpiresAt, fingerprint), nil
	}
	
	// Not in registry - try factories
	var bestFactory *ContextFactory
	bestPriority := -1
	
	cs.factoriesMu.RLock()
	for _, factory := range cs.factories {
		if matched, _ := factory.Match(clientCert); matched {
			if factory.Priority > bestPriority {
				bestFactory = factory
				bestPriority = factory.Priority
			}
		}
	}
	cs.factoriesMu.RUnlock()
	
	if bestFactory == nil {
		return nil, ErrUnregisteredService
	}
	
	// Generate context from factory
	generatedCtx := bestFactory.GenerateContext(clientCert, identity, cs.contextTTL)
	if generatedCtx == nil {
		return nil, errors.New("factory failed to generate context")
	}
	
	// Use the factory-generated context data
	contextID := generateContextID()
	data := generatedCtx
	data.Issuer = cs.issuerName
	data.ContextID = contextID
	data.FactoryID = bestFactory.ID
	
	ctx, err := encodeAndSign(data, cs.privateKey, fingerprint)
	if err != nil {
		return nil, err
	}
	
	// Store active token
	cs.activeTokensMu.Lock()
	cs.activeTokens[fingerprint] = &activeToken{
		ContextID:              contextID,
		CertificateFingerprint: fingerprint,
		IssuedAt:               data.IssuedAt,
		ExpiresAt:              data.ExpiresAt,
		Identity:               identity,
		Permissions:            data.Permissions,
		FactoryID:              bestFactory.ID,
		RefreshCount:           0,
	}
	cs.activeTokensMu.Unlock()
	
	return newToken(ctx, data.ExpiresAt, fingerprint), nil
}


// generateContextID creates a unique identifier for a context
func generateContextID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // This should never happen
	}
	return base64.URLEncoding.EncodeToString(b)
}

// RefreshToken creates a new token with extended expiration for a valid existing token
func (cs *ContextService) RefreshToken(token *Token, tlsState *tls.ConnectionState) error {
	// Verify TLS connection
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
		return errors.New("no client certificate provided")
	}
	
	// Get the client certificate fingerprint
	clientCert := tlsState.PeerCertificates[0]
	clientFingerprint := getCertificateFingerprint(clientCert)
	
	// Verify the current token is still valid
	data, err := decodeAndVerify(token.Context(), cs.publicKey)
	if err != nil {
		return fmt.Errorf("cannot refresh invalid token: %w", err)
	}
	
	// CRITICAL: Verify the requester owns this token
	if data.CertificateFingerprint != clientFingerprint {
		return errors.New("certificate fingerprint mismatch - token does not belong to this client")
	}
	
	// Check if token is still active
	cs.activeTokensMu.RLock()
	currentToken, exists := cs.activeTokens[clientFingerprint]
	cs.activeTokensMu.RUnlock()
	
	if !exists || currentToken.ContextID != data.ContextID {
		return errors.New("token is not active")
	}
	
	// Check if factory allows refresh (if this was factory-created)
	if data.FactoryID != "" {
		cs.factoriesMu.RLock()
		var factory *ContextFactory
		for _, f := range cs.factories {
			if f.ID == data.FactoryID {
				factory = f
				break
			}
		}
		cs.factoriesMu.RUnlock()
		
		if factory != nil && !factory.AllowRefresh {
			return errors.New("factory does not allow refresh")
		}
		
		if factory != nil && factory.MaxRefreshes != nil && data.RefreshCount >= *factory.MaxRefreshes {
			return errors.New("maximum refresh count exceeded")
		}
	}
	
	// Create new context with same data but fresh timestamps
	newContextID := generateContextID()
	newData := &ContextData{
		Type:         data.Type,
		ID:           data.ID,
		Permissions:  data.Permissions,
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(cs.contextTTL),
		Issuer:       cs.issuerName,
		ContextID:    newContextID,
		RefreshCount: data.RefreshCount + 1,
		FactoryID:    data.FactoryID,
	}
	
	// Sign the new context with the same fingerprint
	newCtx, err := encodeAndSign(newData, cs.privateKey, data.CertificateFingerprint)
	if err != nil {
		return fmt.Errorf("failed to sign refreshed context: %w", err)
	}
	
	// Update active token
	cs.activeTokensMu.Lock()
	cs.activeTokens[clientFingerprint] = &activeToken{
		ContextID:              newContextID,
		CertificateFingerprint: clientFingerprint,
		IssuedAt:               newData.IssuedAt,
		ExpiresAt:              newData.ExpiresAt,
		Identity:               data.ID,
		Permissions:            newData.Permissions,
		FactoryID:              newData.FactoryID,
		RefreshCount:           newData.RefreshCount,
	}
	cs.activeTokensMu.Unlock()
	
	// Update the token with new context
	token.update(newCtx, newData.ExpiresAt)
	return nil
}

// VerifyContext verifies a context and returns the decoded data
// The public key must be provided by the caller from a secure source
// The key must be an ECDSA P-256 public key for NIST compliance
func VerifyContext(ctx Context, publicKey *ecdsa.PublicKey) (*ContextData, error) {
	return decodeAndVerify(ctx, publicKey)
}

// HealthCheck verifies the service is operational
func (cs *ContextService) HealthCheck() error {
	// Check we can access our private key
	if cs.privateKey == nil {
		return errors.New("private key not configured")
	}
	
	// Check CA pool is configured
	if cs.caPool == nil {
		return errors.New("CA pool not configured")
	}
	
	// Check registry is accessible
	if cs.registry == nil {
		return errors.New("registry not configured")
	}
	
	return nil
}

// Shutdown gracefully shuts down the service
func (cs *ContextService) Shutdown() {
	close(cs.shutdown)
	cs.wg.Wait()
}

// Stats returns operational statistics
type ServiceStats struct {
	ActiveFactories   int
	ActiveTokens      int
	AdminBootstrapped bool
}

func (cs *ContextService) Stats() ServiceStats {
	cs.factoriesMu.RLock()
	activeFactories := 0
	for _, f := range cs.factories {
		if f.IsActive() {
			activeFactories++
		}
	}
	cs.factoriesMu.RUnlock()
	
	cs.activeTokensMu.RLock()
	activeTokens := len(cs.activeTokens)
	cs.activeTokensMu.RUnlock()
	
	return ServiceStats{
		ActiveFactories:   activeFactories,
		ActiveTokens:      activeTokens,
		AdminBootstrapped: cs.adminBootstrapComplete,
	}
}

// cleanupExpiredTokens periodically removes expired tokens from the active list
func (cs *ContextService) cleanupExpiredTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-cs.shutdown:
			return
		case <-ticker.C:
			cs.activeTokensMu.Lock()
			now := time.Now()
			for fingerprint, token := range cs.activeTokens {
				if now.After(token.ExpiresAt) {
					delete(cs.activeTokens, fingerprint)
				}
			}
			cs.activeTokensMu.Unlock()
		}
	}
}

// extractIdentity extracts the identity from a certificate
// Priority: CN (Common Name) > first SAN (Subject Alternative Name)
func extractIdentity(cert *x509.Certificate) string {
	// First try Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	
	// Fall back to first DNS SAN
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	
	// Fall back to first URI SAN
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	
	// Last resort - use serial number
	return cert.SerialNumber.String()
}