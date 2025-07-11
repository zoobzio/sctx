package sctx

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	SignedContext          Context // The actual signed context string
}

// ContextService issues signed security contexts to authenticated clients.
// This service uses ECDSA P-256 (NIST P-256/secp256r1) for all cryptographic operations,
// providing NIST SP 800-186 and FIPS 186-4 compliance.
//
// To generate a compliant P-256 key pair:
//   openssl ecparam -genkey -name prime256v1 -out private.pem
//   openssl ec -in private.pem -pubout -out public.pem
type ContextService struct {
	// Components
	validator      CertificateValidator
	tokenStore     TokenStore
	factoryManager FactoryManager
	issuer         ContextIssuer
	
	// CA pool for validating client certificates
	caPool *x509.CertPool
	
	// Registry for service permissions
	registry Registry
	
	// Admin bootstrap state
	adminIdentity         string
	adminBootstrapOnce    sync.Once
	adminBootstrapComplete bool
	
	// Service configuration
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

// newContextService creates a new context service (private - use Bootstrap)
func newContextService(config ContextServiceConfig) (*ContextService, error) {
	if config.CAPool == nil {
		return nil, errors.New("CA pool is required")
	}
	if config.PrivateKey == nil {
		return nil, errors.New("private key is required")
	}
	if config.Registry == nil {
		return nil, errors.New("registry is required")
	}
	if config.ContextTTL == 0 {
		config.ContextTTL = 15 * time.Minute // default TTL
	}
	
	// Create components
	validator := newCertificateValidator()
	
	tokenStore := newMemoryTokenStore(5 * time.Minute)
	
	factoryManager := newFactoryManager()
	
	issuer, err := newContextIssuer(config.PrivateKey, config.IssuerName)
	if err != nil {
		return nil, err
	}
	
	svc := &ContextService{
		validator:       validator,
		tokenStore:      tokenStore,
		factoryManager:  factoryManager,
		issuer:          issuer,
		caPool:          config.CAPool,
		registry:        config.Registry,
		contextTTL:      config.ContextTTL,
		adminIdentity:   config.AdminIdentity,
		shutdown:        make(chan struct{}),
	}
	
	// Setup rate limiting if configured
	if config.RateLimitRequests > 0 && config.RateLimitWindow > 0 {
		svc.rateLimiter = newRateLimiter(config.RateLimitRequests, config.RateLimitWindow, svc.shutdown, &svc.wg)
	}
	
	// Start token store cleanup
	tokenStore.Start(svc.shutdown, &svc.wg)
	
	return svc, nil
}

// RequestContext issues a signed context token for an authenticated client
func (cs *ContextService) RequestContext(tlsState *tls.ConnectionState) (*Token, error) {
	// Validate and get the client certificate
	clientCert, err := cs.validator.ValidateClientCert(tlsState, cs.caPool)
	if err != nil {
		return nil, err
	}
	
	// Get certificate fingerprint
	fingerprint := cs.validator.GetFingerprint(clientCert)
	
	// Check for existing active token for this certificate
	existing, hasExisting := cs.tokenStore.Get(fingerprint)
	if hasExisting {
		now := time.Now()
		timeUntilExpiry := existing.ExpiresAt.Sub(now)
		
		// If token is valid and has more than 20% of TTL remaining, return it
		if timeUntilExpiry > (cs.contextTTL / 5) {
			return newToken(existing.SignedContext, existing.ExpiresAt, fingerprint), nil
		}
		
		// Token needs refresh or is expired - we'll create a new one below
	}
	
	// Extract identity from certificate
	identity := cs.validator.ExtractIdentity(clientCert)
	
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
			refreshCount := 0
			if hasExisting {
				refreshCount = existing.RefreshCount + 1
			}
			data := &ContextData{
				Type:         "admin",
				ID:           identity,
				Permissions:  []string{"sctx:register", "sctx:factory", "sctx:bootstrap"},
				IssuedAt:     time.Now(),
				ExpiresAt:    time.Now().Add(cs.contextTTL),
				ContextID:    cs.issuer.GenerateContextID(),
				RefreshCount: refreshCount,
			}
			ctx, err := cs.issuer.IssueContext(data, fingerprint)
			if err != nil {
				adminErr = err
				return
			}
			adminToken = newToken(ctx, data.ExpiresAt, fingerprint)
			
			// Store active token
			cs.tokenStore.Set(fingerprint, &activeToken{
				ContextID:              data.ContextID,
				CertificateFingerprint: fingerprint,
				IssuedAt:               data.IssuedAt,
				ExpiresAt:              data.ExpiresAt,
				Identity:               identity,
				Permissions:            data.Permissions,
				FactoryID:              "",
				RefreshCount:           refreshCount,
				SignedContext:          ctx,
			})
			
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
		refreshCount := 0
		if hasExisting {
			refreshCount = existing.RefreshCount + 1
		}
		data := &ContextData{
			Type:         entry.Type,
			ID:           identity,
			Permissions:  entry.Permissions,
			IssuedAt:     time.Now(),
			ExpiresAt:    time.Now().Add(cs.contextTTL),
			ContextID:    cs.issuer.GenerateContextID(),
			RefreshCount: refreshCount,
		}
		ctx, err := cs.issuer.IssueContext(data, fingerprint)
		if err != nil {
			return nil, err
		}
		
		// Store active token
		cs.tokenStore.Set(fingerprint, &activeToken{
			ContextID:              data.ContextID,
			CertificateFingerprint: fingerprint,
			IssuedAt:               data.IssuedAt,
			ExpiresAt:              data.ExpiresAt,
			Identity:               identity,
			Permissions:            data.Permissions,
			FactoryID:              "",
			RefreshCount:           refreshCount,
			SignedContext:          ctx,
		})
		
		return newToken(ctx, data.ExpiresAt, fingerprint), nil
	}
	
	// Not in registry - try factories
	bestFactory, err := cs.factoryManager.FindBestFactory(clientCert)
	if err != nil {
		return nil, ErrUnregisteredService
	}
	
	// Check if this is a refresh and if factory allows it
	refreshCount := 0
	if hasExisting && existing.FactoryID == bestFactory.ID {
		if !bestFactory.AllowRefresh {
			return nil, errors.New("factory does not allow refresh")
		}
		refreshCount = existing.RefreshCount + 1
		if bestFactory.MaxRefreshes != nil && refreshCount > *bestFactory.MaxRefreshes {
			return nil, errors.New("maximum refresh count exceeded")
		}
	}
	
	// Generate context from factory
	generatedCtx := bestFactory.GenerateContext(clientCert, identity, cs.contextTTL)
	if generatedCtx == nil {
		return nil, errors.New("factory failed to generate context")
	}
	
	// Use the factory-generated context data
	data := generatedCtx
	data.ContextID = cs.issuer.GenerateContextID()
	data.FactoryID = bestFactory.ID
	data.RefreshCount = refreshCount
	
	ctx, err := cs.issuer.IssueContext(data, fingerprint)
	if err != nil {
		return nil, err
	}
	
	// Store active token
	cs.tokenStore.Set(fingerprint, &activeToken{
		ContextID:              data.ContextID,
		CertificateFingerprint: fingerprint,
		IssuedAt:               data.IssuedAt,
		ExpiresAt:              data.ExpiresAt,
		Identity:               identity,
		Permissions:            data.Permissions,
		FactoryID:              bestFactory.ID,
		RefreshCount:           refreshCount,
		SignedContext:          ctx,
	})
	
	return newToken(ctx, data.ExpiresAt, fingerprint), nil
}




// VerifyContext verifies a context and returns the decoded data
// The public key must be provided by the caller from a secure source
// The key must be an ECDSA P-256 public key for NIST compliance
func VerifyContext(ctx Context, publicKey *ecdsa.PublicKey) (*ContextData, error) {
	return decodeAndVerify(ctx, publicKey)
}

// HealthCheck verifies the service is operational
func (cs *ContextService) HealthCheck() error {
	// Check components are configured
	if cs.validator == nil {
		return errors.New("validator not configured")
	}
	
	if cs.tokenStore == nil {
		return errors.New("token store not configured")
	}
	
	if cs.factoryManager == nil {
		return errors.New("factory manager not configured")
	}
	
	if cs.issuer == nil {
		return errors.New("issuer not configured")
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

// ServiceStats holds operational statistics (accessed via admin)
type ServiceStats struct {
	ActiveFactories   int
	ActiveTokens      int
	AdminBootstrapped bool
}


