package sctx

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

var (
	ErrNoCertificate       = errors.New("no client certificate provided")
	ErrInvalidCertificate  = errors.New("invalid client certificate")
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
// Defaults to Ed25519 for optimal performance (30% faster than ECDSA).
// For FIPS 140-2 compliance, configure with ECDSA P-256 algorithm.
//
// To generate Ed25519 keys (default):
//   ssh-keygen -t ed25519 -f private_key
//
// To generate ECDSA P-256 keys (FIPS compliant):
//   openssl ecparam -genkey -name prime256v1 -out private.pem
//   openssl ec -in private.pem -pubout -out public.pem
type ContextService[M any] struct {
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
	adminIdentity          string
	adminBootstrapOnce     sync.Once
	adminBootstrapComplete bool

	// Service configuration
	contextTTL time.Duration

	// Shutdown
	shutdown chan struct{}
	wg       sync.WaitGroup

	// Metadata template
	metadataTemplate M

	// Reference to admin for pipeline access
	admin interface{} // Will be *ServiceAdmin[M] but avoiding circular dependency
}

// ContextServiceConfig holds configuration for the context service
type ContextServiceConfig struct {
	CAPool        *x509.CertPool
	PrivateKey    crypto.PrivateKey // Private key (Ed25519 or ECDSA P-256)
	Algorithm     CryptoAlgorithm   // Crypto algorithm (defaults to Ed25519 for performance)
	Registry      Registry
	IssuerName    string
	ContextTTL    time.Duration
	AdminIdentity string // Expected identity of the admin certificate for bootstrap
}

// newContextService creates a new context service (private - use Bootstrap)
func newContextService[M any](config ContextServiceConfig, metadata M) (*ContextService[M], error) {
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
	
	// Default to high-performance Ed25519 algorithm
	if config.Algorithm == "" {
		config.Algorithm = DefaultCryptoAlgorithm
	}
	
	// Validate algorithm is supported
	if err := ValidateAlgorithm(config.Algorithm); err != nil {
		return nil, fmt.Errorf("invalid crypto algorithm: %w", err)
	}

	// Create components
	validator := newCertificateValidator()

	tokenStore := newMemoryTokenStore(5 * time.Minute)

	factoryManager := newFactoryManager()

	issuer, err := newContextIssuer(config.PrivateKey, config.Algorithm, config.IssuerName)
	if err != nil {
		return nil, err
	}

	svc := &ContextService[M]{
		validator:        validator,
		tokenStore:       tokenStore,
		factoryManager:   factoryManager,
		issuer:           issuer,
		caPool:           config.CAPool,
		registry:         config.Registry,
		contextTTL:       config.ContextTTL,
		adminIdentity:    config.AdminIdentity,
		shutdown:         make(chan struct{}),
		metadataTemplate: metadata,
	}

	// Start token store cleanup
	tokenStore.Start(svc.shutdown, &svc.wg)

	return svc, nil
}


// RequestContext issues a signed context token for an authenticated client
func (cs *ContextService[M]) RequestContext(clientCert *x509.Certificate) (*Token, error) {
	// Get admin for pipeline access
	admin, ok := cs.admin.(*ServiceAdmin[M])
	if !ok || admin == nil {
		return nil, errors.New("service not properly initialized")
	}

	// Get pipeline
	admin.mu.RLock()
	pipeline := admin.pipeline
	admin.mu.RUnlock()

	if pipeline == nil {
		return nil, errors.New("no processors registered - admin must configure pipeline")
	}

	// Get certificate fingerprint for existing token lookup
	fingerprint := ""
	if cs.validator != nil && clientCert != nil {
		fingerprint = cs.validator.GetFingerprint(clientCert)
	}

	// Check for existing token
	var existingToken *activeToken
	if cs.tokenStore != nil && fingerprint != "" {
		existingToken, _ = cs.tokenStore.Get(fingerprint)
	}

	// Create request
	req := &ContextRequest[M]{
		Certificate:   clientCert,
		Fingerprint:   fingerprint,
		ExistingToken: existingToken,
		RemoteAddr:    "", // TODO: extract from context if needed
		Ctx:           context.Background(),
		Metadata:      cs.metadataTemplate,
	}

	// Run pipeline
	result, err := pipeline.Process(req)
	if err != nil {
		return nil, fmt.Errorf("pipeline error: %w", err)
	}

	if !result.Allowed {
		return nil, fmt.Errorf("access denied: %s", result.DenialReason)
	}

	// Check if pipeline already set a token (e.g., returning existing valid token)
	if result.Token != nil {
		return result.Token, nil
	}

	// Pipeline succeeded - generate token
	return cs.generateToken(result)
}

// generateToken creates a token after pipeline approval
func (cs *ContextService[M]) generateToken(req *ContextRequest[M]) (*Token, error) {
	var data *ContextData

	// Generate based on what the pipeline found
	if req.RegistryEntry != nil {
		// Generate from registry
		data = &ContextData{
			Type:         req.RegistryEntry.Type,
			ID:           req.Identity,
			Permissions:  req.RegistryEntry.Permissions,
			IssuedAt:     time.Now(),
			ExpiresAt:    time.Now().Add(cs.contextTTL),
			ContextID:    cs.issuer.GenerateContextID(),
			RefreshCount: 0,
		}

		// Handle refresh
		if req.ExistingToken != nil {
			data.RefreshCount = req.ExistingToken.RefreshCount + 1
			data.ContextID = req.ExistingToken.ContextID
		}

		// Check for admin bootstrap completion
		if req.Identity == cs.adminIdentity && slices.Contains(req.RegistryEntry.Permissions, "sctx:bootstrap") && !cs.adminBootstrapComplete {
			cs.adminBootstrapComplete = true
		}
	} else if req.MatchedFactory != nil {
		// Generate from factory
		factoryData, ttl, err := req.MatchedFactory.generateContext(req.Certificate)
		if err != nil {
			return nil, fmt.Errorf("factory generation failed: %w", err)
		}

		data = factoryData
		data.ContextID = cs.issuer.GenerateContextID()
		data.ExpiresAt = time.Now().Add(ttl)

		// Handle refresh
		if req.ExistingToken != nil {
			data.RefreshCount = req.ExistingToken.RefreshCount + 1
			data.ContextID = req.ExistingToken.ContextID
		}
	} else {
		// Pipeline should have set registry or factory
		return nil, errors.New("no authorization source found")
	}

	// Issue the context
	ctx, err := cs.issuer.IssueContext(data, req.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("context issuance failed: %w", err)
	}

	// Store token
	if cs.tokenStore != nil {
		cs.tokenStore.Set(req.Fingerprint, &activeToken{
			ContextID:              data.ContextID,
			CertificateFingerprint: req.Fingerprint,
			IssuedAt:               data.IssuedAt,
			ExpiresAt:              data.ExpiresAt,
			Identity:               req.Identity,
			Permissions:            data.Permissions,
			FactoryID:              data.FactoryID,
			RefreshCount:           data.RefreshCount,
			SignedContext:          ctx,
		})
	}

	return newToken(ctx, data.ExpiresAt, req.Fingerprint), nil
}

// VerifyContext verifies a context and returns the decoded data
// The public key must be provided by the caller from a secure source
// Supports both Ed25519 (default, high-performance) and ECDSA P-256 (FIPS compliant) algorithms
func VerifyContext(ctx Context, publicKey crypto.PublicKey) (*ContextData, error) {
	return decodeAndVerify(ctx, publicKey)
}

// HealthCheck verifies the service is operational
func (cs *ContextService[M]) HealthCheck() error {
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
func (cs *ContextService[M]) Shutdown() {
	close(cs.shutdown)
	cs.wg.Wait()
}

// ServiceStats holds operational statistics (accessed via admin)
type ServiceStats struct {
	ActiveFactories   int
	ActiveTokens      int
	AdminBootstrapped bool
}
