package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)


// Helper function to extract certificate from TLS state for testing
func certFromTLS(tlsState *tls.ConnectionState) *x509.Certificate {
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
		return nil
	}
	return tlsState.PeerCertificates[0]
}

// Mock implementations for testing

type mockRegistry struct {
	mu      sync.RWMutex
	entries map[string]RegistryEntry
}

func newMockRegistry() *mockRegistry {
	return &mockRegistry{
		entries: make(map[string]RegistryEntry),
	}
}

func (m *mockRegistry) Register(identity string, entry RegistryEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[identity] = entry
	return nil
}

func (m *mockRegistry) Lookup(identity string) (*RegistryEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.entries[identity]
	if !ok {
		return nil, errors.New("not found")
	}
	return &entry, nil
}

func (m *mockRegistry) Remove(identity string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, identity)
	return nil
}

func (m *mockRegistry) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.entries))
	for id := range m.entries {
		ids = append(ids, id)
	}
	return ids
}

type mockValidator struct {
	validateFunc    func(*tls.ConnectionState, *x509.CertPool) (*x509.Certificate, error)
	extractFunc     func(*x509.Certificate) string
	fingerprintFunc func(*x509.Certificate) string
}

func (m *mockValidator) ValidateClientCert(tlsState *tls.ConnectionState, caPool *x509.CertPool) (*x509.Certificate, error) {
	if m.validateFunc != nil {
		return m.validateFunc(tlsState, caPool)
	}
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
		return nil, ErrNoCertificate
	}
	return tlsState.PeerCertificates[0], nil
}

func (m *mockValidator) ExtractIdentity(cert *x509.Certificate) string {
	if m.extractFunc != nil {
		return m.extractFunc(cert)
	}
	return cert.Subject.CommonName
}

func (m *mockValidator) GetFingerprint(cert *x509.Certificate) string {
	if m.fingerprintFunc != nil {
		return m.fingerprintFunc(cert)
	}
	return "test-fingerprint-" + cert.Subject.CommonName
}

type mockTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*activeToken
}

func newMockTokenStore() *mockTokenStore {
	return &mockTokenStore{
		tokens: make(map[string]*activeToken),
	}
}

func (m *mockTokenStore) Get(fingerprint string) (*activeToken, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	token, ok := m.tokens[fingerprint]
	return token, ok
}

func (m *mockTokenStore) Set(fingerprint string, token *activeToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[fingerprint] = token
	return nil
}

func (m *mockTokenStore) Delete(fingerprint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, fingerprint)
	return nil
}

func (m *mockTokenStore) Start(shutdown chan struct{}, wg *sync.WaitGroup) {
	// No-op for tests
}

type mockFactoryManager struct {
	factories map[string]*ContextFactory
	findFunc  func(*x509.Certificate) (*ContextFactory, error)
}

func newMockFactoryManager() *mockFactoryManager {
	return &mockFactoryManager{
		factories: make(map[string]*ContextFactory),
	}
}

func (m *mockFactoryManager) FindBestFactory(cert *x509.Certificate) (*ContextFactory, error) {
	if m.findFunc != nil {
		return m.findFunc(cert)
	}
	// Default: no factory found
	return nil, errors.New("no matching factory")
}

func (m *mockFactoryManager) RegisterFactory(factory *ContextFactory) error {
	m.factories[factory.ID] = factory
	return nil
}

func (m *mockFactoryManager) GetFactory(id string) (*ContextFactory, bool) {
	f, ok := m.factories[id]
	return f, ok
}

func (m *mockFactoryManager) Lock() {
	// No-op for tests
}

func (m *mockFactoryManager) IsLocked() bool {
	return false
}

func (m *mockFactoryManager) ListFactories() []*ContextFactory {
	var list []*ContextFactory
	for _, f := range m.factories {
		list = append(list, f)
	}
	return list
}

// Test helpers

// registerTestProcessors registers the minimal processors needed for tests
func registerTestProcessors(admin *ServiceAdmin[TestMetadata], config ContextServiceConfig) {
	// Get the service to access token store
	service := admin.GetService()
	
	// Get operations interface for real processors
	ops := admin.GetOperations()
	
	// Create real processor instances
	securityProcessor := NewSecurityProcessor[TestMetadata](ops)
	tokenProcessor := NewTokenProcessor[TestMetadata](ops)
	
	
	// Token refresh processor - handles existing tokens
	tokenRefreshChecker := func(req *ContextRequest[TestMetadata]) (*ContextRequest[TestMetadata], error) {
		// Skip if no existing token
		if req.ExistingToken == nil {
			return req, nil
		}
		
		// Check if token needs refresh (less than 20% time remaining)
		remaining := time.Until(req.ExistingToken.ExpiresAt)
		total := req.ExistingToken.ExpiresAt.Sub(req.ExistingToken.IssuedAt)
		
		if remaining > total/5 { // More than 20% remaining
			// Token is still valid, return it as-is
			req.Token = newToken(req.ExistingToken.SignedContext, req.ExistingToken.ExpiresAt, req.ExistingToken.CertificateFingerprint)
			req.Allowed = true
			return req, nil
		}
		
		// Otherwise, let it continue for refresh
		return req, nil
	}
	
	
	// Registry lookup
	registryLookup := func(req *ContextRequest[TestMetadata]) (*ContextRequest[TestMetadata], error) {
		if req.DenialReason != "" || req.Identity == "" {
			return req, nil
		}
		
		// Always look up current permissions from registry
		entry, err := config.Registry.Lookup(req.Identity)
		if err == nil && entry != nil {
			req.RegistryEntry = entry
			req.Allowed = true
		}
		
		return req, nil
	}
	
	// Create a dynamic factory matcher that checks the service's factory manager
	dynamicFactoryMatcher := func(req *ContextRequest[TestMetadata]) (*ContextRequest[TestMetadata], error) {
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
		
		// Check factory manager if it exists
		if service.factoryManager != nil {
			factory, err := service.factoryManager.FindBestFactory(req.Certificate)
			if err == nil && factory != nil && factory.IsActive() {
				req.MatchedFactory = factory
				req.Allowed = true
			}
		}
		
		return req, nil
	}
	
	// Register all processors using REAL processor packages!
	admin.Register(
		securityProcessor.CertificateValidator(),
		tokenRefreshChecker,      // Check for refresh early
		securityProcessor.AdminBootstrap(config.AdminIdentity),
		registryLookup,           // Custom for test token handling
		dynamicFactoryMatcher,    // Dynamic factory matching for tests
		tokenProcessor.FactoryRefreshPolicy(),
		securityProcessor.DefaultDeny(),
	)
}

func createTestService(t *testing.T, config ContextServiceConfig) *ContextService[TestMetadata] {
	t.Helper()

	// Reset bootstrap state for clean test environment
	resetBootstrapForTesting()

	if config.PrivateKey == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		config.PrivateKey = key
	}

	if config.CAPool == nil {
		config.CAPool = x509.NewCertPool()
	}

	if config.Registry == nil {
		config.Registry = newMockRegistry()
	}

	if config.ContextTTL == 0 {
		config.ContextTTL = 15 * time.Minute
	}

	if config.AdminIdentity == "" {
		config.AdminIdentity = "test-admin" // Default admin identity for tests
	}

	// Use Bootstrap to ensure proper initialization
	admin, err := Bootstrap(config, createTestMetadata())
	if err != nil {
		t.Fatalf("Failed to bootstrap service: %v", err)
	}

	// Register basic processors for tests to work
	// Tests can register additional processors if needed
	registerTestProcessors(admin, config)

	return admin.GetService()
}


func createTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// Tests

func TestNewContextService(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		config := ContextServiceConfig{
			CAPool:     x509.NewCertPool(),
			PrivateKey: key,
			Registry:   newMockRegistry(),
			IssuerName: "test-issuer",
			ContextTTL: 10 * time.Minute,
		}

		svc, err := newContextService(config, createTestMetadata())
		if err != nil {
			t.Fatalf("newContextService failed: %v", err)
		}

		if svc.contextTTL != 10*time.Minute {
			t.Errorf("Expected TTL 10m, got %v", svc.contextTTL)
		}

		// Cleanup
		svc.Shutdown()
	})

	t.Run("missing CA pool", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		config := ContextServiceConfig{
			PrivateKey: key,
			Registry:   newMockRegistry(),
		}

		_, err := newContextService(config, createTestMetadata())
		if err == nil || !strings.Contains(err.Error(), "CA pool is required") {
			t.Errorf("Expected CA pool error, got %v", err)
		}
	})

	t.Run("missing private key", func(t *testing.T) {
		config := ContextServiceConfig{
			CAPool:   x509.NewCertPool(),
			Registry: newMockRegistry(),
		}

		_, err := newContextService(config, createTestMetadata())
		if err == nil || !strings.Contains(err.Error(), "private key is required") {
			t.Errorf("Expected private key error, got %v", err)
		}
	})

	t.Run("missing registry", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		config := ContextServiceConfig{
			CAPool:     x509.NewCertPool(),
			PrivateKey: key,
		}

		_, err := newContextService(config, createTestMetadata())
		if err == nil || !strings.Contains(err.Error(), "registry is required") {
			t.Errorf("Expected registry error, got %v", err)
		}
	})

	t.Run("invalid private key", func(t *testing.T) {
		// Create non-P256 key
		key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		config := ContextServiceConfig{
			CAPool:     x509.NewCertPool(),
			PrivateKey: key,
			Registry:   newMockRegistry(),
		}

		_, err := newContextService(config, createTestMetadata())
		if err == nil || !strings.Contains(err.Error(), "P-256") {
			t.Errorf("Expected P-256 error, got %v", err)
		}
	})

	t.Run("default TTL", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		config := ContextServiceConfig{
			CAPool:     x509.NewCertPool(),
			PrivateKey: key,
			Registry:   newMockRegistry(),
			// No TTL specified
		}

		svc, err := newContextService(config, createTestMetadata())
		if err != nil {
			t.Fatalf("newContextService failed: %v", err)
		}

		if svc.contextTTL != 15*time.Minute {
			t.Errorf("Expected default TTL 15m, got %v", svc.contextTTL)
		}

		// Cleanup
		svc.Shutdown()
	})
}

func TestRequestContext_NoCertificate(t *testing.T) {
	// Reset and bootstrap
	resetBootstrapForTesting()
	config := ContextServiceConfig{
		PrivateKey:    generateTestKey(t),
		CAPool:        x509.NewCertPool(),
		Registry:      newMockRegistry(),
		AdminIdentity: "test-admin",
	}
	
	admin, err := Bootstrap(config, createTestMetadata())
	if err != nil {
		t.Fatalf("Bootstrap failed: %v", err)
	}
	
	// Register a processor that rejects nil certificates
	noCertProcessor := func(req *ContextRequest[TestMetadata]) (*ContextRequest[TestMetadata], error) {
		if req.Certificate == nil {
			req.Allowed = false
			req.DenialReason = ErrNoCertificate.Error()
		}
		return req, nil
	}
	
	admin.Register(noCertProcessor)
	
	svc := admin.GetService()
	defer svc.Shutdown()

	// Test with nil certificate
	_, err = svc.RequestContext(nil)
	if err == nil || err.Error() != "access denied: "+ErrNoCertificate.Error() {
		t.Errorf("Expected 'access denied: %s', got %v", ErrNoCertificate, err)
	}
}

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return key
}

func TestRequestContext_ExistingValidToken(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{
		ContextTTL: 10 * time.Minute,
	})
	defer svc.Shutdown()

	cert := createTestCert(t, "test-client")
	fingerprint := "test-fingerprint"

	// Create existing token with plenty of time left
	existingToken := &activeToken{
		ContextID:              "existing-ctx-id",
		CertificateFingerprint: fingerprint,
		IssuedAt:               time.Now().Add(-2 * time.Minute),
		ExpiresAt:              time.Now().Add(8 * time.Minute), // 80% time left
		Identity:               "test-client",
		Permissions:            []string{"read"},
		SignedContext:          Context("existing-signed-context"),
	}

	// Replace components with mocks
	mockStore := newMockTokenStore()
	mockStore.Set(fingerprint, existingToken)
	svc.tokenStore = mockStore

	svc.validator = &mockValidator{
		fingerprintFunc: func(*x509.Certificate) string {
			return fingerprint
		},
	}

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	token, err := svc.RequestContext(certFromTLS(tlsState))
	if err != nil {
		t.Fatalf("RequestContext failed: %v", err)
	}

	// Should get existing token back
	if string(token.Context()) != "existing-signed-context" {
		t.Error("Expected to get existing token back")
	}

	if token.ExpiresAt() != existingToken.ExpiresAt {
		t.Error("Expected same expiration time")
	}
}

func TestRequestContext_TokenRefresh(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{
		ContextTTL: 10 * time.Minute,
	})
	defer svc.Shutdown()

	cert := createTestCert(t, "test-client")
	fingerprint := "test-fingerprint"

	// Create existing token that needs refresh (less than 20% time left)
	existingToken := &activeToken{
		ContextID:              "old-ctx-id",
		CertificateFingerprint: fingerprint,
		IssuedAt:               time.Now().Add(-9 * time.Minute),
		ExpiresAt:              time.Now().Add(1 * time.Minute), // Only 10% time left
		Identity:               "test-client",
		Permissions:            []string{"read"},
		RefreshCount:           1,
		SignedContext:          Context("old-signed-context"),
	}

	// Setup mocks
	mockStore := newMockTokenStore()
	mockStore.Set(fingerprint, existingToken)
	svc.tokenStore = mockStore

	svc.validator = &mockValidator{
		fingerprintFunc: func(*x509.Certificate) string {
			return fingerprint
		},
	}

	// Add to registry so it finds permissions
	svc.registry.Register("test-client", RegistryEntry{
		Type:        "service",
		Permissions: []string{"read", "write"},
	})

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	token, err := svc.RequestContext(certFromTLS(tlsState))
	if err != nil {
		t.Fatalf("RequestContext failed: %v", err)
	}

	// Should get new token
	if string(token.Context()) == "old-signed-context" {
		t.Error("Expected new token, got old one")
	}

	// Check stored token was updated
	stored, _ := mockStore.Get(fingerprint)
	if stored.RefreshCount != 2 {
		t.Logf("Original token refresh count: %d", existingToken.RefreshCount)
		t.Logf("Stored token refresh count: %d", stored.RefreshCount)
		t.Logf("Stored token ID: %s", stored.ContextID)
		t.Logf("Original token ID: %s", existingToken.ContextID)
		t.Errorf("Expected refresh count 2, got %d", stored.RefreshCount)
	}
}

func TestRequestContext_AdminBootstrap(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{
		AdminIdentity: "admin-service",
		ContextTTL:    10 * time.Minute,
	})
	defer svc.Shutdown()

	cert := createTestCert(t, "admin-service")
	fingerprint := "admin-fingerprint"

	// Setup mocks
	mockStore := newMockTokenStore()
	svc.tokenStore = mockStore

	svc.validator = &mockValidator{
		extractFunc: func(*x509.Certificate) string {
			return "admin-service"
		},
		fingerprintFunc: func(*x509.Certificate) string {
			return fingerprint
		},
	}

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	// First request should create admin token
	token1, err := svc.RequestContext(certFromTLS(tlsState))
	if err != nil {
		t.Fatalf("First admin request failed: %v", err)
	}

	// Verify admin permissions
	data, err := VerifyContext(token1.Context(), &svc.issuer.(*defaultContextIssuer).privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to verify context: %v", err)
	}

	expectedPerms := []string{"sctx:register", "sctx:factory", "sctx:bootstrap"}
	if len(data.Permissions) != len(expectedPerms) {
		t.Errorf("Expected %d permissions, got %d", len(expectedPerms), len(data.Permissions))
	}

	for i, perm := range expectedPerms {
		if i >= len(data.Permissions) || data.Permissions[i] != perm {
			t.Errorf("Expected permission %s at index %d", perm, i)
		}
	}

	if data.Type != "admin" {
		t.Errorf("Expected type 'admin', got %s", data.Type)
	}

	// Admin bootstrap should be complete
	if !svc.adminBootstrapComplete {
		t.Error("Admin bootstrap should be complete")
	}

	// Second request should use normal flow
	// Add admin to registry with different permissions
	svc.registry.Register("admin-service", RegistryEntry{
		Type:        "service",
		Permissions: []string{"normal:permission"},
	})

	// Clear the token store to force new token creation
	mockStore.Delete(fingerprint)

	token2, err := svc.RequestContext(certFromTLS(tlsState))
	if err != nil {
		t.Fatalf("Second admin request failed: %v", err)
	}

	data2, _ := VerifyContext(token2.Context(), &svc.issuer.(*defaultContextIssuer).privateKey.PublicKey)
	if len(data2.Permissions) != 1 || data2.Permissions[0] != "normal:permission" {
		t.Error("Second request should use registry permissions")
	}
}

func TestRequestContext_RegistryLookup(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{})
	defer svc.Shutdown()

	cert := createTestCert(t, "registry-client")

	// Add to registry
	svc.registry.Register("registry-client", RegistryEntry{
		Type:        "service",
		Permissions: []string{"api:read", "api:write"},
	})

	// Setup mocks
	svc.tokenStore = newMockTokenStore()
	svc.validator = &mockValidator{} // Use mock validator

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	token, err := svc.RequestContext(certFromTLS(tlsState))
	if err != nil {
		t.Fatalf("RequestContext failed: %v", err)
	}

	// Verify permissions from registry
	data, _ := VerifyContext(token.Context(), &svc.issuer.(*defaultContextIssuer).privateKey.PublicKey)
	if len(data.Permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(data.Permissions))
	}

	if data.Type != "service" {
		t.Errorf("Expected type 'service', got %s", data.Type)
	}
}

func TestRequestContext_FactoryMatch(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{})
	defer svc.Shutdown()

	cert := createTestCert(t, "factory-client")

	// Create a factory
	factory := &ContextFactory{
		ID:           "test-factory",
		ContextType:  "worker",
		Permissions:  []string{"work:process", "work:status"},
		Enabled:      true,
		AllowRefresh: true,
		MatchField:   "CN",
		MatchPattern: ".*", // Match all
	}
	// Compile the pattern
	factory.Compile()

	// Setup mocks
	svc.tokenStore = newMockTokenStore()
	svc.validator = &mockValidator{} // Use mock validator
	svc.factoryManager = &mockFactoryManager{
		findFunc: func(*x509.Certificate) (*ContextFactory, error) {
			return factory, nil
		},
	}

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	token, err := svc.RequestContext(certFromTLS(tlsState))
	if err != nil {
		t.Fatalf("RequestContext failed: %v", err)
	}

	// Verify factory-generated context
	data, _ := VerifyContext(token.Context(), &svc.issuer.(*defaultContextIssuer).privateKey.PublicKey)
	if data.Type != "worker" {
		t.Errorf("Expected type 'worker', got %s", data.Type)
	}

	if data.FactoryID != "test-factory" {
		t.Errorf("Expected factory ID 'test-factory', got %s", data.FactoryID)
	}

	if len(data.Permissions) != 2 {
		t.Errorf("Expected 2 permissions from factory, got %d", len(data.Permissions))
	}
}

func TestRequestContext_FactoryRefreshLimit(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{})
	defer svc.Shutdown()

	cert := createTestCert(t, "refresh-client")
	fingerprint := "refresh-fingerprint"
	maxRefreshes := 2

	// Create factory with refresh limit
	factory := &ContextFactory{
		ID:           "limited-factory",
		AllowRefresh: true,
		MaxRefreshes: &maxRefreshes,
		Enabled:      true,
		MatchField:   "CN",
		MatchPattern: "refresh-client",
		ContextType:  "test",
		Permissions:  []string{"test:refresh"},
	}
	factory.Compile() // Compile the regex pattern

	// Existing token at max refresh count
	existingToken := &activeToken{
		FactoryID:              "limited-factory",
		RefreshCount:           2,
		ExpiresAt:              time.Now().Add(1 * time.Minute), // Needs refresh
		IssuedAt:               time.Now().Add(-9 * time.Minute),
		CertificateFingerprint: fingerprint,
		Identity:               "refresh-client",
		Permissions:            []string{"test:refresh"},
	}

	// Setup mocks
	mockStore := newMockTokenStore()
	mockStore.Set(fingerprint, existingToken)
	svc.tokenStore = mockStore

	svc.validator = &mockValidator{
		fingerprintFunc: func(*x509.Certificate) string {
			return fingerprint
		},
	}

	svc.factoryManager = &mockFactoryManager{
		findFunc: func(*x509.Certificate) (*ContextFactory, error) {
			return factory, nil
		},
	}

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	_, err := svc.RequestContext(certFromTLS(tlsState))
	if err == nil || !strings.Contains(err.Error(), "factory refresh limit exceeded") {
		t.Errorf("Expected factory refresh limit error, got %v", err)
	}
}

func TestRequestContext_NoFactoryRefresh(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{})
	defer svc.Shutdown()

	cert := createTestCert(t, "no-refresh-client")
	fingerprint := "no-refresh-fingerprint"

	// Create factory that doesn't allow refresh
	factory := &ContextFactory{
		ID:           "no-refresh-factory",
		AllowRefresh: false,
		Enabled:      true,
		MatchField:   "CN",
		MatchPattern: "no-refresh-client",
		ContextType:  "test",
		Permissions:  []string{"test:no-refresh"},
	}
	factory.Compile() // Compile the regex pattern

	// Existing token from this factory
	existingToken := &activeToken{
		FactoryID:              "no-refresh-factory",
		RefreshCount:           0,
		ExpiresAt:              time.Now().Add(1 * time.Minute), // Needs refresh
		IssuedAt:               time.Now().Add(-9 * time.Minute),
		CertificateFingerprint: fingerprint,
		Identity:               "no-refresh-client",
		Permissions:            []string{"test:no-refresh"},
	}

	// Setup mocks
	mockStore := newMockTokenStore()
	mockStore.Set(fingerprint, existingToken)
	svc.tokenStore = mockStore

	svc.validator = &mockValidator{
		fingerprintFunc: func(*x509.Certificate) string {
			return fingerprint
		},
	}

	svc.factoryManager = &mockFactoryManager{
		findFunc: func(*x509.Certificate) (*ContextFactory, error) {
			return factory, nil
		},
	}

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	_, err := svc.RequestContext(certFromTLS(tlsState))
	if err == nil || !strings.Contains(err.Error(), "token refresh not allowed by factory policy") {
		t.Errorf("Expected no refresh error, got %v", err)
	}
}

func TestRequestContext_UnregisteredService(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{})
	defer svc.Shutdown()

	cert := createTestCert(t, "unknown-client")

	// Not in registry and no factory match
	svc.tokenStore = newMockTokenStore()
	svc.validator = &mockValidator{} // Use mock validator
	svc.factoryManager = &mockFactoryManager{
		findFunc: func(*x509.Certificate) (*ContextFactory, error) {
			return nil, errors.New("no matching factory")
		},
	}

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	_, err := svc.RequestContext(certFromTLS(tlsState))
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("Expected unauthorized error, got %v", err)
	}
}

// TODO: This test needs to be rewritten to properly test factory generation failures
// It's currently trying to mock internal factory behavior which is complex
// func TestRequestContext_FactoryGenerateFailure(t *testing.T) {
// 	svc := createTestService(t, ContextServiceConfig{})
// 	defer svc.Shutdown()

// 	cert := createTestCert(t, "bad-factory-client")

// 	// Create a mock factory that matches but has nil generation
// 	mockFactory := &mockContextFactory{
// 		factory: &ContextFactory{
// 			ID:           "bad-factory",
// 			Enabled:      true,
// 			MatchField:   "CN",
// 			MatchPattern: ".*",
// 		},
// 		generateFunc: func(*x509.Certificate, string, time.Duration) *ContextData {
// 			return nil // Simulate failure
// 		},
// 	}

// 	// Setup mocks
// 	svc.tokenStore = newMockTokenStore()
// 	svc.factoryManager = &mockFactoryManager{
// 		findFunc: func(*x509.Certificate) (*ContextFactory, error) {
// 			return mockFactory.factory, nil
// 		},
// 	}

// 	// Override the GenerateContext behavior
// 	mockFactory.factory.Compile()

// 	tlsState := &tls.ConnectionState{
// 		PeerCertificates: []*x509.Certificate{cert},
// 	}

// 	_, err := svc.RequestContext(certFromTLS(tlsState))
// 	if err != nil && strings.Contains(err.Error(), "unauthorized") {
// 		// This is ok - the factory properly returned nil which leads to unauthorized
// 		return
// 	}
// 	if err == nil {
// 		t.Error("Expected error for nil context generation")
// 	}
// }

// Mock factory that can override GenerateContext
type mockContextFactory struct {
	factory      *ContextFactory
	generateFunc func(*x509.Certificate, string, time.Duration) *ContextData
}

func TestHealthCheck(t *testing.T) {
	t.Run("healthy service", func(t *testing.T) {
		svc := createTestService(t, ContextServiceConfig{})
		defer svc.Shutdown()

		err := svc.HealthCheck()
		if err != nil {
			t.Errorf("HealthCheck failed for healthy service: %v", err)
		}
	})

	t.Run("missing components", func(t *testing.T) {
		svc := createTestService(t, ContextServiceConfig{})
		defer svc.Shutdown()

		tests := []struct {
			name     string
			setup    func()
			expected string
		}{
			{
				name: "missing validator",
				setup: func() {
					svc.validator = nil
				},
				expected: "validator not configured",
			},
			{
				name: "missing token store",
				setup: func() {
					svc.tokenStore = nil
				},
				expected: "token store not configured",
			},
			{
				name: "missing factory manager",
				setup: func() {
					svc.factoryManager = nil
				},
				expected: "factory manager not configured",
			},
			{
				name: "missing issuer",
				setup: func() {
					svc.issuer = nil
				},
				expected: "issuer not configured",
			},
			{
				name: "missing CA pool",
				setup: func() {
					svc.caPool = nil
				},
				expected: "CA pool not configured",
			},
			{
				name: "missing registry",
				setup: func() {
					svc.registry = nil
				},
				expected: "registry not configured",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Reset service
				svc = createTestService(t, ContextServiceConfig{})
				defer svc.Shutdown()

				tt.setup()

				err := svc.HealthCheck()
				if err == nil || !strings.Contains(err.Error(), tt.expected) {
					t.Errorf("Expected error containing '%s', got %v", tt.expected, err)
				}
			})
		}
	})
}

func TestShutdown(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{})

	// Add a goroutine to wait group
	svc.wg.Add(1)
	shutdownDone := make(chan bool)

	go func() {
		select {
		case <-svc.shutdown:
			svc.wg.Done()
			shutdownDone <- true
		case <-time.After(5 * time.Second):
			svc.wg.Done()
			shutdownDone <- false
		}
	}()

	// Call shutdown
	svc.Shutdown()

	// Verify goroutine received shutdown signal
	success := <-shutdownDone
	if !success {
		t.Error("Shutdown signal not received by goroutine")
	}
}

func TestConcurrentRequests(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{})
	defer svc.Shutdown()

	// Setup registry with multiple clients
	for i := 0; i < 10; i++ {
		identity := fmt.Sprintf("client-%d", i)
		svc.registry.Register(identity, RegistryEntry{
			Type:        "service",
			Permissions: []string{"read"},
		})
	}

	// Replace with thread-safe mock
	svc.tokenStore = newMockTokenStore()
	svc.validator = &mockValidator{
		extractFunc: func(cert *x509.Certificate) string {
			// Extract the identity from the certificate's CN
			return cert.Subject.CommonName
		},
	}

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Simulate concurrent requests from different clients
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			cert := createTestCert(t, fmt.Sprintf("client-%d", clientID))
			tlsState := &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			}

			// Make multiple requests
			for j := 0; j < 10; j++ {
				token, err := svc.RequestContext(certFromTLS(tlsState))
				if err != nil {
					errors <- err
					return
				}

				// Verify token
				data, err := VerifyContext(token.Context(), &svc.issuer.(*defaultContextIssuer).privateKey.PublicKey)
				if err != nil {
					errors <- err
					return
				}

				if data.ID != fmt.Sprintf("client-%d", clientID) {
					errors <- fmt.Errorf("wrong identity in token: %s", data.ID)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent request error: %v", err)
	}
}

func TestAdminBootstrapConcurrency(t *testing.T) {
	svc := createTestService(t, ContextServiceConfig{
		AdminIdentity: "admin",
	})
	defer svc.Shutdown()

	cert := createTestCert(t, "admin")
	svc.tokenStore = newMockTokenStore()
	svc.validator = &mockValidator{
		validateFunc: func(*tls.ConnectionState, *x509.CertPool) (*x509.Certificate, error) {
			return cert, nil
		},
		extractFunc: func(*x509.Certificate) string {
			return "admin"
		},
		fingerprintFunc: func(*x509.Certificate) string {
			return "admin-fingerprint"
		},
	}

	// Add admin to registry so that post-bootstrap requests succeed
	svc.registry.Register("admin", RegistryEntry{
		Type:        "admin",
		Permissions: []string{"sctx:register", "sctx:factory", "sctx:bootstrap"},
	})

	var wg sync.WaitGroup
	tokens := make(chan *Token, 10)

	// Multiple concurrent admin requests during bootstrap
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			tlsState := &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			}

			token, err := svc.RequestContext(certFromTLS(tlsState))
			if err != nil {
				t.Errorf("Admin request failed: %v", err)
				return
			}

			tokens <- token
		}()
	}

	wg.Wait()
	close(tokens)

	// All requests should succeed and produce valid tokens
	tokenCount := 0
	for token := range tokens {
		if token == nil {
			t.Error("Expected non-nil token")
		}
		tokenCount++
	}

	if tokenCount != 10 {
		t.Errorf("Expected 10 tokens, got %d", tokenCount)
	}

	// Verify bootstrap is complete
	if !svc.adminBootstrapComplete {
		t.Error("Admin bootstrap should be complete")
	}
}
