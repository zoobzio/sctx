package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMetadata defines metadata for testing pipeline processors
type TestMetadata struct {
	RequestID   string            `json:"request_id"`
	ClientIP    string            `json:"client_ip"`
	UserAgent   string            `json:"user_agent"`
	ExtraData   map[string]string `json:"extra_data"`
	ProcessedBy []string          `json:"processed_by"`
}

// createTestMetadata creates sample metadata for testing
func createTestMetadata() TestMetadata {
	return TestMetadata{
		RequestID: "test-req-123",
		ClientIP:  "192.168.1.100",
		UserAgent: "SCTX-Test/1.0",
		ExtraData: map[string]string{
			"environment": "test",
			"version":     "1.0.0",
		},
		ProcessedBy: []string{},
	}
}

// resetBootstrapForTesting resets the bootstrap singleton for clean testing
func resetBootstrapForTesting() {
	bootstrapOnce = sync.Once{}
	bootstrapped = false
	bootstrapErr = nil
}

// Test helpers
func generateTestKeys(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

func createTestCAPool(t *testing.T) (*x509.CertPool, *x509.Certificate) {
	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return pool, cert
}

func createTestRegistry() Registry {
	return &memoryRegistry{
		entries: make(map[string]RegistryEntry),
	}
}

func createTestConfig(adminIdentity string) ContextServiceConfig {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	caPool := x509.NewCertPool()
	// For testing, we don't need a real CA cert

	return ContextServiceConfig{
		CAPool:        caPool,
		PrivateKey:    privateKey,
		Algorithm:     CryptoECDSAP256,
		Registry:      createTestRegistry(),
		IssuerName:    "test-issuer",
		ContextTTL:    15 * time.Minute,
		AdminIdentity: adminIdentity,
	}
}

// memoryRegistry test implementation
type memoryRegistry struct {
	mu      sync.RWMutex
	entries map[string]RegistryEntry
}

func (r *memoryRegistry) Register(identity string, entry RegistryEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[identity] = entry
	return nil
}

func (r *memoryRegistry) Lookup(identity string) (*RegistryEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, exists := r.entries[identity]
	if !exists {
		return nil, errors.New("not found")
	}
	return &entry, nil
}

func (r *memoryRegistry) Remove(identity string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, identity)
	return nil
}

func (r *memoryRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	return ids
}

// Tests

func TestBootstrap(t *testing.T) {
	// Reset bootstrap state for testing
	resetBootstrapForTesting()

	config := createTestConfig("test-admin")

	t.Run("successful bootstrap", func(t *testing.T) {
		admin, err := Bootstrap(config, createTestMetadata())
		if err != nil {
			t.Fatalf("Bootstrap failed: %v", err)
		}

		if admin == nil {
			t.Fatal("Bootstrap returned nil admin")
		}

		if admin.service == nil {
			t.Fatal("Admin has nil service")
		}

		if admin.service.adminIdentity != "test-admin" {
			t.Errorf("Expected admin identity 'test-admin', got %s", admin.service.adminIdentity)
		}
	})

	t.Run("bootstrap only once", func(t *testing.T) {
		// Second bootstrap should return error
		admin2, err := Bootstrap(config, createTestMetadata())
		if err != ErrAlreadyBootstrapped {
			t.Errorf("Expected ErrAlreadyBootstrapped, got %v", err)
		}

		if admin2 != nil {
			t.Error("Second bootstrap should return nil admin")
		}
	})
}

func TestBootstrapInvalidConfig(t *testing.T) {
	// Reset bootstrap state for testing
	resetBootstrapForTesting()

	tests := []struct {
		name   string
		config ContextServiceConfig
		errMsg string
	}{
		{
			name: "missing CA pool",
			config: ContextServiceConfig{
				PrivateKey: func() *ecdsa.PrivateKey { pk, _ := generateTestKeys(t); return pk }(),
				Registry:   createTestRegistry(),
			},
			errMsg: "CA pool is required",
		},
		{
			name: "missing private key",
			config: ContextServiceConfig{
				CAPool:   func() *x509.CertPool { pool, _ := createTestCAPool(t); return pool }(),
				Registry: createTestRegistry(),
			},
			errMsg: "private key is required",
		},
		{
			name: "missing registry",
			config: ContextServiceConfig{
				CAPool:     func() *x509.CertPool { pool, _ := createTestCAPool(t); return pool }(),
				PrivateKey: func() *ecdsa.PrivateKey { pk, _ := generateTestKeys(t); return pk }(),
			},
			errMsg: "registry is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset bootstrap state
			bootstrapOnce = sync.Once{}
			bootstrapErr = nil

			admin, err := Bootstrap(tt.config, createTestMetadata())
			if err == nil {
				t.Fatal("Expected error but got none")
			}

			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error containing '%s', got %v", tt.errMsg, err)
			}

			if admin != nil {
				t.Error("Bootstrap should return nil admin on error")
			}
		})
	}
}

// TestNewServiceAdmin_DEPRECATED removed - only Bootstrap pattern is supported

func TestRegisterFactory(t *testing.T) {
	// Setup
	resetBootstrapForTesting()

	admin, _ := Bootstrap(createTestConfig("test-admin"), createTestMetadata())

	t.Run("successful registration", func(t *testing.T) {
		factory, err := NewContextFactory("test-factory", "CN", "^test-.*", "service", []string{"test:read", "test:write"}, 0)
		if err != nil {
			t.Fatalf("NewContextFactory failed: %v", err)
		}

		err = admin.RegisterFactory(factory)
		if err != nil {
			t.Fatalf("RegisterFactory failed: %v", err)
		}

		// Verify factory was registered
		factories, _ := admin.ListFactories()
		if len(factories) != 1 {
			t.Errorf("Expected 1 factory, got %d", len(factories))
		}

		if factories[0].ID != "test-factory" {
			t.Errorf("Expected factory ID 'test-factory', got %s", factories[0].ID)
		}
	})

	t.Run("wildcard permissions rejected", func(t *testing.T) {
		factory, err := NewContextFactory("wildcard-factory", "CN", ".*", "service", []string{"*"}, 0)
		if err != nil {
			t.Fatalf("NewContextFactory failed: %v", err)
		}

		err = admin.RegisterFactory(factory)
		if err == nil {
			t.Fatal("Expected error for wildcard permissions")
		}

		if !strings.Contains(err.Error(), "wildcard permissions are not allowed") {
			t.Errorf("Expected wildcard error, got %v", err)
		}
	})

	t.Run("registration after lock", func(t *testing.T) {
		// Lock factory registration
		err := admin.LockFactoryRegistration()
		if err != nil {
			t.Fatalf("LockFactoryRegistration failed: %v", err)
		}

		// Try to register new factory
		factory, err := NewContextFactory("late-factory", "CN", ".*", "service", []string{"test:read"}, 0)
		if err != nil {
			t.Fatalf("NewContextFactory failed: %v", err)
		}

		err = admin.RegisterFactory(factory)
		if err == nil {
			t.Fatal("Expected error after lock")
		}

		if !strings.Contains(err.Error(), "registration window has closed") {
			t.Errorf("Expected lock error, got %v", err)
		}
	})
}

func TestRegisterIdentity(t *testing.T) {
	// Setup
	resetBootstrapForTesting()

	admin, _ := Bootstrap(createTestConfig("test-admin"), createTestMetadata())

	t.Run("successful registration", func(t *testing.T) {
		entry := RegistryEntry{
			Type:        "service",
			Permissions: []string{"api:read", "api:write"},
		}

		err := admin.RegisterIdentity("test-service", entry)
		if err != nil {
			t.Fatalf("RegisterIdentity failed: %v", err)
		}

		// Verify in metrics
		metrics, _ := admin.GetMetrics()
		if metrics.RegisteredIdentities != 1 {
			t.Errorf("Expected 1 registered identity, got %d", metrics.RegisteredIdentities)
		}
	})

	t.Run("wildcard permissions rejected", func(t *testing.T) {
		entry := RegistryEntry{
			Type:        "service",
			Permissions: []string{"api:*"},
		}

		err := admin.RegisterIdentity("wildcard-service", entry)
		if err == nil {
			t.Fatal("Expected error for wildcard permissions")
		}

		if !strings.Contains(err.Error(), "wildcard permissions are not allowed") {
			t.Errorf("Expected wildcard error, got %v", err)
		}
	})
}

func TestCompleteBootstrap(t *testing.T) {
	// Setup
	resetBootstrapForTesting()

	admin, _ := Bootstrap(createTestConfig("test-admin"), createTestMetadata())

	t.Run("complete bootstrap", func(t *testing.T) {
		err := admin.CompleteBootstrap()
		if err != nil {
			t.Fatalf("CompleteBootstrap failed: %v", err)
		}

		// Verify bootstrap is complete
		metrics, _ := admin.GetMetrics()
		if !metrics.BootstrapComplete {
			t.Error("Bootstrap should be marked complete")
		}

		if !metrics.FactoriesLocked {
			t.Error("Factories should be locked after bootstrap")
		}

		// Verify can't register new factories
		factory, err := NewContextFactory("post-bootstrap", "CN", ".*", "service", []string{"test:read"}, 0)
		if err != nil {
			t.Fatalf("NewContextFactory failed: %v", err)
		}

		err = admin.RegisterFactory(factory)
		if err == nil {
			t.Fatal("Should not allow factory registration after bootstrap")
		}
	})
}

func TestDisableEnableFactory(t *testing.T) {
	// Setup
	resetBootstrapForTesting()

	admin, _ := Bootstrap(createTestConfig("test-admin"), createTestMetadata())

	// Register a factory
	factory, err := NewContextFactory("toggle-factory", "CN", ".*", "service", []string{"test:read"}, 0)
	if err != nil {
		t.Fatalf("NewContextFactory failed: %v", err)
	}
	admin.RegisterFactory(factory)

	t.Run("disable factory", func(t *testing.T) {
		err := admin.DisableFactory("toggle-factory")
		if err != nil {
			t.Fatalf("DisableFactory failed: %v", err)
		}

		// Verify disabled
		factories, _ := admin.ListFactories()
		for _, f := range factories {
			if f.ID == "toggle-factory" && f.Enabled {
				t.Error("Factory should be disabled")
			}
		}
	})

	t.Run("enable factory", func(t *testing.T) {
		err := admin.EnableFactory("toggle-factory")
		if err != nil {
			t.Fatalf("EnableFactory failed: %v", err)
		}

		// Verify enabled
		factories, _ := admin.ListFactories()
		for _, f := range factories {
			if f.ID == "toggle-factory" && !f.Enabled {
				t.Error("Factory should be enabled")
			}
		}
	})

	t.Run("disable non-existent factory", func(t *testing.T) {
		err := admin.DisableFactory("non-existent")
		if err == nil {
			t.Fatal("Expected error for non-existent factory")
		}

		if !strings.Contains(err.Error(), "factory not found") {
			t.Errorf("Expected not found error, got %v", err)
		}
	})
}

func TestGetStats(t *testing.T) {
	// Setup
	resetBootstrapForTesting()

	admin, _ := Bootstrap(createTestConfig("test-admin"), createTestMetadata())

	// Register some data
	factory, err := NewContextFactory("stats-factory", "CN", ".*", "service", []string{"test:read"}, 0)
	if err != nil {
		t.Fatalf("NewContextFactory failed: %v", err)
	}
	admin.RegisterFactory(factory)

	admin.RegisterIdentity("stats-service", RegistryEntry{
		Type:        "service",
		Permissions: []string{"api:read"},
	})

	t.Run("get statistics", func(t *testing.T) {
		stats := admin.GetStats()

		if stats.ActiveFactories != 1 {
			t.Errorf("Expected 1 active factory, got %d", stats.ActiveFactories)
		}

		// Note: AdminBootstrapped is only true after the admin requests their first token
		// In this test, we haven't had the admin request a token yet
		if stats.AdminBootstrapped {
			t.Error("Admin should not be bootstrapped until they request a token")
		}

		// Note: ActiveTokens would be 0 since we haven't requested any tokens
		if stats.ActiveTokens != 0 {
			t.Errorf("Expected 0 active tokens, got %d", stats.ActiveTokens)
		}
	})
}

func TestGetPublicKey(t *testing.T) {
	// Setup
	resetBootstrapForTesting()

	admin, _ := Bootstrap(createTestConfig("test-admin"), createTestMetadata())

	t.Run("get public key", func(t *testing.T) {
		pubKey := admin.GetPublicKey()

		if pubKey == nil {
			t.Fatal("GetPublicKey returned nil")
		}

		// Verify it's a P-256 key
		_ = assertECDSAPublicKey(t, pubKey)
	})
}

func TestRevokeToken(t *testing.T) {
	// Setup
	resetBootstrapForTesting()

	admin, _ := Bootstrap(createTestConfig("test-admin"), createTestMetadata())

	t.Run("revoke non-existent token", func(t *testing.T) {
		err := admin.RevokeToken("non-existent-fingerprint")
		if err == nil {
			t.Fatal("Expected error for non-existent token")
		}

		if !strings.Contains(err.Error(), "no active token") {
			t.Errorf("Expected 'no active token' error, got %v", err)
		}
	})

	// Note: Testing successful revocation would require setting up a full TLS connection
	// and having the admin request a token first, which is beyond the scope of unit tests
}

// Test concurrent operations
func TestConcurrentOperations(t *testing.T) {
	// Setup
	resetBootstrapForTesting()

	admin, _ := Bootstrap(createTestConfig("test-admin"), createTestMetadata())

	// Register initial factory
	factory, err := NewContextFactory("concurrent-factory", "CN", ".*", "service", []string{"test:read"}, 0)
	if err != nil {
		t.Fatalf("NewContextFactory failed: %v", err)
	}
	admin.RegisterFactory(factory)

	t.Run("concurrent factory operations", func(t *testing.T) {
		var wg sync.WaitGroup
		errors := make(chan error, 10)

		// Multiple goroutines trying to disable/enable
		for i := 0; i < 5; i++ {
			wg.Add(2)

			go func() {
				defer wg.Done()
				if err := admin.DisableFactory("concurrent-factory"); err != nil {
					errors <- err
				}
			}()

			go func() {
				defer wg.Done()
				if err := admin.EnableFactory("concurrent-factory"); err != nil {
					errors <- err
				}
			}()
		}

		wg.Wait()
		close(errors)

		// Check for any errors
		for err := range errors {
			t.Errorf("Concurrent operation error: %v", err)
		}
	})

	t.Run("concurrent metrics access", func(t *testing.T) {
		var wg sync.WaitGroup

		// Multiple goroutines reading metrics
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				metrics, err := admin.GetMetrics()
				if err != nil {
					t.Errorf("GetMetrics error: %v", err)
				}
				if metrics == nil {
					t.Error("GetMetrics returned nil")
				}
			}()
		}

		wg.Wait()
	})
}
