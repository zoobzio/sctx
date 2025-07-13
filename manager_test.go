package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test helper to create a certificate with specific fields
func createTestCertWithFields(t *testing.T, fields CertFields) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         fields.CN,
			Organization:       fields.O,
			OrganizationalUnit: fields.OU,
			Country:            fields.C,
			Locality:           fields.L,
			Province:           fields.ST,
			SerialNumber:       fields.SerialNumber,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Add DNS names if provided
	if len(fields.DNS) > 0 {
		template.DNSNames = fields.DNS
	}

	// Add email addresses if provided
	if len(fields.Email) > 0 {
		template.EmailAddresses = fields.Email
	}

	// Add URIs if provided
	if len(fields.URI) > 0 {
		uris := make([]*url.URL, len(fields.URI))
		for i, uriStr := range fields.URI {
			uri, err := url.Parse(uriStr)
			if err != nil {
				t.Fatalf("Failed to parse URI %s: %v", uriStr, err)
			}
			uris[i] = uri
		}
		template.URIs = uris
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

// CertFields holds certificate field values for test certificates
type CertFields struct {
	CN           string
	O            []string
	OU           []string
	C            []string
	L            []string
	ST           []string
	SerialNumber string
	DNS          []string
	Email        []string
	URI          []string
}

func TestNewFactoryManager(t *testing.T) {
	manager := newFactoryManager()
	if manager == nil {
		t.Fatal("newFactoryManager returned nil")
	}

	// Should not be locked initially
	if manager.IsLocked() {
		t.Error("New factory manager should not be locked")
	}

	// Should have no factories initially
	factories := manager.ListFactories()
	if len(factories) != 0 {
		t.Errorf("Expected 0 factories, got %d", len(factories))
	}
}

func TestRegisterFactory_ValidFactory(t *testing.T) {
	manager := newFactoryManager()

	factory := newTestFactory("test-factory", "CN", "^test-.*$", "worker", []string{"work:process"}, 1, true)

	err := manager.RegisterFactory(factory)
	if err != nil {
		t.Fatalf("RegisterFactory failed: %v", err)
	}

	// Verify factory was registered
	factories := manager.ListFactories()
	if len(factories) != 1 {
		t.Errorf("Expected 1 factory, got %d", len(factories))
	}

	if factories[0].ID != "test-factory" {
		t.Errorf("Expected factory ID 'test-factory', got %s", factories[0].ID)
	}

	// Verify factory is enabled by default
	if !factories[0].Enabled {
		t.Error("Factory should be enabled by default")
	}

	// Verify regex was compiled
	if factories[0].regex == nil {
		t.Error("Factory regex should be compiled")
	}
}

func TestRegisterFactory_InvalidFactories(t *testing.T) {
	tests := []struct {
		name    string
		factory *ContextFactory
		wantErr string
	}{
		{
			name:    "nil factory",
			factory: nil,
			wantErr: "factory cannot be nil",
		},
		{
			name: "empty ID",
			factory: &ContextFactory{
				MatchField:   "CN",
				MatchPattern: ".*",
			},
			wantErr: "factory ID is required",
		},
		{
			name: "invalid regex",
			factory: &ContextFactory{
				ID:           "invalid-regex",
				MatchField:   "CN",
				MatchPattern: "[", // Invalid regex
			},
			wantErr: "error parsing regexp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newFactoryManager()

			err := manager.RegisterFactory(tt.factory)
			if err == nil {
				t.Error("Expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestRegisterFactory_DuplicateID(t *testing.T) {
	manager := newFactoryManager()

	factory1 := &ContextFactory{
		ID:           "duplicate-id",
		MatchField:   "CN",
		MatchPattern: ".*",
	}

	factory2 := &ContextFactory{
		ID:           "duplicate-id", // Same ID
		MatchField:   "O",
		MatchPattern: ".*",
	}

	// First registration should succeed
	err := manager.RegisterFactory(factory1)
	if err != nil {
		t.Fatalf("First RegisterFactory failed: %v", err)
	}

	// Second registration should fail
	err = manager.RegisterFactory(factory2)
	if err == nil {
		t.Error("Expected error for duplicate ID")
	}

	if !strings.Contains(err.Error(), "factory ID already exists") {
		t.Errorf("Expected duplicate ID error, got %v", err)
	}
}

func TestRegisterFactory_AfterLock(t *testing.T) {
	manager := newFactoryManager()

	// Lock the manager
	manager.Lock()

	factory := &ContextFactory{
		ID:           "locked-factory",
		MatchField:   "CN",
		MatchPattern: ".*",
	}

	err := manager.RegisterFactory(factory)
	if err == nil {
		t.Error("Expected error when registering after lock")
	}

	if !strings.Contains(err.Error(), "factory registration is locked") {
		t.Errorf("Expected lock error, got %v", err)
	}
}

func TestGetFactory(t *testing.T) {
	manager := newFactoryManager()

	factory := &ContextFactory{
		ID:           "get-test",
		MatchField:   "CN",
		MatchPattern: ".*",
	}

	// Factory should not exist initially
	_, found := manager.GetFactory("get-test")
	if found {
		t.Error("Factory should not exist initially")
	}

	// Register factory
	err := manager.RegisterFactory(factory)
	if err != nil {
		t.Fatalf("RegisterFactory failed: %v", err)
	}

	// Factory should now exist
	retrieved, found := manager.GetFactory("get-test")
	if !found {
		t.Error("Factory should exist after registration")
	}

	if retrieved.ID != "get-test" {
		t.Errorf("Expected factory ID 'get-test', got %s", retrieved.ID)
	}

	// Non-existent factory should not be found
	_, found = manager.GetFactory("non-existent")
	if found {
		t.Error("Non-existent factory should not be found")
	}
}

func TestLockAndIsLocked(t *testing.T) {
	manager := newFactoryManager()

	// Should not be locked initially
	if manager.IsLocked() {
		t.Error("Manager should not be locked initially")
	}

	// Lock the manager
	manager.Lock()

	// Should now be locked
	if !manager.IsLocked() {
		t.Error("Manager should be locked after Lock()")
	}

	// Lock should be idempotent
	manager.Lock()
	if !manager.IsLocked() {
		t.Error("Manager should remain locked after second Lock()")
	}
}

func TestListFactories(t *testing.T) {
	manager := newFactoryManager()

	// Should be empty initially
	factories := manager.ListFactories()
	if len(factories) != 0 {
		t.Errorf("Expected 0 factories, got %d", len(factories))
	}

	// Add some factories
	factory1 := &ContextFactory{
		ID:           "factory-1",
		MatchField:   "CN",
		MatchPattern: ".*",
	}

	factory2 := &ContextFactory{
		ID:           "factory-2",
		MatchField:   "O",
		MatchPattern: ".*",
	}

	manager.RegisterFactory(factory1)
	manager.RegisterFactory(factory2)

	// Should return both factories
	factories = manager.ListFactories()
	if len(factories) != 2 {
		t.Errorf("Expected 2 factories, got %d", len(factories))
	}

	// Verify returned list is a copy (modifications shouldn't affect original)
	factories[0] = nil
	originalFactories := manager.ListFactories()
	if originalFactories[0] == nil {
		t.Error("ListFactories should return a copy, not the original slice")
	}
}

func TestFindBestFactory_NoFactories(t *testing.T) {
	manager := newFactoryManager()
	cert := createTestCertWithFields(t, CertFields{CN: "test"})

	_, err := manager.FindBestFactory(cert)
	if err == nil {
		t.Error("Expected error when no factories are registered")
	}

	if !strings.Contains(err.Error(), "no matching factory found") {
		t.Errorf("Expected no matching factory error, got %v", err)
	}
}

func TestFindBestFactory_NoMatches(t *testing.T) {
	manager := newFactoryManager()

	factory := &ContextFactory{
		ID:           "no-match",
		MatchField:   "CN",
		MatchPattern: "^specific-name$",
		Enabled:      true,
	}

	manager.RegisterFactory(factory)

	cert := createTestCertWithFields(t, CertFields{CN: "different-name"})

	_, err := manager.FindBestFactory(cert)
	if err == nil {
		t.Error("Expected error when no factories match")
	}

	if !strings.Contains(err.Error(), "no matching factory found") {
		t.Errorf("Expected no matching factory error, got %v", err)
	}
}

func TestFindBestFactory_SingleMatch(t *testing.T) {
	manager := newFactoryManager()

	factory := &ContextFactory{
		ID:           "single-match",
		MatchField:   "CN",
		MatchPattern: "^test-.*$",
		Enabled:      true,
		Priority:     1,
	}

	manager.RegisterFactory(factory)

	cert := createTestCertWithFields(t, CertFields{CN: "test-service"})

	result, err := manager.FindBestFactory(cert)
	if err != nil {
		t.Fatalf("FindBestFactory failed: %v", err)
	}

	if result.ID != "single-match" {
		t.Errorf("Expected factory 'single-match', got %s", result.ID)
	}
}

func TestFindBestFactory_PriorityOrdering(t *testing.T) {
	manager := newFactoryManager()

	// Register factories with different priorities
	lowPriority := &ContextFactory{
		ID:           "low-priority",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Enabled:      true,
		Priority:     1,
	}

	highPriority := &ContextFactory{
		ID:           "high-priority",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Enabled:      true,
		Priority:     10,
	}

	mediumPriority := &ContextFactory{
		ID:           "medium-priority",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Enabled:      true,
		Priority:     5,
	}

	// Register in non-priority order
	manager.RegisterFactory(lowPriority)
	manager.RegisterFactory(highPriority)
	manager.RegisterFactory(mediumPriority)

	cert := createTestCertWithFields(t, CertFields{CN: "test-service"})

	result, err := manager.FindBestFactory(cert)
	if err != nil {
		t.Fatalf("FindBestFactory failed: %v", err)
	}

	// Should return the highest priority factory
	if result.ID != "high-priority" {
		t.Errorf("Expected 'high-priority' factory, got %s", result.ID)
	}
}

func TestFindBestFactory_DisabledFactories(t *testing.T) {
	manager := newFactoryManager()

	disabledFactory := &ContextFactory{
		ID:           "disabled",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Priority:     10,
	}

	enabledFactory := &ContextFactory{
		ID:           "enabled",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Priority:     1, // Lower priority
	}

	manager.RegisterFactory(disabledFactory)
	manager.RegisterFactory(enabledFactory)

	// Disable the high priority factory after registration
	disabledFactory.Enabled = false

	cert := createTestCertWithFields(t, CertFields{CN: "test-service"})

	result, err := manager.FindBestFactory(cert)
	if err != nil {
		t.Fatalf("FindBestFactory failed: %v", err)
	}

	// Should return the enabled factory, even with lower priority
	if result.ID != "enabled" {
		t.Errorf("Expected 'enabled' factory, got %s", result.ID)
	}
}

func TestFindBestFactory_ExpiredFactories(t *testing.T) {
	manager := newFactoryManager()

	// Factory that's valid until yesterday
	pastTime := time.Now().Add(-24 * time.Hour)
	expiredFactory := &ContextFactory{
		ID:           "expired",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Enabled:      true,
		ValidUntil:   &pastTime,
		Priority:     10,
	}

	validFactory := &ContextFactory{
		ID:           "valid",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Enabled:      true,
		Priority:     1,
	}

	manager.RegisterFactory(expiredFactory)
	manager.RegisterFactory(validFactory)

	cert := createTestCertWithFields(t, CertFields{CN: "test-service"})

	result, err := manager.FindBestFactory(cert)
	if err != nil {
		t.Fatalf("FindBestFactory failed: %v", err)
	}

	// Should return the valid factory
	if result.ID != "valid" {
		t.Errorf("Expected 'valid' factory, got %s", result.ID)
	}
}

func TestFindBestFactory_NotYetValidFactories(t *testing.T) {
	manager := newFactoryManager()

	// Factory that becomes valid tomorrow
	futureTime := time.Now().Add(24 * time.Hour)
	futureFactory := &ContextFactory{
		ID:           "future",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Enabled:      true,
		ValidFrom:    &futureTime,
		Priority:     10,
	}

	validFactory := &ContextFactory{
		ID:           "valid",
		MatchField:   "CN",
		MatchPattern: "test-.*",
		Enabled:      true,
		Priority:     1,
	}

	manager.RegisterFactory(futureFactory)
	manager.RegisterFactory(validFactory)

	cert := createTestCertWithFields(t, CertFields{CN: "test-service"})

	result, err := manager.FindBestFactory(cert)
	if err != nil {
		t.Fatalf("FindBestFactory failed: %v", err)
	}

	// Should return the currently valid factory
	if result.ID != "valid" {
		t.Errorf("Expected 'valid' factory, got %s", result.ID)
	}
}

func TestFindBestFactory_DifferentMatchFields(t *testing.T) {
	manager := newFactoryManager()

	cnFactory := &ContextFactory{
		ID:           "cn-factory",
		MatchField:   "CN",
		MatchPattern: "^cn-test$",
		Enabled:      true,
		Priority:     1,
	}

	orgFactory := &ContextFactory{
		ID:           "org-factory",
		MatchField:   "O",
		MatchPattern: "^TestOrg$",
		Enabled:      true,
		Priority:     2,
	}

	dnsFactory := &ContextFactory{
		ID:           "dns-factory",
		MatchField:   "DNS",
		MatchPattern: "^.*\\.example\\.com$",
		Enabled:      true,
		Priority:     3,
	}

	manager.RegisterFactory(cnFactory)
	manager.RegisterFactory(orgFactory)
	manager.RegisterFactory(dnsFactory)

	tests := []struct {
		name            string
		certFields      CertFields
		expectedFactory string
	}{
		{
			name:            "CN match",
			certFields:      CertFields{CN: "cn-test"},
			expectedFactory: "cn-factory",
		},
		{
			name:            "Organization match",
			certFields:      CertFields{O: []string{"TestOrg"}},
			expectedFactory: "org-factory",
		},
		{
			name:            "DNS match",
			certFields:      CertFields{DNS: []string{"service.example.com"}},
			expectedFactory: "dns-factory",
		},
		{
			name: "Multiple matches - highest priority wins",
			certFields: CertFields{
				CN:  "cn-test",
				O:   []string{"TestOrg"},
				DNS: []string{"service.example.com"},
			},
			expectedFactory: "dns-factory", // Highest priority (3)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertWithFields(t, tt.certFields)

			result, err := manager.FindBestFactory(cert)
			if err != nil {
				t.Fatalf("FindBestFactory failed: %v", err)
			}

			if result.ID != tt.expectedFactory {
				t.Errorf("Expected factory %s, got %s", tt.expectedFactory, result.ID)
			}
		})
	}
}

func TestFactoryManager_Concurrency(t *testing.T) {
	manager := newFactoryManager()

	// Register some initial factories
	for i := 0; i < 5; i++ {
		factory := &ContextFactory{
			ID:           fmt.Sprintf("factory-%d", i),
			MatchField:   "CN",
			MatchPattern: ".*",
			Enabled:      true,
			Priority:     i,
		}
		manager.RegisterFactory(factory)
	}

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cert := createTestCertWithFields(t, CertFields{CN: fmt.Sprintf("test-%d", id)})

			// Multiple operations
			for j := 0; j < 10; j++ {
				// FindBestFactory
				_, err := manager.FindBestFactory(cert)
				if err != nil {
					errors <- err
					return
				}

				// GetFactory
				_, _ = manager.GetFactory("factory-0")

				// ListFactories
				_ = manager.ListFactories()

				// IsLocked
				_ = manager.IsLocked()
			}
		}(i)
	}

	// Concurrent Lock calls
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager.Lock()
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}

	// Verify final state
	if !manager.IsLocked() {
		t.Error("Manager should be locked after concurrent Lock calls")
	}

	factories := manager.ListFactories()
	if len(factories) != 5 {
		t.Errorf("Expected 5 factories, got %d", len(factories))
	}
}

func TestFactoryManager_EdgeCases(t *testing.T) {
	t.Run("empty certificate fields", func(t *testing.T) {
		manager := newFactoryManager()

		factory := &ContextFactory{
			ID:           "empty-test",
			MatchField:   "CN",
			MatchPattern: ".*",
			Enabled:      true,
		}
		manager.RegisterFactory(factory)

		// Certificate with empty CN
		cert := createTestCertWithFields(t, CertFields{CN: ""})

		_, err := manager.FindBestFactory(cert)
		if err == nil {
			t.Error("Expected error for empty CN field")
		}
	})

	t.Run("zero priority factories", func(t *testing.T) {
		manager := newFactoryManager()

		factory1 := &ContextFactory{
			ID:           "zero-priority-1",
			MatchField:   "CN",
			MatchPattern: "test",
			Enabled:      true,
			Priority:     0,
		}

		factory2 := &ContextFactory{
			ID:           "zero-priority-2",
			MatchField:   "CN",
			MatchPattern: "test",
			Enabled:      true,
			Priority:     0,
		}

		manager.RegisterFactory(factory1)
		manager.RegisterFactory(factory2)

		cert := createTestCertWithFields(t, CertFields{CN: "test"})

		result, err := manager.FindBestFactory(cert)
		if err != nil {
			t.Fatalf("FindBestFactory failed: %v", err)
		}

		// Should return one of them (deterministic based on registration order)
		if result.ID != "zero-priority-1" && result.ID != "zero-priority-2" {
			t.Errorf("Expected one of the zero-priority factories, got %s", result.ID)
		}
	})

	t.Run("negative priority factories", func(t *testing.T) {
		manager := newFactoryManager()

		negativeFactory := &ContextFactory{
			ID:           "negative",
			MatchField:   "CN",
			MatchPattern: "test",
			Enabled:      true,
			Priority:     -5,
		}

		positiveFactory := &ContextFactory{
			ID:           "positive",
			MatchField:   "CN",
			MatchPattern: "test",
			Enabled:      true,
			Priority:     1,
		}

		manager.RegisterFactory(negativeFactory)
		manager.RegisterFactory(positiveFactory)

		cert := createTestCertWithFields(t, CertFields{CN: "test"})

		result, err := manager.FindBestFactory(cert)
		if err != nil {
			t.Fatalf("FindBestFactory failed: %v", err)
		}

		// Should return the positive priority factory
		if result.ID != "positive" {
			t.Errorf("Expected 'positive' factory, got %s", result.ID)
		}
	})
}

// Tests for individual ContextFactory functionality

func TestContextFactory_Compile(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "valid regex",
			pattern: "^test-.*$",
			wantErr: false,
		},
		{
			name:    "empty pattern",
			pattern: "",
			wantErr: false, // Empty pattern is allowed
		},
		{
			name:    "invalid regex",
			pattern: "[",
			wantErr: true,
		},
		{
			name:    "complex regex",
			pattern: "^(service|worker)-[a-z0-9]+-(prod|dev)$",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &ContextFactory{
				MatchPattern: tt.pattern,
			}

			err := factory.Compile()
			if (err != nil) != tt.wantErr {
				t.Errorf("Compile() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && tt.pattern != "" && factory.regex == nil {
				t.Error("Expected regex to be compiled")
			}
		})
	}
}

func TestContextFactory_Match(t *testing.T) {
	tests := []struct {
		name       string
		factory    *ContextFactory
		certFields CertFields
		wantMatch  bool
		wantGroups int
	}{
		{
			name: "CN exact match",
			factory: &ContextFactory{
				MatchField:   "CN",
				MatchPattern: "^test-service$",
			},
			certFields: CertFields{CN: "test-service"},
			wantMatch:  true,
			wantGroups: 1,
		},
		{
			name: "CN pattern match",
			factory: &ContextFactory{
				MatchField:   "CN",
				MatchPattern: "^test-.*$",
			},
			certFields: CertFields{CN: "test-worker-123"},
			wantMatch:  true,
			wantGroups: 1,
		},
		{
			name: "CN no match",
			factory: &ContextFactory{
				MatchField:   "CN",
				MatchPattern: "^prod-.*$",
			},
			certFields: CertFields{CN: "test-service"},
			wantMatch:  false,
			wantGroups: 0,
		},
		{
			name: "Organization match",
			factory: &ContextFactory{
				MatchField:   "O",
				MatchPattern: "^TestCorp$",
			},
			certFields: CertFields{O: []string{"TestCorp"}},
			wantMatch:  true,
			wantGroups: 1,
		},
		{
			name: "DNS match",
			factory: &ContextFactory{
				MatchField:   "DNS",
				MatchPattern: ".*\\.example\\.com$",
			},
			certFields: CertFields{DNS: []string{"api.example.com"}},
			wantMatch:  true,
			wantGroups: 1,
		},
		{
			name: "Email match",
			factory: &ContextFactory{
				MatchField:   "email",
				MatchPattern: ".*@company\\.com$",
			},
			certFields: CertFields{Email: []string{"service@company.com"}},
			wantMatch:  true,
			wantGroups: 1,
		},
		{
			name: "SerialNumber match",
			factory: &ContextFactory{
				MatchField:   "serialNumber",
				MatchPattern: "^SN[0-9]+$",
			},
			certFields: CertFields{SerialNumber: "SN12345"},
			wantMatch:  true,
			wantGroups: 1,
		},
		{
			name: "empty field - no match",
			factory: &ContextFactory{
				MatchField:   "CN",
				MatchPattern: ".*",
			},
			certFields: CertFields{CN: ""},
			wantMatch:  false,
			wantGroups: 0,
		},
		{
			name: "uncompiled regex - no match",
			factory: &ContextFactory{
				MatchField:   "CN",
				MatchPattern: ".*",
				// regex not compiled - this should fail to match
			},
			certFields: CertFields{CN: "test"},
			wantMatch:  false,
			wantGroups: 0,
		},
		{
			name: "capture groups",
			factory: &ContextFactory{
				MatchField:   "CN",
				MatchPattern: "^(service|worker)-(.*)-([a-z]+)$",
			},
			certFields: CertFields{CN: "service-api-prod"},
			wantMatch:  true,
			wantGroups: 4, // Full match + 3 capture groups
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only compile if this isn't the "uncompiled regex" test
			if tt.factory.MatchPattern != "" && tt.name != "uncompiled regex - no match" {
				err := tt.factory.Compile()
				if err != nil {
					t.Fatalf("Failed to compile regex: %v", err)
				}
			}

			cert := createTestCertWithFields(t, tt.certFields)
			matched, groups := tt.factory.Match(cert)

			if matched != tt.wantMatch {
				t.Errorf("Match() matched = %v, want %v", matched, tt.wantMatch)
			}

			if len(groups) != tt.wantGroups {
				t.Errorf("Match() groups = %d, want %d", len(groups), tt.wantGroups)
			}
		})
	}
}

func TestContextFactory_IsActive(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		factory    *ContextFactory
		wantActive bool
	}{
		{
			name: "enabled and valid",
			factory: &ContextFactory{
				Enabled: true,
			},
			wantActive: true,
		},
		{
			name: "disabled",
			factory: &ContextFactory{
				Enabled: false,
			},
			wantActive: false,
		},
		{
			name: "valid from future",
			factory: &ContextFactory{
				Enabled:   true,
				ValidFrom: &[]time.Time{now.Add(time.Hour)}[0],
			},
			wantActive: false,
		},
		{
			name: "valid from past",
			factory: &ContextFactory{
				Enabled:   true,
				ValidFrom: &[]time.Time{now.Add(-time.Hour)}[0],
			},
			wantActive: true,
		},
		{
			name: "valid until future",
			factory: &ContextFactory{
				Enabled:    true,
				ValidUntil: &[]time.Time{now.Add(time.Hour)}[0],
			},
			wantActive: true,
		},
		{
			name: "valid until past",
			factory: &ContextFactory{
				Enabled:    true,
				ValidUntil: &[]time.Time{now.Add(-time.Hour)}[0],
			},
			wantActive: false,
		},
		{
			name: "within valid window",
			factory: &ContextFactory{
				Enabled:    true,
				ValidFrom:  &[]time.Time{now.Add(-time.Hour)}[0],
				ValidUntil: &[]time.Time{now.Add(time.Hour)}[0],
			},
			wantActive: true,
		},
		{
			name: "before valid window",
			factory: &ContextFactory{
				Enabled:    true,
				ValidFrom:  &[]time.Time{now.Add(time.Hour)}[0],
				ValidUntil: &[]time.Time{now.Add(2 * time.Hour)}[0],
			},
			wantActive: false,
		},
		{
			name: "after valid window",
			factory: &ContextFactory{
				Enabled:    true,
				ValidFrom:  &[]time.Time{now.Add(-2 * time.Hour)}[0],
				ValidUntil: &[]time.Time{now.Add(-time.Hour)}[0],
			},
			wantActive: false,
		},
		{
			name: "under issuance limit",
			factory: &ContextFactory{
				Enabled:      true,
				MaxIssuances: &[]int{10}[0],
				IssuedCount:  5,
			},
			wantActive: true,
		},
		{
			name: "at issuance limit",
			factory: &ContextFactory{
				Enabled:      true,
				MaxIssuances: &[]int{10}[0],
				IssuedCount:  10,
			},
			wantActive: false,
		},
		{
			name: "over issuance limit",
			factory: &ContextFactory{
				Enabled:      true,
				MaxIssuances: &[]int{10}[0],
				IssuedCount:  15,
			},
			wantActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active := tt.factory.IsActive()
			if active != tt.wantActive {
				t.Errorf("IsActive() = %v, want %v", active, tt.wantActive)
			}
		})
	}
}

func TestContextFactory_GenerateContext(t *testing.T) {
	factory := &ContextFactory{
		ID:           "test-generator",
		MatchField:   "CN",
		MatchPattern: "^test-.*$",
		ContextType:  "worker",
		Permissions:  []string{"work:process", "work:status"},
		Enabled:      true,
		Priority:     1,
	}

	err := factory.Compile()
	if err != nil {
		t.Fatalf("Failed to compile factory: %v", err)
	}

	tests := []struct {
		name         string
		certFields   CertFields
		identity     string
		defaultTTL   time.Duration
		wantContext  bool
		setupFactory func(*ContextFactory)
	}{
		{
			name:        "successful generation",
			certFields:  CertFields{CN: "test-service"},
			identity:    "test-service",
			defaultTTL:  15 * time.Minute,
			wantContext: true,
		},
		{
			name:        "no match - no context",
			certFields:  CertFields{CN: "prod-service"},
			identity:    "prod-service",
			defaultTTL:  15 * time.Minute,
			wantContext: false,
		},
		{
			name:        "inactive factory - no context",
			certFields:  CertFields{CN: "test-service"},
			identity:    "test-service",
			defaultTTL:  15 * time.Minute,
			wantContext: false,
			setupFactory: func(f *ContextFactory) {
				f.Enabled = false
			},
		},
		{
			name:        "custom TTL",
			certFields:  CertFields{CN: "test-service"},
			identity:    "test-service",
			defaultTTL:  15 * time.Minute,
			wantContext: true,
			setupFactory: func(f *ContextFactory) {
				customTTL := 30 * time.Minute
				f.MaxTokenTTL = &customTTL
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset factory state
			testFactory := &ContextFactory{
				ID:           factory.ID,
				MatchField:   factory.MatchField,
				MatchPattern: factory.MatchPattern,
				ContextType:  factory.ContextType,
				Permissions:  factory.Permissions,
				Enabled:      factory.Enabled,
				Priority:     factory.Priority,
			}
			testFactory.Compile()

			if tt.setupFactory != nil {
				tt.setupFactory(testFactory)
			}

			cert := createTestCertWithFields(t, tt.certFields)
			context, _, err := testFactory.generateContext(cert)
			if tt.wantContext && err != nil {
				t.Errorf("GenerateContext failed: %v", err)
			}

			if tt.wantContext && context == nil {
				t.Error("Expected context to be generated")
			}

			if !tt.wantContext && context != nil {
				t.Error("Expected no context to be generated")
			}

			if context != nil {
				// Verify context fields
				if context.Type != testFactory.ContextType {
					t.Errorf("Expected context type %s, got %s", testFactory.ContextType, context.Type)
				}

				if context.ID != tt.identity {
					t.Errorf("Expected context ID %s, got %s", tt.identity, context.ID)
				}

				if len(context.Permissions) != len(testFactory.Permissions) {
					t.Errorf("Expected %d permissions, got %d", len(testFactory.Permissions), len(context.Permissions))
				}

				// Check TTL
				expectedDuration := tt.defaultTTL
				if testFactory.MaxTokenTTL != nil {
					expectedDuration = *testFactory.MaxTokenTTL
				}

				actualDuration := context.ExpiresAt.Sub(context.IssuedAt)
				if actualDuration < expectedDuration-time.Second || actualDuration > expectedDuration+time.Second {
					t.Errorf("Expected TTL around %v, got %v", expectedDuration, actualDuration)
				}

				// Verify usage tracking was updated
				if testFactory.IssuedCount != 1 {
					t.Errorf("Expected IssuedCount to be 1, got %d", testFactory.IssuedCount)
				}

				if testFactory.LastUsed == nil {
					t.Error("Expected LastUsed to be set")
				}
			}
		})
	}
}

func TestExtractCertField(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		certFields CertFields
		expected   string
	}{
		// CN tests
		{
			name:       "CN field",
			field:      "CN",
			certFields: CertFields{CN: "test-service"},
			expected:   "test-service",
		},
		{
			name:       "commonname field",
			field:      "commonname",
			certFields: CertFields{CN: "test-service"},
			expected:   "test-service",
		},
		{
			name:       "cn lowercase",
			field:      "cn",
			certFields: CertFields{CN: "test-service"},
			expected:   "test-service",
		},

		// Organization tests
		{
			name:       "O field",
			field:      "O",
			certFields: CertFields{O: []string{"TestCorp"}},
			expected:   "TestCorp",
		},
		{
			name:       "O field with multiple - first one",
			field:      "O",
			certFields: CertFields{O: []string{"TestCorp", "SecondOrg"}},
			expected:   "TestCorp", // First one
		},
		{
			name:       "organization field",
			field:      "organization",
			certFields: CertFields{O: []string{"TestCorp"}},
			expected:   "TestCorp",
		},
		{
			name:       "empty organization",
			field:      "O",
			certFields: CertFields{O: []string{}},
			expected:   "",
		},

		// OU tests
		{
			name:       "OU field",
			field:      "OU",
			certFields: CertFields{OU: []string{"Engineering"}},
			expected:   "Engineering",
		},
		{
			name:       "organizationalunit field",
			field:      "organizationalunit",
			certFields: CertFields{OU: []string{"Engineering"}},
			expected:   "Engineering",
		},

		// Country tests
		{
			name:       "C field",
			field:      "C",
			certFields: CertFields{C: []string{"US"}},
			expected:   "US",
		},
		{
			name:       "country field",
			field:      "country",
			certFields: CertFields{C: []string{"US"}},
			expected:   "US",
		},

		// Locality tests
		{
			name:       "L field",
			field:      "L",
			certFields: CertFields{L: []string{"San Francisco"}},
			expected:   "San Francisco",
		},
		{
			name:       "locality field",
			field:      "locality",
			certFields: CertFields{L: []string{"San Francisco"}},
			expected:   "San Francisco",
		},

		// Province tests
		{
			name:       "ST field",
			field:      "ST",
			certFields: CertFields{ST: []string{"California"}},
			expected:   "California",
		},
		{
			name:       "province field",
			field:      "province",
			certFields: CertFields{ST: []string{"California"}},
			expected:   "California",
		},

		// Email tests
		{
			name:       "email field",
			field:      "email",
			certFields: CertFields{Email: []string{"test@example.com"}},
			expected:   "test@example.com",
		},

		// Serial number tests
		{
			name:       "serialnumber field",
			field:      "serialnumber",
			certFields: CertFields{SerialNumber: "SN123456"},
			expected:   "SN123456",
		},
		{
			name:       "serialNumber camelCase",
			field:      "serialNumber",
			certFields: CertFields{SerialNumber: "SN123456"},
			expected:   "SN123456",
		},

		// DNS tests
		{
			name:       "dns field",
			field:      "dns",
			certFields: CertFields{DNS: []string{"api.example.com"}},
			expected:   "api.example.com",
		},
		{
			name:       "DNS uppercase",
			field:      "DNS",
			certFields: CertFields{DNS: []string{"api.example.com"}},
			expected:   "api.example.com",
		},

		// Unknown field tests
		{
			name:       "unknown field",
			field:      "unknown",
			certFields: CertFields{CN: "test"},
			expected:   "",
		},

		// Empty field tests
		{
			name:       "empty field name",
			field:      "",
			certFields: CertFields{CN: "test"},
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertWithFields(t, tt.certFields)
			result := extractCertField(cert, tt.field)

			if result != tt.expected {
				t.Errorf("extractCertField(%s) = %q, want %q", tt.field, result, tt.expected)
			}
		})
	}
}

