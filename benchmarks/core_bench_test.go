package benchmarks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/zoobzio/sctx"
)

// Global service setup - sctx Bootstrap can only be called once
var (
	globalAdmin    *sctx.ServiceAdmin[map[string]interface{}]
	globalService  *sctx.ContextService[map[string]interface{}]
	globalCert     *x509.Certificate
	setupOnce      sync.Once
)

// setupGlobalService creates the service once for all benchmarks
func setupGlobalService() {
	setupOnce.Do(func() {
		// Generate P-256 key pair
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		// Create minimal CA setup
		caTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{CommonName: "Test CA"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA: true,
		}

		caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
		caCert, _ := x509.ParseCertificate(caCertDER)

		caPool := x509.NewCertPool()
		caPool.AddCert(caCert)

		// Minimal registry
		registry := sctx.NewMemoryRegistry()
		registry.Register("test-service", sctx.RegistryEntry{
			Type:        "service",
			Permissions: []string{"read", "write"},
		})

		// Add more services for registry benchmarks
		services := []string{
			"auth-service", "user-service", "payment-service", "order-service",
			"notification-service", "analytics-service", "admin-service", "gateway-service",
		}
		for _, service := range services {
			registry.Register(service, sctx.RegistryEntry{
				Type:        "service",
				Permissions: []string{"api:read", "api:write"},
			})
		}

		// Service config (explicitly specify ECDSA for compatibility with ECDSA key)
		config := sctx.ContextServiceConfig{
			CAPool:        caPool,
			PrivateKey:    privateKey,
			Algorithm:     sctx.CryptoECDSAP256, // Use ECDSA since we have an ECDSA key
			Registry:      registry,
			IssuerName:    "test",
			ContextTTL:    15 * time.Minute,
			AdminIdentity: "admin",
		}

		admin, err := sctx.Bootstrap(config, make(map[string]interface{}))
		if err != nil {
			panic(fmt.Sprintf("Bootstrap failed: %v", err))
		}

		// Configure minimal pipeline
		ops := admin.GetOperations()
		securityProcessor := sctx.NewSecurityProcessor[map[string]interface{}](ops)
		
		admin.Register(
			securityProcessor.CertificateValidator(),
			securityProcessor.RegistryLookup(),
			securityProcessor.DefaultDeny(),
		)

		// Complete bootstrap to enable the service
		err = admin.CompleteBootstrap()
		if err != nil {
			panic(fmt.Sprintf("CompleteBootstrap failed: %v", err))
		}

		// Create client certificate using the same CA
		clientTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{CommonName: "test-service"},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &privateKey.PublicKey, privateKey)
		clientCert, _ := x509.ParseCertificate(clientCertDER)

		// Store globally
		globalAdmin = admin
		globalService = admin.GetService()
		globalCert = clientCert
	})
}

// CORE SCTX CAPABILITIES BENCHMARKS

// BenchmarkContextGeneration - The primary sctx capability: generate signed security contexts
func BenchmarkContextGeneration(b *testing.B) {
	setupGlobalService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := globalService.RequestContext(globalCert)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkContextVerification - The primary validation capability: verify signed contexts
func BenchmarkContextVerification(b *testing.B) {
	setupGlobalService()

	// Generate a context to verify
	token, _ := globalService.RequestContext(globalCert)
	publicKey := globalAdmin.GetPublicKey()
	ctx := token.Context()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sctx.VerifyContext(ctx, publicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFullAuthFlow - Complete authentication flow (generate + verify)
func BenchmarkFullAuthFlow(b *testing.B) {
	setupGlobalService()
	publicKey := globalAdmin.GetPublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate context
		token, err := globalService.RequestContext(globalCert)
		if err != nil {
			b.Fatal(err)
		}

		// Verify context
		_, err = sctx.VerifyContext(token.Context(), publicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPermissionChecking - Permission validation after context verification
func BenchmarkPermissionChecking(b *testing.B) {
	setupGlobalService()

	// Get verified context data
	token, _ := globalService.RequestContext(globalCert)
	publicKey := globalAdmin.GetPublicKey()
	data, _ := sctx.VerifyContext(token.Context(), publicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Test multiple permission checks (realistic usage)
		_ = data.HasPermission("read")
		_ = data.HasPermission("write")
		_ = data.HasPermission("admin")
		_ = data.HasPermission("delete")
	}
}

// BenchmarkTokenOperations - Token utility operations
func BenchmarkTokenOperations(b *testing.B) {
	setupGlobalService()

	token, _ := globalService.RequestContext(globalCert)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Common token operations
		_ = token.IsExpired()
		_ = token.ExpiresAt()
		_ = token.TimeUntilExpiry()
		_ = token.Fingerprint()
		_ = token.String()
	}
}

// BenchmarkServiceDiscovery - Registry-based service lookup
func BenchmarkServiceDiscovery(b *testing.B) {
	registry := sctx.NewMemoryRegistry()
	
	// Add realistic number of services
	services := []string{
		"auth-service", "user-service", "payment-service", "order-service",
		"notification-service", "analytics-service", "admin-service", "gateway-service",
	}
	
	for _, service := range services {
		registry.Register(service, sctx.RegistryEntry{
			Type:        "service",
			Permissions: []string{"api:read", "api:write"},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Lookup different services (realistic pattern)
		for _, service := range services {
			_, err := registry.Lookup(service)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkCompatibilityChecking - Inter-service authorization verification
func BenchmarkCompatibilityChecking(b *testing.B) {
	setupGlobalService()

	// Create two contexts for compatibility testing
	token1, _ := globalService.RequestContext(globalCert)
	token2, _ := globalService.RequestContext(globalCert)
	publicKey := globalAdmin.GetPublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sctx.CheckCompatibility(token1.Context(), token2.Context(), publicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkServiceHealthCheck - Operational health verification
func BenchmarkServiceHealthCheck(b *testing.B) {
	setupGlobalService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := globalService.HealthCheck()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// CONCURRENCY AND SCALABILITY BENCHMARKS

// BenchmarkConcurrentAuthentication - Multiple services authenticating simultaneously
func BenchmarkConcurrentAuthentication(b *testing.B) {
	setupGlobalService()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := globalService.RequestContext(globalCert)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkConcurrentVerification - Multiple verification operations
func BenchmarkConcurrentVerification(b *testing.B) {
	setupGlobalService()

	token, _ := globalService.RequestContext(globalCert)
	publicKey := globalAdmin.GetPublicKey()
	ctx := token.Context()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := sctx.VerifyContext(ctx, publicKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// MEMORY AND ALLOCATION BENCHMARKS

// BenchmarkMemoryAllocations - Memory usage during authentication
func BenchmarkMemoryAllocations(b *testing.B) {
	setupGlobalService()
	publicKey := globalAdmin.GetPublicKey()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		token, err := globalService.RequestContext(globalCert)
		if err != nil {
			b.Fatal(err)
		}

		_, err = sctx.VerifyContext(token.Context(), publicKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// SCALABILITY BENCHMARKS

// BenchmarkLargeRegistry - Performance with many registered services
func BenchmarkLargeRegistry(b *testing.B) {
	registry := sctx.NewMemoryRegistry()

	// Register 1000 services
	for i := 0; i < 1000; i++ {
		registry.Register(fmt.Sprintf("service-%d", i), sctx.RegistryEntry{
			Type:        "service",
			Permissions: []string{"read"},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := registry.Lookup("service-500") // Middle of the range
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkContextReuse - Token refresh/reuse patterns
func BenchmarkContextReuse(b *testing.B) {
	setupGlobalService()

	// Create initial context
	_, err := globalService.RequestContext(globalCert)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Subsequent requests (simulates refresh pattern)
		_, err := globalService.RequestContext(globalCert)
		if err != nil {
			b.Fatal(err)
		}
	}
}