package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// Test processors for pipeline functionality
func certificateValidationProcessor(req *ContextRequest[TestMetadata]) (*ContextRequest[TestMetadata], error) {
	// Track processing
	req.Metadata.ProcessedBy = append(req.Metadata.ProcessedBy, "certificate-validation")

	// Default to allowed, processors can deny
	req.Allowed = true

	// Validate certificate exists - this is a hard stop
	if req.Certificate == nil {
		req.Allowed = false
		req.DenialReason = "no client certificate provided"
		return req, nil // Return early, don't continue processing
	}

	// Extract identity and fingerprint
	req.Identity = req.Certificate.Subject.CommonName
	if req.Identity == "" && len(req.Certificate.DNSNames) > 0 {
		req.Identity = req.Certificate.DNSNames[0]
	}
	if req.Identity == "" {
		req.Allowed = false
		req.DenialReason = "no identity found in certificate"
		return req, nil
	}

	// Generate fingerprint (simple version for testing)
	req.Fingerprint = fmt.Sprintf("test-fp-%s", req.Identity)

	return req, nil
}

func authorizationProcessor(req *ContextRequest[TestMetadata]) (*ContextRequest[TestMetadata], error) {
	// Track processing  
	req.Metadata.ProcessedBy = append(req.Metadata.ProcessedBy, "authorization")

	// Skip processing if already denied by earlier processor
	if !req.Allowed && req.DenialReason != "" {
		return req, nil
	}

	// Simple authorization logic for testing
	if req.Identity == "allowed-client" {
		req.Allowed = true
		// Set up registry entry for token generation
		req.RegistryEntry = &RegistryEntry{
			Type:        "client", 
			Permissions: []string{"read", "write"},
		}
	} else if req.Identity == "admin-client" {
		req.Allowed = true
		// Set up admin registry entry
		req.RegistryEntry = &RegistryEntry{
			Type:        "admin",
			Permissions: []string{"admin:access", "read", "write"},
		}
	} else {
		req.Allowed = false
		req.DenialReason = fmt.Sprintf("identity '%s' not authorized", req.Identity)
	}

	return req, nil
}

func TestPipelineProcessors(t *testing.T) {
	// Reset bootstrap state
	resetBootstrapForTesting()

	// Create test configuration
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	config := ContextServiceConfig{
		CAPool:        x509.NewCertPool(),
		PrivateKey:    privateKey,
		Registry:      newMockRegistry(),
		IssuerName:    "Test Issuer",
		ContextTTL:    15 * time.Minute,
		AdminIdentity: "admin-client",
	}

	// Bootstrap service
	admin, err := Bootstrap(config, createTestMetadata())
	if err != nil {
		t.Fatalf("Bootstrap failed: %v", err)
	}

	// Register processors
	admin.Register(
		certificateValidationProcessor,
		authorizationProcessor,
	)

	service := admin.GetService()

	t.Run("no certificate", func(t *testing.T) {
		_, err := service.RequestContext(nil)
		if err == nil {
			t.Fatal("Expected error for nil certificate")
		}
		if err.Error() != "access denied: no client certificate provided" {
			t.Errorf("Expected specific denial message, got: %v", err)
		}
	})

	t.Run("allowed client", func(t *testing.T) {
		cert := createTestCertWithCN(t, "allowed-client")
		token, err := service.RequestContext(cert)
		if err != nil {
			t.Fatalf("Expected successful token for allowed client, got: %v", err)
		}
		if token == nil {
			t.Fatal("Expected token, got nil")
		}
	})

	t.Run("denied client", func(t *testing.T) {
		cert := createTestCertWithCN(t, "denied-client")
		_, err := service.RequestContext(cert)
		if err == nil {
			t.Fatal("Expected error for denied client")
		}
		if err.Error() != "access denied: identity 'denied-client' not authorized" {
			t.Errorf("Expected specific denial message, got: %v", err)
		}
	})

	t.Run("metadata processing", func(t *testing.T) {
		// This test would need access to the processed metadata
		// For now, just verify the pipeline runs
		cert := createTestCertWithCN(t, "allowed-client")
		_, err := service.RequestContext(cert)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		// In a real implementation, we might return the processed metadata
		// or have a way to inspect it for testing
	})
}

// Helper to create test certificate with specific CN
func createTestCertWithCN(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}