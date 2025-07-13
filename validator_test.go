package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Helper to create a test certificate with custom fields
func createTestCertificate(t *testing.T, template *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Set defaults if not provided
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(1)
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-24 * time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, priv
}

// Helper to create a CA certificate
func createTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	ca, caKey := createTestCertificate(t, template)

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	return ca, caKey, pool
}

// Helper to create a client certificate signed by CA
func createClientCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, template *x509.Certificate) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Set defaults
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(2)
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-24 * time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(30 * 24 * time.Hour)
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestValidateClientCert_ValidCertificate(t *testing.T) {
	validator := newCertificateValidator()
	ca, caKey, caPool := createTestCA(t)

	// Create valid client certificate
	clientTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test-client",
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert := createClientCert(t, ca, caKey, clientTemplate)

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	result, err := validator.ValidateClientCert(tlsState, caPool)
	if err != nil {
		t.Fatalf("ValidateClientCert failed: %v", err)
	}

	if result != clientCert {
		t.Error("Expected to get the same certificate back")
	}
}

func TestValidateClientCert_NoCertificate(t *testing.T) {
	validator := newCertificateValidator()
	_, _, caPool := createTestCA(t)

	tests := []struct {
		name     string
		tlsState *tls.ConnectionState
	}{
		{
			name:     "nil TLS state",
			tlsState: nil,
		},
		{
			name: "empty peer certificates",
			tlsState: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.ValidateClientCert(tt.tlsState, caPool)
			if err != ErrNoCertificate {
				t.Errorf("Expected ErrNoCertificate, got %v", err)
			}
		})
	}
}

func TestValidateClientCert_ExpiredCertificate(t *testing.T) {
	validator := newCertificateValidator()
	ca, caKey, caPool := createTestCA(t)

	// Create expired certificate
	clientTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "expired-client",
		},
		NotBefore:   time.Now().Add(-48 * time.Hour),
		NotAfter:    time.Now().Add(-24 * time.Hour), // Expired yesterday
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert := createClientCert(t, ca, caKey, clientTemplate)

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	_, err := validator.ValidateClientCert(tlsState, caPool)
	if err == nil {
		t.Fatal("Expected error for expired certificate")
	}

	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Expected error to mention 'expired', got %v", err)
	}
}

func TestValidateClientCert_NotYetValidCertificate(t *testing.T) {
	validator := newCertificateValidator()
	ca, caKey, caPool := createTestCA(t)

	// Create not yet valid certificate
	clientTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "future-client",
		},
		NotBefore:   time.Now().Add(24 * time.Hour), // Valid tomorrow
		NotAfter:    time.Now().Add(48 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert := createClientCert(t, ca, caKey, clientTemplate)

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	_, err := validator.ValidateClientCert(tlsState, caPool)
	if err == nil {
		t.Fatal("Expected error for not yet valid certificate")
	}

	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("Expected error to mention 'not yet valid', got %v", err)
	}
}

func TestValidateClientCert_MissingClientAuth(t *testing.T) {
	validator := newCertificateValidator()
	ca, caKey, caPool := createTestCA(t)

	// Create certificate without client auth
	clientTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "no-auth-client",
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // Wrong usage
	}
	clientCert := createClientCert(t, ca, caKey, clientTemplate)

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	_, err := validator.ValidateClientCert(tlsState, caPool)
	if err == nil {
		t.Fatal("Expected error for missing client auth")
	}

	// The error could be either our custom message or x509's incompatible key usage
	if !strings.Contains(err.Error(), "client authentication") && !strings.Contains(err.Error(), "incompatible key usage") {
		t.Errorf("Expected error about client authentication or incompatible key usage, got %v", err)
	}
}

func TestValidateClientCert_InvalidChain(t *testing.T) {
	validator := newCertificateValidator()

	// Create a different CA that won't be in our pool
	ca1, caKey1, _ := createTestCA(t)
	_, _, caPool2 := createTestCA(t) // Different CA pool

	// Create certificate signed by ca1 but validate against caPool2
	clientTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "wrong-ca-client",
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert := createClientCert(t, ca1, caKey1, clientTemplate)

	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	_, err := validator.ValidateClientCert(tlsState, caPool2)
	if err == nil {
		t.Fatal("Expected error for invalid chain")
	}

	if !strings.Contains(err.Error(), ErrInvalidCertificate.Error()) {
		t.Errorf("Expected ErrInvalidCertificate, got %v", err)
	}
}

func TestValidateClientCert_WithIntermediates(t *testing.T) {
	validator := newCertificateValidator()

	// Create root CA
	rootCA, rootKey, rootPool := createTestCA(t)

	// Generate intermediate key
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	// Create intermediate CA certificate template
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Intermediate CA"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create intermediate certificate signed by root CA
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCA, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate certificate: %v", err)
	}

	// Create client cert signed by intermediate
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "client-with-intermediate",
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(30 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert := createClientCert(t, intermediateCert, intermediateKey, clientTemplate)

	// Include intermediate in chain
	tlsState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert, intermediateCert},
	}

	result, err := validator.ValidateClientCert(tlsState, rootPool)
	if err != nil {
		t.Fatalf("ValidateClientCert failed: %v", err)
	}

	if result != clientCert {
		t.Error("Expected to get the client certificate back")
	}
}

func TestExtractIdentity(t *testing.T) {
	validator := newCertificateValidator()

	uri, _ := url.Parse("https://example.com/user/123")

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected string
	}{
		{
			name: "Common Name present",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "test-cn",
				},
				DNSNames:     []string{"dns1.example.com", "dns2.example.com"},
				URIs:         []*url.URL{uri},
				SerialNumber: big.NewInt(12345),
			},
			expected: "test-cn",
		},
		{
			name: "No CN, use first DNS SAN",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:     []string{"dns1.example.com", "dns2.example.com"},
				URIs:         []*url.URL{uri},
				SerialNumber: big.NewInt(12345),
			},
			expected: "dns1.example.com",
		},
		{
			name: "No CN or DNS, use URI SAN",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:     []string{},
				URIs:         []*url.URL{uri},
				SerialNumber: big.NewInt(12345),
			},
			expected: "https://example.com/user/123",
		},
		{
			name: "Only serial number",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:     []string{},
				URIs:         []*url.URL{},
				SerialNumber: big.NewInt(12345),
			},
			expected: "12345",
		},
		{
			name: "Empty CN should fall back",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
				DNSNames:     []string{"fallback.example.com"},
				SerialNumber: big.NewInt(12345),
			},
			expected: "fallback.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := validator.ExtractIdentity(tt.cert)
			if identity != tt.expected {
				t.Errorf("ExtractIdentity() = %v, want %v", identity, tt.expected)
			}
		})
	}
}

func TestGetFingerprint(t *testing.T) {
	validator := newCertificateValidator()

	// Create two different certificates
	cert1, _ := createTestCertificate(t, &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "cert1",
		},
		SerialNumber: big.NewInt(1),
	})

	cert2, _ := createTestCertificate(t, &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "cert2",
		},
		SerialNumber: big.NewInt(2),
	})

	// Get fingerprints
	fp1 := validator.GetFingerprint(cert1)
	fp2 := validator.GetFingerprint(cert2)

	// Fingerprints should be different
	if fp1 == fp2 {
		t.Error("Different certificates should have different fingerprints")
	}

	// Fingerprint should be consistent
	fp1Again := validator.GetFingerprint(cert1)
	if fp1 != fp1Again {
		t.Error("Fingerprint should be consistent for the same certificate")
	}

	// Should be valid base64
	if _, err := base64.StdEncoding.DecodeString(fp1); err != nil {
		t.Errorf("Fingerprint should be valid base64: %v", err)
	}

	// Should be 44 characters (base64 of 32 bytes)
	if len(fp1) != 44 {
		t.Errorf("Fingerprint length should be 44, got %d", len(fp1))
	}
}

func TestValidateClientCert_EdgeCases(t *testing.T) {
	validator := newCertificateValidator()
	ca, caKey, caPool := createTestCA(t)

	t.Run("certificate with no ExtKeyUsage", func(t *testing.T) {
		// Certificate with nil ExtKeyUsage
		clientTemplate := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "no-key-usage",
			},
			ExtKeyUsage: nil,
		}
		clientCert := createClientCert(t, ca, caKey, clientTemplate)

		tlsState := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert},
		}

		// Should pass - no ExtKeyUsage means no restriction
		result, err := validator.ValidateClientCert(tlsState, caPool)
		if err != nil {
			t.Fatalf("ValidateClientCert should pass with nil ExtKeyUsage: %v", err)
		}
		if result != clientCert {
			t.Error("Expected to get the certificate back")
		}
	})

	t.Run("certificate with empty ExtKeyUsage", func(t *testing.T) {
		// Certificate with empty ExtKeyUsage slice
		clientTemplate := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "empty-key-usage",
			},
			ExtKeyUsage: []x509.ExtKeyUsage{},
		}
		clientCert := createClientCert(t, ca, caKey, clientTemplate)

		tlsState := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert},
		}

		// Should pass - empty ExtKeyUsage means no restriction
		result, err := validator.ValidateClientCert(tlsState, caPool)
		if err != nil {
			t.Fatalf("ValidateClientCert should pass with empty ExtKeyUsage: %v", err)
		}
		if result != clientCert {
			t.Error("Expected to get the certificate back")
		}
	})

	t.Run("certificate with multiple ExtKeyUsage including ClientAuth", func(t *testing.T) {
		// Certificate with multiple usages
		clientTemplate := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "multi-usage",
			},
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageCodeSigning,
			},
		}
		clientCert := createClientCert(t, ca, caKey, clientTemplate)

		tlsState := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert},
		}

		// Should pass - has ClientAuth among others
		result, err := validator.ValidateClientCert(tlsState, caPool)
		if err != nil {
			t.Fatalf("ValidateClientCert should pass with ClientAuth in ExtKeyUsage: %v", err)
		}
		if result != clientCert {
			t.Error("Expected to get the certificate back")
		}
	})
}

// Test the interface is properly implemented
func TestValidatorInterface(t *testing.T) {
	var _ CertificateValidator = (*defaultCertValidator)(nil)
	var _ CertificateValidator = newCertificateValidator()
}
