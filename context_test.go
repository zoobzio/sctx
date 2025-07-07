package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// Helper function to generate test ECDSA P-256 key pair
func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// Helper function to generate test certificate
func generateTestCertificate(t *testing.T) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
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

func TestContextData_HasPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		scope       string
		want        bool
	}{
		{
			name:        "has permission",
			permissions: []string{"read", "write", "delete"},
			scope:       "write",
			want:        true,
		},
		{
			name:        "does not have permission",
			permissions: []string{"read", "write"},
			scope:       "delete",
			want:        false,
		},
		{
			name:        "empty permissions",
			permissions: []string{},
			scope:       "read",
			want:        false,
		},
		{
			name:        "nil permissions",
			permissions: nil,
			scope:       "read",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cd := &ContextData{
				Permissions: tt.permissions,
			}
			if got := cd.HasPermission(tt.scope); got != tt.want {
				t.Errorf("HasPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContextData_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "expires in 1 second",
			expiresAt: time.Now().Add(1 * time.Second),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cd := &ContextData{
				ExpiresAt: tt.expiresAt,
			}
			if got := cd.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodeAndSign_DecodeAndVerify(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	cert := generateTestCertificate(t)
	fingerprint := getCertificateFingerprint(cert)

	data := &ContextData{
		Type:                   "test",
		ID:                     "test-id",
		Permissions:            []string{"read", "write"},
		IssuedAt:               time.Now(),
		ExpiresAt:              time.Now().Add(1 * time.Hour),
		Issuer:                 "test-issuer",
		CertificateFingerprint: fingerprint,
		ContextID:              "test-context-id",
		RefreshCount:           0,
		FactoryID:              "test-factory",
	}

	// Test encoding and signing
	ctx, err := encodeAndSign(data, privateKey, fingerprint)
	if err != nil {
		t.Fatalf("Failed to encode and sign: %v", err)
	}

	// Verify the context is base64 encoded
	if _, err := base64.URLEncoding.DecodeString(string(ctx)); err != nil {
		t.Errorf("Context is not valid base64: %v", err)
	}

	// Test decoding and verification with correct key
	decoded, err := decodeAndVerify(ctx, publicKey)
	if err != nil {
		t.Fatalf("Failed to decode and verify: %v", err)
	}

	// Verify all fields match
	if decoded.Type != data.Type {
		t.Errorf("Type mismatch: got %v, want %v", decoded.Type, data.Type)
	}
	if decoded.ID != data.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, data.ID)
	}
	if len(decoded.Permissions) != len(data.Permissions) {
		t.Errorf("Permissions length mismatch: got %v, want %v", len(decoded.Permissions), len(data.Permissions))
	}
	if decoded.Issuer != data.Issuer {
		t.Errorf("Issuer mismatch: got %v, want %v", decoded.Issuer, data.Issuer)
	}
	if decoded.CertificateFingerprint != data.CertificateFingerprint {
		t.Errorf("CertificateFingerprint mismatch: got %v, want %v", decoded.CertificateFingerprint, data.CertificateFingerprint)
	}
	if decoded.ContextID != data.ContextID {
		t.Errorf("ContextID mismatch: got %v, want %v", decoded.ContextID, data.ContextID)
	}
	if decoded.RefreshCount != data.RefreshCount {
		t.Errorf("RefreshCount mismatch: got %v, want %v", decoded.RefreshCount, data.RefreshCount)
	}
	if decoded.FactoryID != data.FactoryID {
		t.Errorf("FactoryID mismatch: got %v, want %v", decoded.FactoryID, data.FactoryID)
	}
}

func TestDecodeAndVerify_InvalidSignature(t *testing.T) {
	privateKey1, _ := generateTestKeyPair(t)
	_, publicKey2 := generateTestKeyPair(t) // Different key pair
	cert := generateTestCertificate(t)
	fingerprint := getCertificateFingerprint(cert)

	data := &ContextData{
		Type:        "test",
		ID:          "test-id",
		Permissions: []string{"read"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Issuer:      "test-issuer",
	}

	// Sign with one key
	ctx, err := encodeAndSign(data, privateKey1, fingerprint)
	if err != nil {
		t.Fatalf("Failed to encode and sign: %v", err)
	}

	// Try to verify with different key
	_, err = decodeAndVerify(ctx, publicKey2)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got: %v", err)
	}
}

func TestDecodeAndVerify_ExpiredContext(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	cert := generateTestCertificate(t)
	fingerprint := getCertificateFingerprint(cert)

	data := &ContextData{
		Type:        "test",
		ID:          "test-id",
		Permissions: []string{"read"},
		IssuedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // Already expired
		Issuer:      "test-issuer",
	}

	ctx, err := encodeAndSign(data, privateKey, fingerprint)
	if err != nil {
		t.Fatalf("Failed to encode and sign: %v", err)
	}

	_, err = decodeAndVerify(ctx, publicKey)
	if err != ErrExpiredContext {
		t.Errorf("Expected ErrExpiredContext, got: %v", err)
	}
}

func TestDecodeAndVerify_InvalidContext(t *testing.T) {
	_, publicKey := generateTestKeyPair(t)

	tests := []struct {
		name    string
		context Context
		wantErr error
	}{
		{
			name:    "empty context",
			context: "",
			wantErr: ErrInvalidContext,
		},
		{
			name:    "invalid base64",
			context: Context("not-base64!@#$"),
			wantErr: ErrInvalidContext,
		},
		{
			name:    "valid base64 but invalid json",
			context: Context(base64.URLEncoding.EncodeToString([]byte("not json"))),
			wantErr: ErrInvalidContext,
		},
		{
			name:    "valid json but invalid signature base64",
			context: Context(base64.URLEncoding.EncodeToString([]byte(`{"data":"dGVzdA==","signature":"!!!invalid!!!"}`))),
			wantErr: ErrInvalidContext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeAndVerify(tt.context, publicKey)
			if err != tt.wantErr {
				t.Errorf("decodeAndVerify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetCertificateFingerprint(t *testing.T) {
	cert := generateTestCertificate(t)
	
	fingerprint1 := getCertificateFingerprint(cert)
	fingerprint2 := getCertificateFingerprint(cert)
	
	// Same certificate should produce same fingerprint
	if fingerprint1 != fingerprint2 {
		t.Errorf("Same certificate produced different fingerprints: %v != %v", fingerprint1, fingerprint2)
	}
	
	// Fingerprint should be base64 encoded
	decoded, err := base64.StdEncoding.DecodeString(fingerprint1)
	if err != nil {
		t.Errorf("Fingerprint is not valid base64: %v", err)
	}
	
	// Should be SHA256 hash (32 bytes)
	if len(decoded) != 32 {
		t.Errorf("Fingerprint decoded length = %v, want 32", len(decoded))
	}
	
	// Different certificates should produce different fingerprints
	cert2 := generateTestCertificate(t)
	fingerprint3 := getCertificateFingerprint(cert2)
	if fingerprint1 == fingerprint3 {
		t.Errorf("Different certificates produced same fingerprint")
	}
}

func TestEncodeAndSign_ModifiedFingerprint(t *testing.T) {
	privateKey, _ := generateTestKeyPair(t)
	cert := generateTestCertificate(t)
	originalFingerprint := getCertificateFingerprint(cert)

	data := &ContextData{
		Type:        "test",
		ID:          "test-id",
		Permissions: []string{"read"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Issuer:      "test-issuer",
	}

	// Sign with original fingerprint
	ctx, err := encodeAndSign(data, privateKey, originalFingerprint)
	if err != nil {
		t.Fatalf("Failed to encode and sign: %v", err)
	}

	// The encoded data should contain the fingerprint
	decoded, err := decodeAndVerify(ctx, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if decoded.CertificateFingerprint != originalFingerprint {
		t.Errorf("Fingerprint not preserved: got %v, want %v", decoded.CertificateFingerprint, originalFingerprint)
	}
}