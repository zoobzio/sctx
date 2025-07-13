package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Helper function to create a test ECDSA P-256 key
func createTestIssuerKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	return key
}

func TestNewContextIssuer(t *testing.T) {
	tests := []struct {
		name       string
		privateKey *ecdsa.PrivateKey
		issuerName string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "valid P-256 key",
			privateKey: createTestIssuerKey(t),
			issuerName: "test-issuer",
			wantErr:    false,
		},
		{
			name:       "nil private key",
			privateKey: nil,
			issuerName: "test-issuer",
			wantErr:    true,
			errMsg:     "private key is required",
		},
		{
			name:       "empty issuer name",
			privateKey: createTestIssuerKey(t),
			issuerName: "",
			wantErr:    false, // Empty issuer name is allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := newContextIssuer(tt.privateKey, tt.issuerName)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("Expected error %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if issuer == nil {
				t.Fatal("newContextIssuer returned nil")
			}

			// Verify it implements the interface
			var _ ContextIssuer = issuer

			// Verify public key is accessible
			pubKey := issuer.GetPublicKey()
			if pubKey == nil {
				t.Error("GetPublicKey returned nil")
			}

			// Verify public key matches private key
			if tt.privateKey != nil && pubKey != &tt.privateKey.PublicKey {
				t.Error("Public key doesn't match private key")
			}
		})
	}
}

func TestNewContextIssuer_InvalidCurve(t *testing.T) {
	// Generate a key with a different curve (P-384)
	invalidKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-384 key: %v", err)
	}

	issuer, err := newContextIssuer(invalidKey, "test-issuer")
	if err == nil {
		t.Error("Expected error for non-P-256 key")
	}

	if issuer != nil {
		t.Error("Expected nil issuer for invalid key")
	}

	expectedErr := "private key must use P-256 curve for NIST compliance"
	if err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
	}
}

func TestContextIssuer_GenerateContextID(t *testing.T) {
	key := createTestIssuerKey(t)
	issuer, err := newContextIssuer(key, "test-issuer")
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	// Generate multiple IDs
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := issuer.GenerateContextID()

		// Should not be empty
		if id == "" {
			t.Error("GenerateContextID returned empty string")
		}

		// Should be valid base64 URL encoding
		decoded, err := base64.URLEncoding.DecodeString(id)
		if err != nil {
			t.Errorf("Generated ID is not valid base64 URL encoding: %v", err)
		}

		// Should be 16 bytes (128 bits) when decoded
		if len(decoded) != 16 {
			t.Errorf("Expected 16 bytes when decoded, got %d", len(decoded))
		}

		// Should be unique
		if ids[id] {
			t.Errorf("Duplicate context ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestContextIssuer_IssueContext(t *testing.T) {
	key := createTestIssuerKey(t)
	issuerName := "test-issuer"
	issuer, err := newContextIssuer(key, issuerName)
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	fingerprint := "test-fingerprint"

	t.Run("valid context data", func(t *testing.T) {
		data := &ContextData{
			ContextID:   "test-context-id",
			Issuer:      "custom-issuer",
			ID:          "test-user",
			Permissions: []string{"read", "write"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, fingerprint)
		if err != nil {
			t.Fatalf("IssueContext failed: %v", err)
		}

		if context == "" {
			t.Error("IssueContext returned empty context")
		}

		// Verify the context can be decoded and verified
		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Fatalf("Failed to decode and verify issued context: %v", err)
		}

		// Verify data matches
		if decoded.ContextID != data.ContextID {
			t.Errorf("Expected ContextID %s, got %s", data.ContextID, decoded.ContextID)
		}

		if decoded.Issuer != data.Issuer {
			t.Errorf("Expected Issuer %s, got %s", data.Issuer, decoded.Issuer)
		}

		if decoded.ID != data.ID {
			t.Errorf("Expected ID %s, got %s", data.ID, decoded.ID)
		}
	})

	t.Run("nil context data", func(t *testing.T) {
		context, err := issuer.IssueContext(nil, fingerprint)
		if err == nil {
			t.Error("Expected error for nil context data")
		}

		if context != "" {
			t.Error("Expected empty context for nil data")
		}

		expectedErr := "context data is required"
		if err.Error() != expectedErr {
			t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
		}
	})

	t.Run("auto-set issuer", func(t *testing.T) {
		data := &ContextData{
			ContextID:   "test-context-id",
			Issuer:      "", // Empty - should be auto-set
			ID:          "test-user",
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, fingerprint)
		if err != nil {
			t.Fatalf("IssueContext failed: %v", err)
		}

		// Verify issuer was set
		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Fatalf("Failed to decode context: %v", err)
		}

		if decoded.Issuer != issuerName {
			t.Errorf("Expected auto-set issuer %s, got %s", issuerName, decoded.Issuer)
		}
	})

	t.Run("auto-generate context ID", func(t *testing.T) {
		data := &ContextData{
			ContextID:   "", // Empty - should be auto-generated
			Issuer:      "custom-issuer",
			ID:          "test-user",
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, fingerprint)
		if err != nil {
			t.Fatalf("IssueContext failed: %v", err)
		}

		// Verify context ID was generated
		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Fatalf("Failed to decode context: %v", err)
		}

		if decoded.ContextID == "" {
			t.Error("Context ID should have been auto-generated")
		}

		// Should be valid base64 URL encoding
		_, err = base64.URLEncoding.DecodeString(decoded.ContextID)
		if err != nil {
			t.Errorf("Auto-generated context ID is not valid base64: %v", err)
		}
	})

	t.Run("preserve existing context ID and issuer", func(t *testing.T) {
		originalContextID := "original-context-id"
		originalIssuer := "original-issuer"

		data := &ContextData{
			ContextID:   originalContextID,
			Issuer:      originalIssuer,
			ID:          "test-user",
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, fingerprint)
		if err != nil {
			t.Fatalf("IssueContext failed: %v", err)
		}

		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Fatalf("Failed to decode context: %v", err)
		}

		if decoded.ContextID != originalContextID {
			t.Errorf("Expected preserved ContextID %s, got %s", originalContextID, decoded.ContextID)
		}

		if decoded.Issuer != originalIssuer {
			t.Errorf("Expected preserved Issuer %s, got %s", originalIssuer, decoded.Issuer)
		}
	})
}

func TestContextIssuer_GetPublicKey(t *testing.T) {
	key := createTestIssuerKey(t)
	issuer, err := newContextIssuer(key, "test-issuer")
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	pubKey := issuer.GetPublicKey()
	if pubKey == nil {
		t.Error("GetPublicKey returned nil")
	}

	// Should be the same as the private key's public key
	if pubKey != &key.PublicKey {
		t.Error("GetPublicKey didn't return the correct public key")
	}

	// Should be P-256
	if pubKey.Curve != elliptic.P256() {
		t.Error("Public key should use P-256 curve")
	}
}

func TestContextIssuer_Integration(t *testing.T) {
	// Test full integration: create issuer, issue context, verify it works with validation
	key := createTestIssuerKey(t)
	issuer, err := newContextIssuer(key, "integration-issuer")
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	fingerprint := "integration-test-fingerprint"
	data := &ContextData{
		ID:    "integration-user",
		Permissions: []string{"integration:read", "integration:write"},
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	// Issue the context
	context, err := issuer.IssueContext(data, fingerprint)
	if err != nil {
		t.Fatalf("Failed to issue context: %v", err)
	}

	// Verify it can be decoded
	decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
	if err != nil {
		t.Fatalf("Failed to decode issued context: %v", err)
	}

	// Test HasPermission
	if !decoded.HasPermission("integration:read") {
		t.Error("Context should have integration:read permission")
	}

	if !decoded.HasPermission("integration:write") {
		t.Error("Context should have integration:write permission")
	}

	if decoded.HasPermission("integration:admin") {
		t.Error("Context should not have integration:admin permission")
	}

	// Test IsExpired
	if decoded.IsExpired() {
		t.Error("Context should not be expired")
	}

	// Test with expired context
	expiredData := &ContextData{
		ID:    "expired-user",
		Permissions: []string{"read"},
		ExpiresAt:   time.Now().Add(-time.Hour), // Expired 1 hour ago
	}

	expiredContext, err := issuer.IssueContext(expiredData, fingerprint)
	if err != nil {
		t.Fatalf("Failed to issue expired context: %v", err)
	}

	// decodeAndVerify should return an error for expired contexts
	_, err = decodeAndVerify(expiredContext, issuer.GetPublicKey())
	if err == nil {
		t.Error("decodeAndVerify should return error for expired context")
	}
	if err != ErrExpiredContext {
		t.Errorf("Expected ErrExpiredContext, got %v", err)
	}
}

func TestContextIssuer_EdgeCases(t *testing.T) {
	key := createTestIssuerKey(t)
	issuer, err := newContextIssuer(key, "edge-case-issuer")
	if err != nil {
		t.Fatalf("Failed to create issuer: %v", err)
	}

	t.Run("very long identity", func(t *testing.T) {
		longIdentity := strings.Repeat("a", 10000)
		data := &ContextData{
			ID:    longIdentity,
			Permissions: []string{"read"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, "fingerprint")
		if err != nil {
			t.Errorf("Failed to issue context with long identity: %v", err)
		}

		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Errorf("Failed to decode context with long identity: %v", err)
		}

		if decoded.ID != longIdentity {
			t.Error("Long identity was not preserved")
		}
	})

	t.Run("many permissions", func(t *testing.T) {
		manyPermissions := make([]string, 1000)
		for i := range manyPermissions {
			manyPermissions[i] = strings.Repeat("perm", i+1)
		}

		data := &ContextData{
			ID:    "user",
			Permissions: manyPermissions,
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, "fingerprint")
		if err != nil {
			t.Errorf("Failed to issue context with many permissions: %v", err)
		}

		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Errorf("Failed to decode context with many permissions: %v", err)
		}

		if len(decoded.Permissions) != len(manyPermissions) {
			t.Errorf("Expected %d permissions, got %d", len(manyPermissions), len(decoded.Permissions))
		}
	})

	t.Run("special characters in data", func(t *testing.T) {
		data := &ContextData{
			ContextID:   "context-éñ-🔐",
			Issuer:      "issuer-with-special-chars-éñ-🔐",
			ID:    "identity-éñ-🔐-\n\t",
			Permissions: []string{"permission:éñ:🔐", "perm\nwith\nnewlines"},
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, "fingerprint-éñ-🔐")
		if err != nil {
			t.Errorf("Failed to issue context with special characters: %v", err)
		}

		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Errorf("Failed to decode context with special characters: %v", err)
		}

		if decoded.ID != data.ID {
			t.Error("Special characters in identity were not preserved")
		}
	})

	t.Run("empty permissions", func(t *testing.T) {
		data := &ContextData{
			ID:    "user",
			Permissions: []string{},
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, "fingerprint")
		if err != nil {
			t.Errorf("Failed to issue context with empty permissions: %v", err)
		}

		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Errorf("Failed to decode context with empty permissions: %v", err)
		}

		if len(decoded.Permissions) != 0 {
			t.Errorf("Expected 0 permissions, got %d", len(decoded.Permissions))
		}
	})

	t.Run("nil permissions", func(t *testing.T) {
		data := &ContextData{
			ID:    "user",
			Permissions: nil,
			ExpiresAt:   time.Now().Add(time.Hour),
		}

		context, err := issuer.IssueContext(data, "fingerprint")
		if err != nil {
			t.Errorf("Failed to issue context with nil permissions: %v", err)
		}

		decoded, err := decodeAndVerify(context, issuer.GetPublicKey())
		if err != nil {
			t.Errorf("Failed to decode context with nil permissions: %v", err)
		}

		// nil permissions should be handled gracefully
		// JSON unmarshaling will result in nil slice being preserved
		if decoded.Permissions != nil && len(decoded.Permissions) != 0 {
			t.Error("Nil permissions should remain nil or empty after decoding")
		}
	})
}

func TestContextIssuer_MultipleIssuers(t *testing.T) {
	// Test that contexts from different issuers can't be verified with wrong keys
	issuer1Key := createTestIssuerKey(t)
	issuer1, err := newContextIssuer(issuer1Key, "issuer1")
	if err != nil {
		t.Fatalf("Failed to create issuer1: %v", err)
	}

	issuer2Key := createTestIssuerKey(t)
	issuer2, err := newContextIssuer(issuer2Key, "issuer2")
	if err != nil {
		t.Fatalf("Failed to create issuer2: %v", err)
	}

	data := &ContextData{
		ID:    "test-user",
		Permissions: []string{"read"},
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	fingerprint := "test-fingerprint"

	// Issue context with issuer1
	context1, err := issuer1.IssueContext(data, fingerprint)
	if err != nil {
		t.Fatalf("Failed to issue context with issuer1: %v", err)
	}

	// Should verify with issuer1's key
	_, err = decodeAndVerify(context1, issuer1.GetPublicKey())
	if err != nil {
		t.Errorf("Context should verify with correct issuer key: %v", err)
	}

	// Should NOT verify with issuer2's key
	_, err = decodeAndVerify(context1, issuer2.GetPublicKey())
	if err == nil {
		t.Error("Context should not verify with wrong issuer key")
	}
}