package sctx

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Test ContextData methods
func TestContextData_HasPermission(t *testing.T) {
	cd := &ContextData{
		Permissions: []string{"read", "write", "admin:access"},
	}

	tests := []struct {
		name       string
		permission string
		expected   bool
	}{
		{"has read permission", "read", true},
		{"has write permission", "write", true},
		{"has admin:access permission", "admin:access", true},
		{"does not have delete permission", "delete", false},
		{"does not have empty permission", "", false},
		{"case sensitive", "READ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cd.HasPermission(tt.permission); got != tt.expected {
				t.Errorf("HasPermission(%q) = %v, want %v", tt.permission, got, tt.expected)
			}
		})
	}
}

func TestContextData_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{"expired 1 hour ago", now.Add(-1 * time.Hour), true},
		{"expires in 1 hour", now.Add(1 * time.Hour), false},
		{"expires in 1 second", now.Add(1 * time.Second), false}, // Close to expiring but safe margin
		{"expired 1 millisecond ago", now.Add(-1 * time.Millisecond), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cd := &ContextData{
				ExpiresAt: tt.expiresAt,
			}
			if got := cd.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Test cryptographic functions
func TestEncodeAndSign_ValidData(t *testing.T) {
	// Generate test key
	_, signer := generateTestECDSAKey(t)

	data := &ContextData{
		Type:        "service",
		ID:          "test-service",
		Permissions: []string{"read", "write"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Issuer:      "test-issuer",
		ContextID:   "test-context-123",
	}

	fingerprint := "test-fingerprint"

	ctx, err := encodeAndSign(data, signer, fingerprint)
	if err != nil {
		t.Fatalf("encodeAndSign failed: %v", err)
	}

	// Verify the context is base64 encoded
	if _, err := base64.URLEncoding.DecodeString(string(ctx)); err != nil {
		t.Errorf("Context is not valid base64 URL encoding: %v", err)
	}

	// Verify it's not empty
	if len(ctx) == 0 {
		t.Error("Context should not be empty")
	}

	// Verify the fingerprint was set in the data
	if data.CertificateFingerprint != fingerprint {
		t.Errorf("Fingerprint not set: got %q, want %q", data.CertificateFingerprint, fingerprint)
	}
}

func TestDecodeAndVerify_ValidSignature(t *testing.T) {
	// Generate test key
	privateKey, signer := generateTestECDSAKey(t)

	originalData := &ContextData{
		Type:        "service",
		ID:          "test-service",
		Permissions: []string{"read", "write"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Issuer:      "test-issuer",
		ContextID:   "test-context-123",
	}

	fingerprint := "test-fingerprint"

	// Sign the data
	ctx, err := encodeAndSign(originalData, signer, fingerprint)
	if err != nil {
		t.Fatalf("encodeAndSign failed: %v", err)
	}

	// Verify with correct public key
	verifiedData, err := decodeAndVerify(ctx, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("decodeAndVerify failed: %v", err)
	}

	// Check all fields match
	if verifiedData.Type != originalData.Type {
		t.Errorf("Type mismatch: got %v, want %v", verifiedData.Type, originalData.Type)
	}
	if verifiedData.ID != originalData.ID {
		t.Errorf("ID mismatch: got %v, want %v", verifiedData.ID, originalData.ID)
	}
	if len(verifiedData.Permissions) != len(originalData.Permissions) {
		t.Errorf("Permissions length mismatch: got %d, want %d", len(verifiedData.Permissions), len(originalData.Permissions))
	}
	if verifiedData.CertificateFingerprint != fingerprint {
		t.Errorf("Fingerprint mismatch: got %v, want %v", verifiedData.CertificateFingerprint, fingerprint)
	}
}

func TestDecodeAndVerify_InvalidSignature(t *testing.T) {
	// Generate two different keys
	_, signer1 := generateTestECDSAKey(t)
	privateKey2, _ := generateTestECDSAKey(t)

	data := &ContextData{
		Type:        "service",
		ID:          "test-service",
		Permissions: []string{"read"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Issuer:      "test-issuer",
		ContextID:   "test-context-123",
	}

	// Sign with key1
	ctx, err := encodeAndSign(data, signer1, "test-fingerprint")
	if err != nil {
		t.Fatalf("encodeAndSign failed: %v", err)
	}

	// Try to verify with key2 (should fail)
	_, err = decodeAndVerify(ctx, &privateKey2.PublicKey)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

func TestDecodeAndVerify_TamperedData(t *testing.T) {
	privateKey, signer := generateTestECDSAKey(t)

	data := &ContextData{
		Type:        "service",
		ID:          "test-service",
		Permissions: []string{"read"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Issuer:      "test-issuer",
		ContextID:   "test-context-123",
	}

	ctx, err := encodeAndSign(data, signer, "test-fingerprint")
	if err != nil {
		t.Fatalf("encodeAndSign failed: %v", err)
	}

	// Tamper with the context by modifying the middle of the base64 string
	ctxStr := string(ctx)
	if len(ctxStr) < 10 {
		t.Fatal("Context too short to tamper with")
	}
	// Change a character in the middle to ensure we're tampering with actual data
	midPoint := len(ctxStr) / 2
	tamperedBytes := []byte(ctxStr)
	// Find a character that's not the one we're changing to
	if tamperedBytes[midPoint] == 'A' {
		tamperedBytes[midPoint] = 'B'
	} else {
		tamperedBytes[midPoint] = 'A'
	}
	tamperedCtx := Context(tamperedBytes)

	_, err = decodeAndVerify(tamperedCtx, &privateKey.PublicKey)
	if err == nil {
		t.Error("Expected error for tampered data, got nil")
	}
	// Could be either invalid context or invalid signature depending on what was tampered
	if err != ErrInvalidContext && err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidContext or ErrInvalidSignature, got %v", err)
	}
}

func TestDecodeAndVerify_ExpiredContext(t *testing.T) {
	privateKey, signer := generateTestECDSAKey(t)

	// Create already expired context
	data := &ContextData{
		Type:        "service",
		ID:          "test-service",
		Permissions: []string{"read"},
		IssuedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		Issuer:      "test-issuer",
		ContextID:   "test-context-123",
	}

	ctx, err := encodeAndSign(data, signer, "test-fingerprint")
	if err != nil {
		t.Fatalf("encodeAndSign failed: %v", err)
	}

	_, err = decodeAndVerify(ctx, &privateKey.PublicKey)
	if err != ErrExpiredContext {
		t.Errorf("Expected ErrExpiredContext, got %v", err)
	}
}

func TestDecodeAndVerify_InvalidFormats(t *testing.T) {
	privateKey, _ := generateTestECDSAKey(t)

	tests := []struct {
		name    string
		context Context
		errWant error
	}{
		{
			name:    "empty context",
			context: "",
			errWant: ErrInvalidContext,
		},
		{
			name:    "invalid base64",
			context: Context("not-base64!@#$"),
			errWant: ErrInvalidContext,
		},
		{
			name:    "valid base64 but not JSON",
			context: Context(base64.URLEncoding.EncodeToString([]byte("not json"))),
			errWant: ErrInvalidContext,
		},
		{
			name:    "valid JSON but wrong structure",
			context: Context(base64.URLEncoding.EncodeToString([]byte(`{"wrong": "structure"}`))),
			errWant: ErrInvalidSignature, // Fails at signature decode, not context structure
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeAndVerify(tt.context, &privateKey.PublicKey)
			if err != tt.errWant {
				t.Errorf("decodeAndVerify() error = %v, want %v", err, tt.errWant)
			}
		})
	}
}

func TestEncodeAndSign_EdgeCases(t *testing.T) {
	_, signer := generateTestECDSAKey(t)

	tests := []struct {
		name        string
		data        *ContextData
		fingerprint string
		wantErr     bool
	}{
		{
			name: "empty permissions",
			data: &ContextData{
				Type:        "service",
				ID:          "test",
				Permissions: []string{},
				IssuedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			fingerprint: "fp",
			wantErr:     false,
		},
		{
			name: "nil permissions",
			data: &ContextData{
				Type:        "service",
				ID:          "test",
				Permissions: nil,
				IssuedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			fingerprint: "fp",
			wantErr:     false,
		},
		{
			name: "empty fingerprint",
			data: &ContextData{
				Type:        "service",
				ID:          "test",
				Permissions: []string{"read"},
				IssuedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			fingerprint: "",
			wantErr:     false, // Empty fingerprint is allowed
		},
		{
			name: "very long ID",
			data: &ContextData{
				Type:        "service",
				ID:          strings.Repeat("a", 1000),
				Permissions: []string{"read"},
				IssuedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(time.Hour),
			},
			fingerprint: "fp",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeAndSign(tt.data, signer, tt.fingerprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("encodeAndSign() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRoundTripWithDifferentData(t *testing.T) {
	privateKey, signer := generateTestECDSAKey(t)

	testCases := []struct {
		name string
		data *ContextData
	}{
		{
			name: "minimal data",
			data: &ContextData{
				Type:        "service",
				ID:          "minimal",
				Permissions: []string{"read"},
				IssuedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(time.Hour),
			},
		},
		{
			name: "full data",
			data: &ContextData{
				Type:         "admin",
				ID:           "full-service",
				Permissions:  []string{"read", "write", "delete", "admin:*"},
				IssuedAt:     time.Now(),
				ExpiresAt:    time.Now().Add(24 * time.Hour),
				Issuer:       "test-issuer",
				ContextID:    "ctx-12345",
				RefreshCount: 5,
				FactoryID:    "factory-abc",
			},
		},
		{
			name: "special characters in ID",
			data: &ContextData{
				Type:        "service",
				ID:          "service-with-special-chars-éñ",
				Permissions: []string{"read"},
				IssuedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(time.Hour),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fingerprint := "test-fp-" + tc.name

			// Encode and sign
			ctx, err := encodeAndSign(tc.data, signer, fingerprint)
			if err != nil {
				t.Fatalf("encodeAndSign failed: %v", err)
			}

			// Decode and verify
			decoded, err := decodeAndVerify(ctx, &privateKey.PublicKey)
			if err != nil {
				t.Fatalf("decodeAndVerify failed: %v", err)
			}

			// Verify fingerprint was correctly bound
			if decoded.CertificateFingerprint != fingerprint {
				t.Errorf("Fingerprint mismatch: got %v, want %v", decoded.CertificateFingerprint, fingerprint)
			}

			// Verify core fields
			if decoded.Type != tc.data.Type {
				t.Errorf("Type mismatch: got %v, want %v", decoded.Type, tc.data.Type)
			}
			if decoded.ID != tc.data.ID {
				t.Errorf("ID mismatch: got %v, want %v", decoded.ID, tc.data.ID)
			}
		})
	}
}

// Test for potential timing attacks in signature verification
func TestDecodeAndVerify_ConsistentTiming(t *testing.T) {
	privateKey, signer := generateTestECDSAKey(t)

	data := &ContextData{
		Type:        "service",
		ID:          "test",
		Permissions: []string{"read"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	ctx, err := encodeAndSign(data, signer, "fp")
	if err != nil {
		t.Fatalf("encodeAndSign failed: %v", err)
	}

	// Create various invalid contexts
	invalidContexts := []Context{
		Context(""),        // Empty
		Context("invalid"), // Invalid base64
		Context(base64.URLEncoding.EncodeToString([]byte("invalid"))), // Invalid JSON
		ctx[:len(ctx)-1], // Truncated
	}

	// This is a basic test - in production you'd want more sophisticated timing analysis
	for _, invalidCtx := range invalidContexts {
		start := time.Now()
		_, _ = decodeAndVerify(invalidCtx, &privateKey.PublicKey)
		elapsed := time.Since(start)

		// Just ensure it completes in reasonable time (not hanging)
		if elapsed > 100*time.Millisecond {
			t.Errorf("Decoding took too long: %v", elapsed)
		}
	}
}

// Verify the public function matches our implementation
func TestVerifyContext_PublicFunction(t *testing.T) {
	privateKey, signer := generateTestECDSAKey(t)

	data := &ContextData{
		Type:        "service",
		ID:          "test-service",
		Permissions: []string{"read", "write"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Issuer:      "test-issuer",
		ContextID:   "test-context-123",
	}

	ctx, err := encodeAndSign(data, signer, "test-fingerprint")
	if err != nil {
		t.Fatalf("encodeAndSign failed: %v", err)
	}

	// Test the public VerifyContext function
	verifiedData, err := VerifyContext(ctx, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyContext failed: %v", err)
	}

	if verifiedData.ID != data.ID {
		t.Errorf("ID mismatch: got %v, want %v", verifiedData.ID, data.ID)
	}
}

func TestCheckCompatibility(t *testing.T) {
	// Setup test key
	privateKey, signer := generateTestECDSAKey(t)
	publicKey := &privateKey.PublicKey

	// Helper to create tokens
	createToken := func(permissions []string, id string) Context {
		data := &ContextData{
			Type:        "service",
			ID:          id,
			Permissions: permissions,
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(time.Hour),
			Issuer:      "test-issuer",
			ContextID:   "test-" + id,
		}
		ctx, err := encodeAndSign(data, signer, "test-fp")
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}
		return ctx
	}

	t.Run("Compatible permissions - exact match", func(t *testing.T) {
		callerToken := createToken([]string{"api:read", "api:write"}, "caller")
		subjectToken := createToken([]string{"api:read", "api:write"}, "subject")

		compatible, err := CheckCompatibility(callerToken, subjectToken, publicKey)
		if err != nil {
			t.Fatalf("CheckCompatibility failed: %v", err)
		}
		if !compatible {
			t.Error("Expected tokens to be compatible")
		}
	})

	t.Run("Compatible permissions - subject is subset", func(t *testing.T) {
		callerToken := createToken([]string{"api:read", "api:write", "admin:access"}, "caller")
		subjectToken := createToken([]string{"api:read", "api:write"}, "subject")

		compatible, err := CheckCompatibility(callerToken, subjectToken, publicKey)
		if err != nil {
			t.Fatalf("CheckCompatibility failed: %v", err)
		}
		if !compatible {
			t.Error("Expected tokens to be compatible (subject is subset)")
		}
	})

	t.Run("Compatible permissions - subject has single permission", func(t *testing.T) {
		callerToken := createToken([]string{"api:read", "api:write", "payments:process"}, "caller")
		subjectToken := createToken([]string{"api:read"}, "subject")

		compatible, err := CheckCompatibility(callerToken, subjectToken, publicKey)
		if err != nil {
			t.Fatalf("CheckCompatibility failed: %v", err)
		}
		if !compatible {
			t.Error("Expected tokens to be compatible")
		}
	})

	t.Run("Incompatible permissions - subject has more", func(t *testing.T) {
		callerToken := createToken([]string{"api:read"}, "caller")
		subjectToken := createToken([]string{"api:read", "api:write"}, "subject")

		compatible, err := CheckCompatibility(callerToken, subjectToken, publicKey)
		if err != nil {
			t.Fatalf("CheckCompatibility failed: %v", err)
		}
		if compatible {
			t.Error("Expected tokens to be incompatible (subject has more permissions)")
		}
	})

	t.Run("Incompatible permissions - no overlap", func(t *testing.T) {
		callerToken := createToken([]string{"orders:read", "payments:read"}, "caller")
		subjectToken := createToken([]string{"api:write", "admin:access"}, "subject")

		compatible, err := CheckCompatibility(callerToken, subjectToken, publicKey)
		if err != nil {
			t.Fatalf("CheckCompatibility failed: %v", err)
		}
		if compatible {
			t.Error("Expected tokens to be incompatible (no permission overlap)")
		}
	})

	t.Run("Compatible permissions - empty subject", func(t *testing.T) {
		callerToken := createToken([]string{"api:read", "api:write"}, "caller")
		subjectToken := createToken([]string{}, "subject")

		compatible, err := CheckCompatibility(callerToken, subjectToken, publicKey)
		if err != nil {
			t.Fatalf("CheckCompatibility failed: %v", err)
		}
		if !compatible {
			t.Error("Expected tokens to be compatible (empty subject permissions)")
		}
	})

	t.Run("Compatible permissions - both empty", func(t *testing.T) {
		callerToken := createToken([]string{}, "caller")
		subjectToken := createToken([]string{}, "subject")

		compatible, err := CheckCompatibility(callerToken, subjectToken, publicKey)
		if err != nil {
			t.Fatalf("CheckCompatibility failed: %v", err)
		}
		if !compatible {
			t.Error("Expected tokens to be compatible (both empty)")
		}
	})

	t.Run("Invalid caller token", func(t *testing.T) {
		invalidToken := Context("invalid-token")
		subjectToken := createToken([]string{"api:read"}, "subject")

		compatible, err := CheckCompatibility(invalidToken, subjectToken, publicKey)
		if err == nil {
			t.Error("Expected error for invalid caller token")
		}
		if compatible {
			t.Error("Expected incompatible result for invalid caller token")
		}
		if !strings.Contains(err.Error(), "invalid caller token") {
			t.Errorf("Expected 'invalid caller token' in error, got: %v", err)
		}
	})

	t.Run("Invalid subject token", func(t *testing.T) {
		callerToken := createToken([]string{"api:read"}, "caller")
		invalidToken := Context("invalid-token")

		compatible, err := CheckCompatibility(callerToken, invalidToken, publicKey)
		if err == nil {
			t.Error("Expected error for invalid subject token")
		}
		if compatible {
			t.Error("Expected incompatible result for invalid subject token")
		}
		if !strings.Contains(err.Error(), "invalid subject token") {
			t.Errorf("Expected 'invalid subject token' in error, got: %v", err)
		}
	})
}

func TestCheckCompatibility_ExpiredTokens(t *testing.T) {
	// Setup test key
	privateKey, signer := generateTestECDSAKey(t)
	publicKey := &privateKey.PublicKey

	// Create expired token
	expiredData := &ContextData{
		Type:        "service",
		ID:          "expired",
		Permissions: []string{"api:read"},
		IssuedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		Issuer:      "test-issuer",
		ContextID:   "expired-token",
	}
	expiredToken, err := encodeAndSign(expiredData, signer, "test-fp")
	if err != nil {
		t.Fatalf("Failed to create expired token: %v", err)
	}

	// Create valid token
	validData := &ContextData{
		Type:        "service",
		ID:          "valid",
		Permissions: []string{"api:read", "api:write"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
		Issuer:      "test-issuer",
		ContextID:   "valid-token",
	}
	validToken, err := encodeAndSign(validData, signer, "test-fp")
	if err != nil {
		t.Fatalf("Failed to create valid token: %v", err)
	}

	t.Run("Expired caller token", func(t *testing.T) {
		compatible, err := CheckCompatibility(expiredToken, validToken, publicKey)
		if err == nil {
			t.Error("Expected error for expired caller token")
		}
		if compatible {
			t.Error("Expected incompatible result for expired caller token")
		}
	})

	t.Run("Expired subject token", func(t *testing.T) {
		compatible, err := CheckCompatibility(validToken, expiredToken, publicKey)
		if err == nil {
			t.Error("Expected error for expired subject token")
		}
		if compatible {
			t.Error("Expected incompatible result for expired subject token")
		}
	})
}
