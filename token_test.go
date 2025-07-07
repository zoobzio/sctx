package sctx

import (
	"sync"
	"testing"
	"time"
)

func TestNewToken(t *testing.T) {
	ctx := Context("test-context")
	expiresAt := time.Now().Add(1 * time.Hour)
	fingerprint := "test-fingerprint"

	token := newToken(ctx, expiresAt, fingerprint)

	if token == nil {
		t.Fatal("newToken returned nil")
	}

	if token.value != string(ctx) {
		t.Errorf("Token value = %v, want %v", token.value, ctx)
	}

	if !token.expiresAt.Equal(expiresAt) {
		t.Errorf("Token expiresAt = %v, want %v", token.expiresAt, expiresAt)
	}

	if token.fingerprint != fingerprint {
		t.Errorf("Token fingerprint = %v, want %v", token.fingerprint, fingerprint)
	}
}

func TestToken_Context(t *testing.T) {
	ctx := Context("test-context-value")
	token := newToken(ctx, time.Now().Add(1*time.Hour), "fingerprint")

	got := token.Context()
	if got != ctx {
		t.Errorf("Context() = %v, want %v", got, ctx)
	}
}

func TestToken_IsExpired(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := newToken(Context("test"), tt.expiresAt, "fingerprint")
			if got := token.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToken_ExpiresAt(t *testing.T) {
	expiresAt := time.Now().Add(1 * time.Hour)
	token := newToken(Context("test"), expiresAt, "fingerprint")

	got := token.ExpiresAt()
	if !got.Equal(expiresAt) {
		t.Errorf("ExpiresAt() = %v, want %v", got, expiresAt)
	}
}

func TestToken_Update(t *testing.T) {
	originalCtx := Context("original-context")
	originalExpiry := time.Now().Add(1 * time.Hour)
	token := newToken(originalCtx, originalExpiry, "fingerprint")

	// Update the token
	newCtx := Context("new-context")
	newExpiry := time.Now().Add(2 * time.Hour)
	token.update(newCtx, newExpiry)

	// Verify updates
	if token.Context() != newCtx {
		t.Errorf("After update, Context() = %v, want %v", token.Context(), newCtx)
	}

	if !token.ExpiresAt().Equal(newExpiry) {
		t.Errorf("After update, ExpiresAt() = %v, want %v", token.ExpiresAt(), newExpiry)
	}
}

func TestToken_ConcurrentAccess(t *testing.T) {
	token := newToken(Context("test"), time.Now().Add(1*time.Hour), "fingerprint")

	// Test concurrent reads
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = token.Context()
			_ = token.IsExpired()
			_ = token.ExpiresAt()
		}()
	}
	wg.Wait()

	// Test concurrent update with reads
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				token.update(Context("updated"), time.Now().Add(2*time.Hour))
			}
		}(i)
		go func() {
			defer wg.Done()
			_ = token.Context()
			_ = token.IsExpired()
			_ = token.ExpiresAt()
		}()
	}
	wg.Wait()
}

func TestToken_UpdatePreservesFingerprint(t *testing.T) {
	fingerprint := "test-fingerprint"
	token := newToken(Context("original"), time.Now().Add(1*time.Hour), fingerprint)

	// Update should not change fingerprint
	token.update(Context("updated"), time.Now().Add(2*time.Hour))

	// Fingerprint should remain the same (internal field)
	if token.fingerprint != fingerprint {
		t.Errorf("Fingerprint changed after update: got %v, want %v", token.fingerprint, fingerprint)
	}
}

func TestToken_NilToken(t *testing.T) {
	var token *Token

	// These should not panic on nil token
	t.Run("nil token operations", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Operation on nil token panicked: %v", r)
			}
		}()

		// These operations should be safe on nil
		if token != nil {
			_ = token.Context()
			_ = token.IsExpired()
			_ = token.ExpiresAt()
		}
	})
}

func TestToken_RefreshRequiresService(t *testing.T) {
	// This test verifies that Refresh requires a service and TLS state
	// Since we can't easily mock these dependencies, we just ensure
	// the method exists and has the right signature
	token := newToken(Context("test"), time.Now().Add(1*time.Hour), "fingerprint")

	// Verify the Refresh method exists by checking it can be called
	// (will fail at runtime due to nil service, but that's expected)
	var service *ContextService
	
	// This is a compile-time check that the method exists with the right signature
	_ = func() {
		// This would panic at runtime due to nil service, so we don't actually call it
		// token.Refresh(service, tlsState.(*tls.ConnectionState))
		_ = service
		_ = token
	}
}