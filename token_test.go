package sctx

import (
	"sync"
	"testing"
	"time"
)

func TestNewToken(t *testing.T) {
	ctx := Context("test-context-data")
	expiresAt := time.Now().Add(time.Hour)
	fingerprint := "test-fingerprint"

	token := newToken(ctx, expiresAt, fingerprint)

	if token == nil {
		t.Fatal("newToken returned nil")
	}

	if token.String() != string(ctx) {
		t.Errorf("Expected token value %s, got %s", string(ctx), token.String())
	}

	if token.ExpiresAt() != expiresAt {
		t.Errorf("Expected expiration %v, got %v", expiresAt, token.ExpiresAt())
	}

	if token.Fingerprint() != fingerprint {
		t.Errorf("Expected fingerprint %s, got %s", fingerprint, token.Fingerprint())
	}
}

func TestToken_String(t *testing.T) {
	tests := []struct {
		name    string
		context Context
	}{
		{
			name:    "normal context",
			context: Context("normal-context-string"),
		},
		{
			name:    "empty context",
			context: Context(""),
		},
		{
			name:    "long context",
			context: Context("very-long-context-" + string(make([]byte, 10000))),
		},
		{
			name:    "special characters",
			context: Context("context-with-special-chars-éñ-🔐-\n\t"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := newToken(tt.context, time.Now().Add(time.Hour), "fingerprint")

			result := token.String()
			if result != string(tt.context) {
				t.Errorf("Expected %s, got %s", string(tt.context), result)
			}
		})
	}
}

func TestToken_Context(t *testing.T) {
	ctx := Context("test-context-data")
	token := newToken(ctx, time.Now().Add(time.Hour), "fingerprint")

	result := token.Context()
	if result != ctx {
		t.Errorf("Expected context %s, got %s", string(ctx), string(result))
	}

	// Verify it returns the Context type, not just string
	var _ Context = result
}

func TestToken_ExpiresAt(t *testing.T) {
	ctx := Context("test-context")
	expiration := time.Now().Add(2 * time.Hour)
	token := newToken(ctx, expiration, "fingerprint")

	result := token.ExpiresAt()
	if !result.Equal(expiration) {
		t.Errorf("Expected expiration %v, got %v", expiration, result)
	}
}

func TestToken_IsExpired(t *testing.T) {
	ctx := Context("test-context")
	fingerprint := "test-fingerprint"

	t.Run("not expired", func(t *testing.T) {
		futureTime := time.Now().Add(time.Hour)
		token := newToken(ctx, futureTime, fingerprint)

		if token.IsExpired() {
			t.Error("Token should not be expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		pastTime := time.Now().Add(-time.Hour)
		token := newToken(ctx, pastTime, fingerprint)

		if !token.IsExpired() {
			t.Error("Token should be expired")
		}
	})

	t.Run("expires right now", func(t *testing.T) {
		// Test edge case where token expires at exactly current time
		nowTime := time.Now()
		token := newToken(ctx, nowTime, fingerprint)

		// Sleep a tiny bit to ensure we're past the expiration
		time.Sleep(time.Millisecond)

		if !token.IsExpired() {
			t.Error("Token should be expired when time has passed")
		}
	})
}

func TestToken_TimeUntilExpiry(t *testing.T) {
	ctx := Context("test-context")
	fingerprint := "test-fingerprint"

	t.Run("future expiration", func(t *testing.T) {
		duration := 2 * time.Hour
		expiresAt := time.Now().Add(duration)
		token := newToken(ctx, expiresAt, fingerprint)

		timeUntil := token.TimeUntilExpiry()

		// Should be approximately the duration (within a reasonable margin)
		diff := timeUntil - duration
		if diff < -time.Second || diff > time.Second {
			t.Errorf("Expected time until expiry to be around %v, got %v (diff: %v)", duration, timeUntil, diff)
		}
	})

	t.Run("past expiration", func(t *testing.T) {
		pastTime := time.Now().Add(-time.Hour)
		token := newToken(ctx, pastTime, fingerprint)

		timeUntil := token.TimeUntilExpiry()

		// Should be negative for past times
		if timeUntil >= 0 {
			t.Errorf("Expected negative time until expiry for expired token, got %v", timeUntil)
		}
	})
}

func TestToken_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
	}{
		{
			name:        "normal fingerprint",
			fingerprint: "normal-fingerprint",
		},
		{
			name:        "empty fingerprint",
			fingerprint: "",
		},
		{
			name:        "long fingerprint",
			fingerprint: "very-long-fingerprint-" + string(make([]byte, 1000)),
		},
		{
			name:        "special characters",
			fingerprint: "fingerprint-éñ-🔐-\n\t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := newToken(Context("test"), time.Now().Add(time.Hour), tt.fingerprint)

			result := token.Fingerprint()
			if result != tt.fingerprint {
				t.Errorf("Expected fingerprint %s, got %s", tt.fingerprint, result)
			}
		})
	}
}

func TestToken_Update(t *testing.T) {
	originalCtx := Context("original-context")
	originalExpiration := time.Now().Add(time.Hour)
	fingerprint := "test-fingerprint"

	token := newToken(originalCtx, originalExpiration, fingerprint)

	// Verify initial state
	if token.String() != string(originalCtx) {
		t.Errorf("Expected initial context %s, got %s", string(originalCtx), token.String())
	}

	if token.ExpiresAt() != originalExpiration {
		t.Errorf("Expected initial expiration %v, got %v", originalExpiration, token.ExpiresAt())
	}

	// Update the token
	newCtx := Context("updated-context")
	newExpiration := time.Now().Add(2 * time.Hour)

	token.update(newCtx, newExpiration)

	// Verify updated state
	if token.String() != string(newCtx) {
		t.Errorf("Expected updated context %s, got %s", string(newCtx), token.String())
	}

	if token.Context() != newCtx {
		t.Errorf("Expected updated context %s, got %s", string(newCtx), string(token.Context()))
	}

	if token.ExpiresAt() != newExpiration {
		t.Errorf("Expected updated expiration %v, got %v", newExpiration, token.ExpiresAt())
	}

	// Fingerprint should remain unchanged
	if token.Fingerprint() != fingerprint {
		t.Errorf("Fingerprint should not change during update, got %s", token.Fingerprint())
	}
}

func TestToken_ConcurrentAccess(t *testing.T) {
	ctx := Context("concurrent-test-context")
	expiresAt := time.Now().Add(time.Hour)
	fingerprint := "concurrent-fingerprint"

	token := newToken(ctx, expiresAt, fingerprint)

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Number of concurrent operations
	numGoroutines := 10
	numOperationsPerGoroutine := 100

	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperationsPerGoroutine; j++ {
				// Test all read operations
				str := token.String()
				if str == "" {
					errors <- nil // Error channel just to signal, but empty string might be valid
				}

				ctx := token.Context()
				_ = ctx

				exp := token.ExpiresAt()
				_ = exp

				expired := token.IsExpired()
				_ = expired

				timeUntil := token.TimeUntilExpiry()
				_ = timeUntil

				fp := token.Fingerprint()
				_ = fp
			}
		}(i)
	}

	// Concurrent writers (updates)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < 20; j++ {
				newCtx := Context("updated-context")
				newExp := time.Now().Add(time.Duration(id*j) * time.Minute)
				token.update(newCtx, newExp)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors (though we're mainly testing for race conditions/panics)
	for err := range errors {
		if err != nil {
			t.Errorf("Concurrent operation error: %v", err)
		}
	}

	// Final state should be consistent
	finalStr := token.String()
	finalCtx := token.Context()
	if string(finalCtx) != finalStr {
		t.Error("Final state inconsistency between String() and Context()")
	}
}

func TestToken_ImmutableFingerprint(t *testing.T) {
	originalFingerprint := "original-fingerprint"
	token := newToken(Context("test"), time.Now().Add(time.Hour), originalFingerprint)

	// Multiple updates should not change fingerprint
	for i := 0; i < 10; i++ {
		newCtx := Context("updated-context")
		newExp := time.Now().Add(time.Duration(i) * time.Hour)
		token.update(newCtx, newExp)

		if token.Fingerprint() != originalFingerprint {
			t.Errorf("Fingerprint changed after update %d: expected %s, got %s", 
				i, originalFingerprint, token.Fingerprint())
		}
	}
}

func TestToken_EdgeCases(t *testing.T) {
	t.Run("zero time expiration", func(t *testing.T) {
		token := newToken(Context("test"), time.Time{}, "fp")

		if !token.IsExpired() {
			t.Error("Token with zero time should be expired")
		}

		timeUntil := token.TimeUntilExpiry()
		if timeUntil >= 0 {
			t.Error("Time until expiry should be negative for zero time")
		}
	})

	t.Run("far future expiration", func(t *testing.T) {
		farFuture := time.Now().Add(100 * 365 * 24 * time.Hour) // 100 years
		token := newToken(Context("test"), farFuture, "fp")

		if token.IsExpired() {
			t.Error("Token with far future expiration should not be expired")
		}

		timeUntil := token.TimeUntilExpiry()
		if timeUntil <= 0 {
			t.Error("Time until expiry should be positive for far future")
		}
	})

	t.Run("update with same values", func(t *testing.T) {
		ctx := Context("same-context")
		exp := time.Now().Add(time.Hour)
		token := newToken(ctx, exp, "fp")

		// Update with exactly the same values
		token.update(ctx, exp)

		if token.String() != string(ctx) {
			t.Error("Context should remain the same after update with same values")
		}

		if token.ExpiresAt() != exp {
			t.Error("Expiration should remain the same after update with same values")
		}
	})

	t.Run("update to shorter expiration", func(t *testing.T) {
		originalExp := time.Now().Add(2 * time.Hour)
		token := newToken(Context("test"), originalExp, "fp")

		shorterExp := time.Now().Add(30 * time.Minute)
		token.update(Context("new"), shorterExp)

		if token.ExpiresAt() != shorterExp {
			t.Error("Should be able to update to shorter expiration")
		}

		// Should now expire sooner
		timeUntil := token.TimeUntilExpiry()
		if timeUntil > 31*time.Minute {
			t.Error("Time until expiry should reflect the shorter expiration")
		}
	})
}

func TestToken_StringVsContext(t *testing.T) {
	// Test that String() and Context() return equivalent values
	testCases := []Context{
		Context("simple"),
		Context(""),
		Context("with-special-chars-éñ-🔐"),
		Context("very-long-" + string(make([]byte, 5000))),
	}

	for i, ctx := range testCases {
		t.Run(string(ctx)[:min(len(ctx), 20)], func(t *testing.T) {
			token := newToken(ctx, time.Now().Add(time.Hour), "fp")

			str := token.String()
			ctxResult := token.Context()

			if str != string(ctxResult) {
				t.Errorf("Test case %d: String() and Context() should return equivalent values", i)
			}

			if string(ctxResult) != string(ctx) {
				t.Errorf("Test case %d: Context() should return original context", i)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}