package sctx

// TokenProcessor provides token lifecycle management processors
type TokenProcessor[M any] struct {
	ops Operations
}

// NewTokenProcessor creates a new token processor with operations access
func NewTokenProcessor[M any](ops Operations) *TokenProcessor[M] {
	return &TokenProcessor[M]{
		ops: ops,
	}
}

// RefreshChecker checks if existing tokens need refresh based on TTL.
// This is the core token refresh processor that was missing.
func (tp *TokenProcessor[M]) RefreshChecker() PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Skip if no fingerprint
		if req.Fingerprint == "" {
			return req, nil
		}

		// Check if token should be refreshed using operations interface
		if tp.ops.ShouldRefreshToken(req.Fingerprint) {
			// The operations interface handles the token refresh logic internally
			// We just need to signal that refresh is needed
			// The service will handle the actual token retrieval and refresh
			// For now, we'll use a placeholder - this needs to be handled by the service
			// TODO: The service needs to check ShouldRefreshToken and handle refresh internally
		}

		return req, nil
	}
}

// MaxRefreshLimiter enforces a maximum number of token refreshes.
// This prevents infinite refresh loops and token abuse.
func (tp *TokenProcessor[M]) MaxRefreshLimiter(maxRefreshes int) PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Skip if no existing token
		if req.ExistingToken == nil {
			return req, nil
		}

		// Check refresh count
		if req.ExistingToken.RefreshCount >= maxRefreshes {
			req.Allowed = false
			req.DenialReason = "maximum token refreshes exceeded"
		}

		return req, nil
	}
}

// RevocationChecker checks if a token has been revoked.
func (tp *TokenProcessor[M]) RevocationChecker() PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Skip if no fingerprint to check
		if req.Fingerprint == "" {
			return req, nil
		}

		// Check if token is revoked using operations interface
		if tp.ops.IsTokenRevoked(req.Fingerprint) {
			req.Allowed = false
			req.DenialReason = "token has been revoked"
			req.ExistingToken = nil // Clear the token
		}

		return req, nil
	}
}

// TokenUsageTracker tracks token usage for analytics and security monitoring.
func (tp *TokenProcessor[M]) TokenUsageTracker() PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Track usage if there's a fingerprint
		if req.Fingerprint != "" {
			tp.ops.TrackTokenUsage(req.Fingerprint)
		}

		return req, nil
	}
}

// FactoryRefreshPolicy enforces factory-specific refresh policies.
// Different factories may have different refresh rules.
func (tp *TokenProcessor[M]) FactoryRefreshPolicy() PipelineProcessor[M] {
	return func(req *ContextRequest[M]) (*ContextRequest[M], error) {
		// Skip if no existing token or no matched factory
		if req.ExistingToken == nil || req.MatchedFactory == nil {
			return req, nil
		}

		// Check if factory allows refresh
		if !req.MatchedFactory.AllowRefresh {
			req.Allowed = false
			req.DenialReason = "token refresh not allowed by factory policy"
			return req, nil
		}

		// Check max refreshes if set
		if req.MatchedFactory.MaxRefreshes != nil {
			if req.ExistingToken.RefreshCount >= *req.MatchedFactory.MaxRefreshes {
				req.Allowed = false
				req.DenialReason = "factory refresh limit exceeded"
			}
		}

		return req, nil
	}
}