package sctx

import (
	"context"
	"crypto/x509"
)

// PipelineProcessor is a function type for processing context requests
// This makes it easier to define processors without repeating the full type
type PipelineProcessor[M any] func(*ContextRequest[M]) (*ContextRequest[M], error)

// ContextRequest represents a request flowing through the security pipeline
type ContextRequest[M any] struct {
	// INPUT - What comes in
	Certificate *x509.Certificate
	Fingerprint string
	RemoteAddr  string

	// PROCESSING STATE - Built up during pipeline
	Identity       string
	RegistryEntry  *RegistryEntry
	MatchedFactory *ContextFactory
	ExistingToken  *activeToken

	// OUTPUT - The decision
	Token        *Token
	Allowed      bool
	DenialReason string

	// TYPE-SAFE METADATA
	Metadata M

	// Context for cancellation and request state
	Ctx context.Context
}