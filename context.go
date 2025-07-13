package sctx

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrExpiredContext   = errors.New("context has expired")
	ErrInvalidContext   = errors.New("invalid context format")
)

// ContextType represents the type of security context
type ContextType string

// Context is an opaque, tamper-proof security token.
// It contains encoded and signed identity, permissions, and metadata.
// Contexts can only be created by the ContextService and must be verified before use.
type Context string

// ContextData contains the decoded context information after verification
type ContextData struct {
	Type                   ContextType
	ID                     string
	Permissions            []string
	IssuedAt               time.Time
	ExpiresAt              time.Time
	Issuer                 string
	CertificateFingerprint string // Cryptographically bound to the context
	ContextID              string // Unique ID for revocation
	RefreshCount           int    // Track refresh chain
	FactoryID              string // Which factory created this
}

// HasPermission checks if the context data includes a specific permission scope
func (cd *ContextData) HasPermission(scope string) bool {
	return slices.Contains(cd.Permissions, scope)
}

// IsExpired checks if the context data has expired
func (cd *ContextData) IsExpired() bool {
	return time.Now().After(cd.ExpiresAt)
}

// signedPayload represents the wire format of a context
type signedPayload struct {
	Data      string `json:"data"`      // Base64 encoded contextData
	Signature string `json:"signature"` // Base64 encoded signature
}

// ecdsaSignature represents an ECDSA signature for ASN.1 encoding
type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// encodeAndSign creates a signed context token using ECDSA P-256
func encodeAndSign(data *ContextData, privateKey *ecdsa.PrivateKey, certificateFingerprint string) (Context, error) {
	// Include fingerprint in the signed data
	data.CertificateFingerprint = certificateFingerprint

	// Serialize the data
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal context data: %w", err)
	}

	// Sign the data with ECDSA
	hash := sha256.Sum256(dataBytes)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign context: %w", err)
	}

	// Encode signature using ASN.1 DER format (standard for ECDSA)
	sig := ecdsaSignature{R: r, S: s}
	signatureBytes, err := asn1.Marshal(sig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %w", err)
	}

	// Create the signed payload
	payload := signedPayload{
		Data:      base64.StdEncoding.EncodeToString(dataBytes),
		Signature: base64.StdEncoding.EncodeToString(signatureBytes),
	}

	// Encode the final payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signed payload: %w", err)
	}

	// Return as base64 encoded context
	return Context(base64.URLEncoding.EncodeToString(payloadBytes)), nil
}

// decodeAndVerify extracts and verifies context data using ECDSA P-256
func decodeAndVerify(ctx Context, publicKey *ecdsa.PublicKey) (*ContextData, error) {
	// Decode the outer payload
	payloadBytes, err := base64.URLEncoding.DecodeString(string(ctx))
	if err != nil {
		return nil, ErrInvalidContext
	}

	// Unmarshal the signed payload
	var payload signedPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrInvalidContext
	}

	// Decode the data and signature
	dataBytes, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return nil, ErrInvalidContext
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(payload.Signature)
	if err != nil {
		return nil, ErrInvalidContext
	}

	// Decode ECDSA signature
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(signatureBytes, &sig); err != nil {
		return nil, ErrInvalidSignature
	}

	// Verify the signature
	hash := sha256.Sum256(dataBytes)
	if !ecdsa.Verify(publicKey, hash[:], sig.R, sig.S) {
		return nil, ErrInvalidSignature
	}

	// Unmarshal the context data
	var data ContextData
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return nil, ErrInvalidContext
	}

	// Check expiration
	if data.IsExpired() {
		return nil, ErrExpiredContext
	}

	return &data, nil
}

// CheckCompatibility verifies that the subject token has permissions that are
// a subset of or equal to the caller token permissions. This enables delegation
// and authorization chain verification in microservices.
//
// Returns true if:
// - Both tokens are valid and not expired
// - All permissions in subjectToken exist in callerToken
//
// Use cases:
// - Service delegation: "Can this upstream service ask me to perform this operation?"
// - Proxy/Gateway: "Should I forward this request based on both tokens?"
// - Workflow orchestration: "Can service A tell service B to do X?"
func CheckCompatibility(callerToken, subjectToken Context, publicKey *ecdsa.PublicKey) (bool, error) {
	// Verify caller token
	callerData, err := VerifyContext(callerToken, publicKey)
	if err != nil {
		return false, fmt.Errorf("invalid caller token: %w", err)
	}
	
	// Verify subject token
	subjectData, err := VerifyContext(subjectToken, publicKey)
	if err != nil {
		return false, fmt.Errorf("invalid subject token: %w", err)
	}
	
	// Check if subject permissions are subset of caller permissions
	for _, perm := range subjectData.Permissions {
		if !slices.Contains(callerData.Permissions, perm) {
			return false, nil
		}
	}
	
	return true, nil
}
