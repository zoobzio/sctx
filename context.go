package sctx

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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


// encodeAndSign creates a signed context token using the configured crypto algorithm
func encodeAndSign(data *ContextData, signer CryptoSigner, certificateFingerprint string) (Context, error) {
	// Include fingerprint in the signed data
	data.CertificateFingerprint = certificateFingerprint

	// Serialize the data
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal context data: %w", err)
	}

	// Sign the data using the configured algorithm
	signatureBytes, err := signer.Sign(dataBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign context: %w", err)
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

// decodeAndVerify extracts and verifies context data using the detected algorithm
func decodeAndVerify(ctx Context, publicKey crypto.PublicKey) (*ContextData, error) {
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

	// Detect algorithm from public key and create appropriate verifier
	algorithm, err := DetectAlgorithmFromPublicKey(publicKey)
	if err != nil {
		return nil, ErrInvalidSignature
	}
	
	// Create verifier (we don't need the private key for verification)
	var signer CryptoSigner
	switch algorithm {
	case CryptoEd25519:
		signer = &ed25519Signer{} // Only used for verification
	case CryptoECDSAP256:
		signer = &ecdsaP256Signer{} // Only used for verification
	default:
		return nil, ErrInvalidSignature
	}

	// Verify the signature using the detected algorithm
	if !signer.Verify(dataBytes, signatureBytes, publicKey) {
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
func CheckCompatibility(callerToken, subjectToken Context, publicKey crypto.PublicKey) (bool, error) {
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
