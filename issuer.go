package sctx

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// ContextIssuer creates and signs security contexts
type ContextIssuer interface {
	// IssueContext creates a signed context from the provided data
	IssueContext(data *ContextData, certificateFingerprint string) (Context, error)

	// GenerateContextID creates a unique identifier for a context
	GenerateContextID() string

	// GetPublicKey returns the public key for verification
	GetPublicKey() crypto.PublicKey
	
	// GetAlgorithm returns the cryptographic algorithm used
	GetAlgorithm() CryptoAlgorithm
}

// defaultContextIssuer is the algorithm-agnostic implementation
type defaultContextIssuer struct {
	signer     CryptoSigner
	issuerName string
}

// newContextIssuer creates a new context issuer with the provided private key and algorithm
func newContextIssuer(privateKey crypto.PrivateKey, algorithm CryptoAlgorithm, issuerName string) (ContextIssuer, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}

	// Create appropriate signer for the algorithm
	signer, err := NewCryptoSigner(algorithm, privateKey)
	if err != nil {
		return nil, err
	}

	return &defaultContextIssuer{
		signer:     signer,
		issuerName: issuerName,
	}, nil
}

// IssueContext creates a signed context from the provided data
func (i *defaultContextIssuer) IssueContext(data *ContextData, certificateFingerprint string) (Context, error) {
	if data == nil {
		return "", errors.New("context data is required")
	}

	// Set issuer if not already set
	if data.Issuer == "" {
		data.Issuer = i.issuerName
	}

	// Ensure context ID is set
	if data.ContextID == "" {
		data.ContextID = i.GenerateContextID()
	}

	// Sign the context using the configured algorithm
	return encodeAndSign(data, i.signer, certificateFingerprint)
}

// GenerateContextID creates a unique identifier for a context
func (i *defaultContextIssuer) GenerateContextID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // This should never happen
	}
	return base64.URLEncoding.EncodeToString(b)
}

// GetPublicKey returns the public key for verification
func (i *defaultContextIssuer) GetPublicKey() crypto.PublicKey {
	return i.signer.PublicKey()
}

// GetAlgorithm returns the cryptographic algorithm used
func (i *defaultContextIssuer) GetAlgorithm() CryptoAlgorithm {
	return i.signer.Algorithm()
}
