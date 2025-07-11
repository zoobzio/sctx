package sctx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	GetPublicKey() *ecdsa.PublicKey
}

// defaultContextIssuer is the standard implementation using ECDSA P-256
type defaultContextIssuer struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuerName string
}

// newContextIssuer creates a new context issuer with the provided private key (private)
func newContextIssuer(privateKey *ecdsa.PrivateKey, issuerName string) (ContextIssuer, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	
	// Validate key is P-256 for NIST compliance
	if privateKey.Curve != elliptic.P256() {
		return nil, errors.New("private key must use P-256 curve for NIST compliance")
	}
	
	return &defaultContextIssuer{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
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
	
	// Sign the context
	return encodeAndSign(data, i.privateKey, certificateFingerprint)
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
func (i *defaultContextIssuer) GetPublicKey() *ecdsa.PublicKey {
	return i.publicKey
}