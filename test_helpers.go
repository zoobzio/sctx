package sctx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// testECDSASigner wraps an ECDSA private key to implement the CryptoSigner interface for tests
type testECDSASigner struct {
	*ecdsaP256Signer
}

// newTestECDSASigner creates a CryptoSigner from an ECDSA private key for testing
func newTestECDSASigner(privateKey *ecdsa.PrivateKey) CryptoSigner {
	return &testECDSASigner{
		ecdsaP256Signer: &ecdsaP256Signer{privateKey: privateKey},
	}
}

// generateTestECDSAKey generates a P-256 ECDSA key pair for testing
func generateTestECDSAKey(t *testing.T) (*ecdsa.PrivateKey, CryptoSigner) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	
	signer := newTestECDSASigner(privateKey)
	return privateKey, signer
}

// assertECDSAPublicKey asserts that a crypto.PublicKey is an ECDSA public key with P-256 curve
func assertECDSAPublicKey(t *testing.T, pubKey crypto.PublicKey) *ecdsa.PublicKey {
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PublicKey, got %T", pubKey)
	}
	
	if ecdsaPubKey.Curve != elliptic.P256() {
		t.Errorf("Expected P-256 curve, got %v", ecdsaPubKey.Curve)
	}
	
	return ecdsaPubKey
}