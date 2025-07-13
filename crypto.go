package sctx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// CryptoAlgorithm represents the supported cryptographic algorithms
type CryptoAlgorithm string

const (
	// CryptoEd25519 is the default high-performance algorithm (30% faster than ECDSA)
	CryptoEd25519 CryptoAlgorithm = "ed25519"
	
	// CryptoECDSAP256 is the FIPS 140-2 compliant algorithm for government/compliance requirements
	CryptoECDSAP256 CryptoAlgorithm = "ecdsa-p256"
	
	// DefaultCryptoAlgorithm prioritizes performance - governments can opt into compliance
	DefaultCryptoAlgorithm = CryptoEd25519
)

// CryptoSigner provides algorithm-agnostic cryptographic operations
type CryptoSigner interface {
	// Sign signs the provided data
	Sign(data []byte) ([]byte, error)
	
	// Verify verifies a signature against data and public key
	Verify(data []byte, signature []byte, publicKey crypto.PublicKey) bool
	
	// Algorithm returns the algorithm identifier
	Algorithm() CryptoAlgorithm
	
	// PublicKey returns the public key
	PublicKey() crypto.PublicKey
	
	// KeyType returns a string description for debugging
	KeyType() string
}

// NewCryptoSigner creates a new crypto signer for the specified algorithm
func NewCryptoSigner(algorithm CryptoAlgorithm, privateKey crypto.PrivateKey) (CryptoSigner, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	
	switch algorithm {
	case CryptoEd25519:
		ed25519Key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key must be ed25519.PrivateKey for Ed25519 algorithm")
		}
		return &ed25519Signer{privateKey: ed25519Key}, nil
		
	case CryptoECDSAP256:
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key must be *ecdsa.PrivateKey for ECDSA P-256 algorithm")
		}
		if ecdsaKey == nil {
			return nil, fmt.Errorf("private key is required")
		}
		if ecdsaKey.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ECDSA private key must use P-256 curve for NIST compliance")
		}
		return &ecdsaP256Signer{privateKey: ecdsaKey}, nil
		
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// GenerateKeyPair generates a key pair for the specified algorithm
func GenerateKeyPair(algorithm CryptoAlgorithm) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch algorithm {
	case CryptoEd25519:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		return privateKey, publicKey, err
		
	case CryptoECDSAP256:
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return privateKey, &privateKey.PublicKey, nil
		
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// ed25519Signer implements CryptoSigner for Ed25519
type ed25519Signer struct {
	privateKey ed25519.PrivateKey
}

func (s *ed25519Signer) Sign(data []byte) ([]byte, error) {
	// Ed25519 signs the data directly (no hashing required)
	signature := ed25519.Sign(s.privateKey, data)
	return signature, nil
}

func (s *ed25519Signer) Verify(data []byte, signature []byte, publicKey crypto.PublicKey) bool {
	ed25519PubKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(ed25519PubKey, data, signature)
}

func (s *ed25519Signer) Algorithm() CryptoAlgorithm {
	return CryptoEd25519
}

func (s *ed25519Signer) PublicKey() crypto.PublicKey {
	return s.privateKey.Public()
}

func (s *ed25519Signer) KeyType() string {
	return "Ed25519"
}

// ecdsaP256Signer implements CryptoSigner for ECDSA P-256
type ecdsaP256Signer struct {
	privateKey *ecdsa.PrivateKey
}

// ecdsaSignature represents an ECDSA signature for ASN.1 encoding (FIPS compliance)
type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

func (s *ecdsaP256Signer) Sign(data []byte) ([]byte, error) {
	// ECDSA requires hashing the data first
	hash := sha256.Sum256(data)
	r, sig, err := ecdsa.Sign(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}
	
	// Encode signature using ASN.1 DER format (FIPS standard)
	signature := ecdsaSignature{R: r, S: sig}
	signatureBytes, err := asn1.Marshal(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA signature: %w", err)
	}
	
	return signatureBytes, nil
}

func (s *ecdsaP256Signer) Verify(data []byte, signature []byte, publicKey crypto.PublicKey) bool {
	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	
	// Decode ASN.1 DER signature
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return false
	}
	
	// Hash the data
	hash := sha256.Sum256(data)
	
	// Verify signature
	return ecdsa.Verify(ecdsaPubKey, hash[:], sig.R, sig.S)
}

func (s *ecdsaP256Signer) Algorithm() CryptoAlgorithm {
	return CryptoECDSAP256
}

func (s *ecdsaP256Signer) PublicKey() crypto.PublicKey {
	return &s.privateKey.PublicKey
}

func (s *ecdsaP256Signer) KeyType() string {
	return "ECDSA P-256"
}

// DetectAlgorithmFromPublicKey determines the algorithm from a public key
func DetectAlgorithmFromPublicKey(publicKey crypto.PublicKey) (CryptoAlgorithm, error) {
	switch publicKey.(type) {
	case ed25519.PublicKey:
		return CryptoEd25519, nil
	case *ecdsa.PublicKey:
		return CryptoECDSAP256, nil
	default:
		return "", fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// ValidateAlgorithm checks if the algorithm is supported
func ValidateAlgorithm(algorithm CryptoAlgorithm) error {
	switch algorithm {
	case CryptoEd25519, CryptoECDSAP256:
		return nil
	default:
		return fmt.Errorf("unsupported algorithm: %s. Supported algorithms: %s (default, high-performance), %s (FIPS 140-2 compliant)", 
			algorithm, CryptoEd25519, CryptoECDSAP256)
	}
}