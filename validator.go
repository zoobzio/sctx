package sctx

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// CertificateValidator handles client certificate validation and identity extraction
type CertificateValidator interface {
	// ValidateClientCert validates the client certificate from TLS connection state
	ValidateClientCert(tlsState *tls.ConnectionState, caPool *x509.CertPool) (*x509.Certificate, error)
	
	// ExtractIdentity extracts the identity from a certificate
	ExtractIdentity(cert *x509.Certificate) string
	
	// GetFingerprint computes the SHA256 fingerprint of a certificate
	GetFingerprint(cert *x509.Certificate) string
}

// defaultCertValidator is the standard implementation of CertificateValidator
type defaultCertValidator struct{}

// newCertificateValidator creates a new certificate validator (private)
func newCertificateValidator() CertificateValidator {
	return &defaultCertValidator{}
}

// ValidateClientCert validates the client certificate chain and checks key usage
func (v *defaultCertValidator) ValidateClientCert(tlsState *tls.ConnectionState, caPool *x509.CertPool) (*x509.Certificate, error) {
	// Validate TLS connection state
	if tlsState == nil || len(tlsState.PeerCertificates) == 0 {
		return nil, ErrNoCertificate
	}
	
	// Get the client certificate
	clientCert := tlsState.PeerCertificates[0]
	
	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         caPool,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	
	// Add any intermediate certificates
	for _, cert := range tlsState.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	
	// Verify the certificate
	if _, err := clientCert.Verify(opts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	
	// Additional certificate validation
	now := time.Now()
	if now.Before(clientCert.NotBefore) {
		return nil, errors.New("certificate not yet valid")
	}
	if now.After(clientCert.NotAfter) {
		return nil, errors.New("certificate has expired")
	}
	
	// Check key usage
	if clientCert.ExtKeyUsage != nil && len(clientCert.ExtKeyUsage) > 0 {
		hasClientAuth := false
		for _, usage := range clientCert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth {
				hasClientAuth = true
				break
			}
		}
		if !hasClientAuth {
			return nil, errors.New("certificate not authorized for client authentication")
		}
	}
	
	return clientCert, nil
}

// ExtractIdentity extracts the identity from a certificate
// Priority: CN (Common Name) > first SAN (Subject Alternative Name)
func (v *defaultCertValidator) ExtractIdentity(cert *x509.Certificate) string {
	// First try Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	
	// Fall back to first DNS SAN
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	
	// Fall back to first URI SAN
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	
	// Last resort - use serial number
	return cert.SerialNumber.String()
}

// GetFingerprint computes SHA256 fingerprint of a certificate
func (v *defaultCertValidator) GetFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.StdEncoding.EncodeToString(hash[:])
}