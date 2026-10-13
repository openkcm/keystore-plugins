package testcerts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

const rsaKeyBits = 2048

// NewRSAKey generates a 2048-bit RSA private key. Fails the test on error.
func NewRSAKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		tb.Fatalf("testcerts.NewRSAKey: %v", err)
	}
	return key
}

// NewCert generates an x509 certificate for key. If parent or signerKey are nil
// the certificate is self-signed. Set isCA to true to produce a CA certificate.
func NewCert(tb testing.TB, key *rsa.PrivateKey, isCA bool, parent *x509.Certificate, signerKey *rsa.PrivateKey) *x509.Certificate {
	tb.Helper()
	if signerKey == nil {
		signerKey = key
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         isCA,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signerKey)
	if err != nil {
		tb.Fatalf("testcerts.NewCert: CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("testcerts.NewCert: ParseCertificate: %v", err)
	}
	return cert
}

// RSAKeyPEM returns the PKCS#1 PEM-encoded form of key.
func RSAKeyPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

// CertPEM returns the PEM-encoded form of cert.
func CertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// NewKeyAndCertPEM generates a fresh RSA key and self-signed certificate,
// returning the key and certificate as PEM strings, in that order. This is the most common pattern across tests.
func NewKeyAndCertPEM(tb testing.TB) (string, string) {
	tb.Helper()
	key := NewRSAKey(tb)
	cert := NewCert(tb, key, false, nil, nil)
	return RSAKeyPEM(key), CertPEM(cert)
}
