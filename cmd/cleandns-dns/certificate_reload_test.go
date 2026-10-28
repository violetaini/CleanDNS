package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateReloaderLoadsRenewedPair(t *testing.T) {
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "fullchain.pem")
	keyFile := filepath.Join(tempDir, "privkey.pem")
	writeReloadTestKeyPair(t, certFile, keyFile, 1, time.Now())

	tlsConfig, err := makeTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.GetCertificate == nil || len(tlsConfig.Certificates) != 0 {
		t.Fatal("TLS config does not use the certificate reloader")
	}
	if serial := loadedConfigCertificateSerial(t, tlsConfig); serial != 1 {
		t.Fatalf("initial certificate serial = %d, want 1", serial)
	}

	writeReloadTestKeyPair(t, certFile, keyFile, 2, time.Now().Add(2*time.Second))
	if serial := loadedConfigCertificateSerial(t, tlsConfig); serial != 2 {
		t.Fatalf("renewed certificate serial = %d, want 2", serial)
	}

	if err = os.WriteFile(keyFile, []byte("incomplete renewal"), 0o600); err != nil {
		t.Fatal(err)
	}
	changedAt := time.Now().Add(4 * time.Second)
	if err = os.Chtimes(keyFile, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	if serial := loadedConfigCertificateSerial(t, tlsConfig); serial != 2 {
		t.Fatalf("fallback certificate serial = %d, want 2", serial)
	}
}

func loadedConfigCertificateSerial(t *testing.T, config *tls.Config) int64 {
	t.Helper()
	certificate, err := config.GetCertificate(nil)
	return loadedCertificateSerial(t, certificate, err)
}

func loadedCertificateSerial(t *testing.T, certificate *tls.Certificate, err error) int64 {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if certificate == nil || len(certificate.Certificate) == 0 {
		t.Fatal("certificate is empty")
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed.SerialNumber.Int64()
}

func writeReloadTestKeyPair(t *testing.T, certFile, keyFile string, serial int64, modTime time.Time) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"dns.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(certFile, modTime, modTime); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(keyFile, modTime, modTime); err != nil {
		t.Fatal(err)
	}
}
