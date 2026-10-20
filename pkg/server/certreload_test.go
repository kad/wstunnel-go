package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSigned(t *testing.T, certFile, keyFile, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func commonName(t *testing.T, r *certReloader) string {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloaderPicksUpRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	writeSelfSigned(t, certFile, keyFile, "old")
	r, err := newCertReloader(certFile, keyFile, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got := commonName(t, r); got != "old" {
		t.Fatalf("cn = %q, want old", got)
	}

	writeSelfSigned(t, certFile, keyFile, "renewed-cert")
	time.Sleep(5 * time.Millisecond)
	if got := commonName(t, r); got != "renewed-cert" {
		t.Fatalf("cn = %q after renewal, want renewed-cert", got)
	}
}

func TestCertReloaderKeepsCertificateWhenPairIsBroken(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	writeSelfSigned(t, certFile, keyFile, "good")
	r, err := newCertReloader(certFile, keyFile, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Half a renewal: a new certificate with the old key.
	otherCert, otherKey := filepath.Join(dir, "c2.pem"), filepath.Join(dir, "k2.pem")
	writeSelfSigned(t, otherCert, otherKey, "mismatch")
	data, _ := os.ReadFile(otherCert)
	if err := os.WriteFile(certFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if got := commonName(t, r); got != "good" {
		t.Fatalf("cn = %q with a mismatched pair, want the previous certificate", got)
	}

	// The key lands: the pair is consistent again and gets picked up.
	keyData, _ := os.ReadFile(otherKey)
	if err := os.WriteFile(keyFile, keyData, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if got := commonName(t, r); got != "mismatch" {
		t.Fatalf("cn = %q after the key arrived, want mismatch", got)
	}
}
