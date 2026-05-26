package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	priv, der, err := GenerateSelfSignedCert("example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil || len(der) == 0 {
		t.Fatal("expected certificate material")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "example" || !cert.IsCA {
		t.Fatalf("unexpected certificate %+v", cert.Subject)
	}

	_, der, err = GenerateSelfSignedCert("ignored", &model.CertificatePolicy{X509Props: map[string]any{"subject": "CN=custom.example"}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "custom.example" {
		t.Fatalf("unexpected cn %q", cert.Subject.CommonName)
	}

	oldRSA := rsaGenerateKey
	rsaGenerateKey = func(_ io.Reader, _ int) (*rsa.PrivateKey, error) { return nil, errors.New("boom") }
	if _, _, err := GenerateSelfSignedCert("broken", nil); err == nil {
		t.Fatal("expected rsa generation error")
	}
	rsaGenerateKey = oldRSA
	priv2, err := rsaGenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	oldRandInt := randInt
	randInt = func(_ io.Reader, _ *big.Int) (*big.Int, error) { return nil, errors.New("boom") }
	if _, _, err := GenerateSelfSignedCert("broken", nil); err == nil {
		t.Fatal("expected rand.Int error")
	}
	randInt = oldRandInt
	oldCreate := createCertificate
	createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return nil, errors.New("boom")
	}
	rsaGenerateKey = func(_ io.Reader, _ int) (*rsa.PrivateKey, error) { return priv2, nil }
	if _, _, err := GenerateSelfSignedCert("broken", nil); err == nil {
		t.Fatal("expected create certificate error")
	}
	createCertificate = oldCreate
	rsaGenerateKey = oldRSA
}
func TestParseImportedCertificate(t *testing.T) {
	priv, der, err := GenerateSelfSignedCert("import.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	combined := string(append(certPEM, keyPEM...))

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	tests := []struct {
		name      string
		value     string
		wantKey   bool
		wantPEM   string
		wantError bool
	}{
		{name: "pem-cert-and-key", value: combined, wantKey: true, wantPEM: "RSA PRIVATE KEY"},
		{name: "pem-cert-and-pkcs8-key", value: string(append(certPEM, pkcs8PEM...)), wantKey: true, wantPEM: "PRIVATE KEY"},
		{name: "pem-cert-only", value: string(certPEM), wantKey: false, wantPEM: "CERTIFICATE"},
		{name: "der", value: string(der), wantKey: false, wantPEM: "CERTIFICATE"},
		{name: "base64-der", value: base64.StdEncoding.EncodeToString(der), wantKey: false, wantPEM: "CERTIFICATE"},
		{name: "key-only", value: string(keyPEM), wantError: true},
		{name: "invalid", value: "definitely not a cert", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, pemData, err := ParseImportedCertificate(tt.value)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cert == nil || cert.Subject.CommonName != "import.example" {
				t.Fatalf("unexpected cert %+v", cert)
			}
			if (key != nil) != tt.wantKey {
				t.Fatalf("unexpected key presence %v", key != nil)
			}
			if !strings.Contains(string(pemData), tt.wantPEM) {
				t.Fatalf("unexpected pem %q", pemData)
			}
		})
	}
}

func TestParseSubject(t *testing.T) {
	if got := ParseSubject("plain"); got.CommonName != "plain" {
		t.Fatalf("unexpected cn %q", got.CommonName)
	}
	if got := ParseSubject("CN=example.com"); got.CommonName != "example.com" {
		t.Fatalf("unexpected cn %q", got.CommonName)
	}
	if got := ParseSubject("CN=foo, O=bar"); got.CommonName != "foo" {
		t.Fatalf("unexpected cn %q", got.CommonName)
	}
}
