package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

var (
	randInt           = rand.Int
	createCertificate = x509.CreateCertificate
)

// GenerateSelfSignedCert creates a new RSA 2048-bit self-signed X.509 certificate.
func GenerateSelfSignedCert(name string, policy *model.CertificatePolicy) (*rsa.PrivateKey, []byte, error) {
	priv, err := rsaGenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	subject := "CN=" + name
	if policy != nil && policy.X509Props != nil {
		if raw, ok := policy.X509Props["subject"].(string); ok && raw != "" {
			subject = raw
		}
	}
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := randInt(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               ParseSubject(subject),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := createCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, der, nil
}

// ParseImportedCertificate parses PEM or DER encoded certificate data.
func ParseImportedCertificate(value string) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	data := []byte(value)
	if !strings.Contains(value, "BEGIN ") {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err == nil {
			data = decoded
		}
	}
	var cert *x509.Certificate
	var priv *rsa.PrivateKey
	pemData := data
	if block, rest := pem.Decode(data); block != nil {
		pemData = data
		current := block
		remaining := rest
		for current != nil {
			switch current.Type {
			case "CERTIFICATE":
				parsed, err := x509.ParseCertificate(current.Bytes)
				if err == nil && cert == nil {
					cert = parsed
				}
			case "RSA PRIVATE KEY":
				parsed, err := x509.ParsePKCS1PrivateKey(current.Bytes)
				if err == nil && priv == nil {
					priv = parsed
				}
			case "PRIVATE KEY":
				parsed, err := x509.ParsePKCS8PrivateKey(current.Bytes)
				if err == nil {
					if key, ok := parsed.(*rsa.PrivateKey); ok && priv == nil {
						priv = key
					}
				}
			}
			current, remaining = pem.Decode(remaining)
		}
	} else {
		parsed, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid certificate value")
		}
		cert = parsed
		pemData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
	}
	if cert == nil {
		return nil, nil, nil, fmt.Errorf("invalid certificate value")
	}
	if priv != nil && !strings.Contains(string(pemData), "PRIVATE KEY") {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})...)
	}
	return cert, priv, pemData, nil
}

// ParseSubject parses a distinguished name string into a pkix.Name.
func ParseSubject(subject string) pkix.Name {
	name := pkix.Name{CommonName: subject}
	parts := strings.Split(subject, ",")
	for _, part := range parts {
		piece := strings.TrimSpace(part)
		if strings.HasPrefix(piece, "CN=") {
			name.CommonName = strings.TrimPrefix(piece, "CN=")
		}
	}
	return name
}
