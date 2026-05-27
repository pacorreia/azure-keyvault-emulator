package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"golang.org/x/crypto/pkcs12"
)

var (
	randInt           = rand.Int
	createCertificate = x509.CreateCertificate
)

// CertOptions controls certificate generation behaviour.
type CertOptions struct {
	// CertType is one of "CA", "intermediate", or "leaf". Defaults to "leaf".
	CertType string
	// IssuerCert and IssuerKey are the signing parent. When nil the certificate is self-signed.
	IssuerCert *x509.Certificate
	IssuerKey  *rsa.PrivateKey
}

// GenerateCert creates a new RSA 2048-bit X.509 certificate controlled by opts.
// Subject and validity are read from policy.X509Props ("subject", "validity_months").
// When opts.IssuerCert is nil the certificate is self-signed.
func GenerateCert(name string, policy *model.CertificatePolicy, opts CertOptions) (*rsa.PrivateKey, []byte, error) {
	priv, err := rsaGenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	certType := opts.CertType
	if certType == "" {
		certType = "leaf"
	}
	subject := "CN=" + name
	if policy != nil && policy.X509Props != nil {
		if raw, ok := policy.X509Props["subject"].(string); ok && raw != "" {
			subject = raw
		}
	}
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	if policy != nil && policy.X509Props != nil {
		if vm, ok := policy.X509Props["validity_months"].(float64); ok && vm > 0 {
			notAfter = notBefore.Add(time.Duration(vm*30*24) * time.Hour)
		}
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := randInt(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	isCA := certType == "CA" || certType == "intermediate"
	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage
	if isCA {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               ParseSubject(subject),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	signerCert := opts.IssuerCert
	signerKey := opts.IssuerKey
	if signerCert == nil {
		signerCert = tpl
		signerKey = priv
	}
	der, err := createCertificate(rand.Reader, tpl, signerCert, &priv.PublicKey, signerKey)
	if err != nil {
		return nil, nil, err
	}
	return priv, der, nil
}

// GenerateSelfSignedCert creates a new RSA 2048-bit self-signed CA certificate.
func GenerateSelfSignedCert(name string, policy *model.CertificatePolicy) (*rsa.PrivateKey, []byte, error) {
	return GenerateCert(name, policy, CertOptions{CertType: "CA"})
}

func GenerateTLSCertificate(cn string, dnsNames []string) (tls.Certificate, error) {
	policy := &model.CertificatePolicy{X509Props: map[string]any{"subject": "CN=" + cn}}
	priv, der, err := GenerateSelfSignedCert(cn, policy)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf.DNSNames = append([]string(nil), dnsNames...)
	updatedDER, err := createCertificate(rand.Reader, leaf, leaf, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: updatedDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// parsePEMData extracts the first certificate and RSA private key from PEM-encoded data.
func parsePEMData(data []byte) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	var cert *x509.Certificate
	var priv *rsa.PrivateKey
	pemOut := data
	block, rest := pem.Decode(data)
	for block != nil {
		switch block.Type {
		case "CERTIFICATE":
			if c, err := x509.ParseCertificate(block.Bytes); err == nil && cert == nil {
				cert = c
			}
		case "RSA PRIVATE KEY":
			if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil && priv == nil {
				priv = k
			}
		case "PRIVATE KEY":
			if raw, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if k, ok := raw.(*rsa.PrivateKey); ok && priv == nil {
					priv = k
				}
			}
		}
		block, rest = pem.Decode(rest)
	}
	if cert == nil {
		return nil, nil, nil, fmt.Errorf("invalid certificate value")
	}
	if priv != nil && !strings.Contains(string(pemOut), "PRIVATE KEY") {
		pemOut = append(pemOut, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})...)
	}
	return cert, priv, pemOut, nil
}

// ParseImportedCertificate parses PEM, DER, or PKCS#12/PFX encoded certificate data.
// For PKCS#12 files, password is used to decrypt the archive.
func ParseImportedCertificate(value, password string) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	data := []byte(value)
	if !strings.Contains(value, "BEGIN ") {
		if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
			data = decoded
		}
	}

	// PEM path — fast-path if the data starts with a PEM block.
	if block, _ := pem.Decode(data); block != nil {
		return parsePEMData(data)
	}

	// PKCS#12/PFX path — try before raw DER, since PFX is ASN.1 like DER.
	if blocks, err := pkcs12.ToPEM(data, password); err == nil && len(blocks) > 0 {
		var pemData []byte
		for _, block := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(block)...)
		}
		return parsePEMData(pemData)
	}

	// Raw DER path.
	parsed, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid certificate value")
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
	return parsed, nil, pemData, nil
}

// ParseSubject parses a distinguished name string into a pkix.Name.
func ParseSubject(subject string) pkix.Name {
	name := pkix.Name{CommonName: subject}
	parts := strings.Split(subject, ",")
	for _, part := range parts {
		piece := strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(piece, "CN="):
			name.CommonName = strings.TrimPrefix(piece, "CN=")
		case strings.HasPrefix(piece, "O="):
			name.Organization = append(name.Organization, strings.TrimPrefix(piece, "O="))
		case strings.HasPrefix(piece, "OU="):
			name.OrganizationalUnit = append(name.OrganizationalUnit, strings.TrimPrefix(piece, "OU="))
		case strings.HasPrefix(piece, "C="):
			name.Country = append(name.Country, strings.TrimPrefix(piece, "C="))
		case strings.HasPrefix(piece, "ST="):
			name.Province = append(name.Province, strings.TrimPrefix(piece, "ST="))
		case strings.HasPrefix(piece, "L="):
			name.Locality = append(name.Locality, strings.TrimPrefix(piece, "L="))
		}
	}
	return name
}
