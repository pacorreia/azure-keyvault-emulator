package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

func (s *Store) CreateCertificate(name string, req model.CreateCertificateRequest) (CertificateRecord, error) {
	if name == "" {
		return CertificateRecord{}, newError(http.StatusBadRequest, "BadParameter", "Certificate name is required.")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.deletedCertificates[name]; ok {
		return CertificateRecord{}, newError(http.StatusConflict, "InvalidOperation", fmt.Sprintf("Certificate %s is currently deleted and cannot be reused until recovered or purged.", name))
	}

	policy := defaultCertificatePolicy(name, req.Policy)
	now := nowUnix()
	version := newVersion()
	attrs := buildAttributes(req.Attributes, now, now)
	priv, der, err := createSelfSignedCertificate(name, policy)
	if err != nil {
		return CertificateRecord{}, newError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	managedSecret := string(append(certPEM, keyPEM...))

	record := CertificateRecord{
		Name:       name,
		Version:    version,
		Cer:        append([]byte(nil), der...),
		Kid:        name,
		Sid:        name,
		Attributes: attrs,
		Tags:       cloneTags(req.Tags),
		Policy:     clonePolicy(policy),
	}
	entry := s.certificates[name]
	if entry == nil {
		entry = &certificateEntry{}
		s.certificates[name] = entry
	}
	entry.versions = append(entry.versions, &certificateVersion{record: cloneCertificateRecord(record), pem: append([]byte(nil), certPEM...)})

	keyRecord := KeyRecord{
		Name:       name,
		Version:    version,
		Key:        kvcrypto.RSAToJWK("", "RSA", defaultKeyOps("RSA", nil), &priv.PublicKey),
		Attributes: attrs,
		Tags:       cloneTags(req.Tags),
	}
	s.putKeyVersion(name, version, keyRecord, kvcrypto.KeyMaterial{RSA: priv, RSAPub: &priv.PublicKey})
	s.putSecretVersion(name, version, managedSecret, "application/x-pkcs12", attrs, req.Tags)
	return cloneCertificateRecord(record), nil
}

func (s *Store) ImportCertificate(name string, req model.ImportCertificateRequest) (CertificateRecord, error) {
	if name == "" {
		return CertificateRecord{}, newError(http.StatusBadRequest, "BadParameter", "Certificate name is required.")
	}
	if req.Value == "" {
		return CertificateRecord{}, newError(http.StatusBadRequest, "BadParameter", "Certificate value is required.")
	}

	cert, priv, pemValue, err := parseImportedCertificate(req.Value)
	if err != nil {
		return CertificateRecord{}, newError(http.StatusBadRequest, "BadParameter", err.Error())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.deletedCertificates[name]; ok {
		return CertificateRecord{}, newError(http.StatusConflict, "InvalidOperation", fmt.Sprintf("Certificate %s is currently deleted and cannot be reused until recovered or purged.", name))
	}

	policy := defaultCertificatePolicy(name, req.Policy)
	now := nowUnix()
	version := newVersion()
	attrs := buildAttributes(req.Attributes, now, now)
	record := CertificateRecord{
		Name:       name,
		Version:    version,
		Cer:        append([]byte(nil), cert.Raw...),
		Kid:        name,
		Sid:        name,
		Attributes: attrs,
		Tags:       cloneTags(req.Tags),
		Policy:     clonePolicy(policy),
	}
	entry := s.certificates[name]
	if entry == nil {
		entry = &certificateEntry{}
		s.certificates[name] = entry
	}
	entry.versions = append(entry.versions, &certificateVersion{record: cloneCertificateRecord(record), pem: append([]byte(nil), pemValue...)})

	if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		material := kvcrypto.KeyMaterial{RSAPub: rsaPub}
		if priv != nil {
			material.RSA = priv
			material.RSAPub = &priv.PublicKey
		}
		keyRecord := KeyRecord{
			Name:       name,
			Version:    version,
			Key:        kvcrypto.RSAToJWK("", "RSA", defaultKeyOps("RSA", nil), rsaPub),
			Attributes: attrs,
			Tags:       cloneTags(req.Tags),
		}
		s.putKeyVersion(name, version, keyRecord, material)
	}
	s.putSecretVersion(name, version, string(pemValue), "application/x-pkcs12", attrs, req.Tags)
	return cloneCertificateRecord(record), nil
}

func (s *Store) GetCertificate(name, version string) (CertificateRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry := s.certificates[name]
	if entry == nil {
		return CertificateRecord{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	ver := findCertificateVersion(entry, version)
	if ver == nil {
		return CertificateRecord{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	return cloneCertificateRecord(ver.record), nil
}

func (s *Store) ListCertificates(maxResults int, skipToken string) ([]CertificateRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.certificates))
	for name := range s.certificates {
		names = append(names, name)
	}
	sort.Strings(names)
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]CertificateRecord, 0, len(page))
	for _, name := range page {
		latest := latestCertificate(s.certificates[name])
		if latest != nil {
			items = append(items, cloneCertificateRecord(latest.record))
		}
	}
	return items, next, nil
}

func (s *Store) ListCertificateVersions(name string, maxResults int, skipToken string) ([]CertificateRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry := s.certificates[name]
	if entry == nil {
		return nil, nil, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	versions := make([]CertificateRecord, 0, len(entry.versions))
	for i := len(entry.versions) - 1; i >= 0; i-- {
		versions = append(versions, cloneCertificateRecord(entry.versions[i].record))
	}
	page, next, err := paginateNames(versions, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	return page, next, nil
}

func (s *Store) UpdateCertificate(name, version string, req model.UpdateCertificateRequest) (CertificateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.certificates[name]
	if entry == nil {
		return CertificateRecord{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	ver := findCertificateVersion(entry, version)
	if ver == nil {
		return CertificateRecord{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	ver.record.Attributes = mergeAttributes(ver.record.Attributes, req.Attributes)
	if req.Tags != nil {
		ver.record.Tags = cloneTags(req.Tags)
	}
	return cloneCertificateRecord(ver.record), nil
}

func (s *Store) GetCertificatePolicy(name string) (*model.CertificatePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry := s.certificates[name]
	if entry == nil {
		return nil, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	return clonePolicy(latestCertificate(entry).record.Policy), nil
}

func (s *Store) UpdateCertificatePolicy(name string, policy *model.CertificatePolicy) (*model.CertificatePolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.certificates[name]
	if entry == nil {
		return nil, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	latest := latestCertificate(entry)
	latest.record.Policy = defaultCertificatePolicy(name, policy)
	latest.record.Attributes.Updated = nowUnix()
	return clonePolicy(latest.record.Policy), nil
}

func (s *Store) GetPendingCertificateOperation(name string) (model.CertificateOperation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry := s.certificates[name]
	if entry == nil {
		return model.CertificateOperation{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	latest := latestCertificate(entry)
	return model.CertificateOperation{ID: name, Status: "completed", Target: latest.record.Name}, nil
}

func (s *Store) DeleteCertificate(name string) (DeletedCertificateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.certificates[name]
	if entry == nil {
		return DeletedCertificateRecord{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	if _, ok := s.deletedCertificates[name]; ok {
		return DeletedCertificateRecord{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	delete(s.certificates, name)
	now := nowUnix()
	deleted := &deletedCertificateEntry{
		entry:              entry,
		recoveryID:         newRecoveryID("certificates", name),
		deletedDate:        now,
		scheduledPurgeDate: now + int64(recoverableDays*24*60*60),
	}
	s.deletedCertificates[name] = deleted
	latest := cloneCertificateRecord(latestCertificate(entry).record)
	return DeletedCertificateRecord{
		CertificateRecord:  latest,
		RecoveryID:         deleted.recoveryID,
		DeletedDate:        deleted.deletedDate,
		ScheduledPurgeDate: deleted.scheduledPurgeDate,
	}, nil
}

func (s *Store) ListDeletedCertificates(maxResults int, skipToken string) ([]DeletedCertificateRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.deletedCertificates))
	for name := range s.deletedCertificates {
		names = append(names, name)
	}
	sort.Strings(names)
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]DeletedCertificateRecord, 0, len(page))
	for _, name := range page {
		deleted := s.deletedCertificates[name]
		items = append(items, DeletedCertificateRecord{
			CertificateRecord:  cloneCertificateRecord(latestCertificate(deleted.entry).record),
			RecoveryID:         deleted.recoveryID,
			DeletedDate:        deleted.deletedDate,
			ScheduledPurgeDate: deleted.scheduledPurgeDate,
		})
	}
	return items, next, nil
}

func (s *Store) GetDeletedCertificate(name string) (DeletedCertificateRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	deleted := s.deletedCertificates[name]
	if deleted == nil {
		return DeletedCertificateRecord{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A deleted certificate with name %s was not found in this key vault.", name))
	}
	return DeletedCertificateRecord{
		CertificateRecord:  cloneCertificateRecord(latestCertificate(deleted.entry).record),
		RecoveryID:         deleted.recoveryID,
		DeletedDate:        deleted.deletedDate,
		ScheduledPurgeDate: deleted.scheduledPurgeDate,
	}, nil
}

func (s *Store) PurgeDeletedCertificate(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.deletedCertificates[name]; !ok {
		return newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A deleted certificate with name %s was not found in this key vault.", name))
	}
	delete(s.deletedCertificates, name)
	return nil
}

func (s *Store) RecoverDeletedCertificate(name string) (CertificateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.certificates[name]; ok {
		return CertificateRecord{}, newError(http.StatusConflict, "Conflict", fmt.Sprintf("Certificate %s already exists.", name))
	}
	deleted := s.deletedCertificates[name]
	if deleted == nil {
		return CertificateRecord{}, newError(http.StatusNotFound, "CertificateNotFound", fmt.Sprintf("A deleted certificate with name %s was not found in this key vault.", name))
	}
	s.certificates[name] = deleted.entry
	delete(s.deletedCertificates, name)
	return cloneCertificateRecord(latestCertificate(deleted.entry).record), nil
}

func createSelfSignedCertificate(name string, policy *model.CertificatePolicy) (*rsa.PrivateKey, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               parseSubject(subject),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, der, nil
}

func parseImportedCertificate(value string) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
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

func defaultCertificatePolicy(name string, policy *model.CertificatePolicy) *model.CertificatePolicy {
	if policy == nil {
		policy = &model.CertificatePolicy{}
	}
	out := clonePolicy(policy)
	if out == nil {
		out = &model.CertificatePolicy{}
	}
	if out.Issuer == nil {
		out.Issuer = map[string]any{"name": "Self"}
	}
	if out.KeyProps == nil {
		out.KeyProps = map[string]any{"kty": "RSA", "key_size": 2048, "reuse_key": false}
	}
	if out.SecretProps == nil {
		out.SecretProps = map[string]any{"contentType": "application/x-pkcs12"}
	}
	if out.X509Props == nil {
		out.X509Props = map[string]any{"subject": "CN=" + name}
	}
	return out
}

func clonePolicy(policy *model.CertificatePolicy) *model.CertificatePolicy {
	if policy == nil {
		return nil
	}
	data, _ := json.Marshal(policy)
	var out model.CertificatePolicy
	_ = json.Unmarshal(data, &out)
	return &out
}

func findCertificateVersion(entry *certificateEntry, version string) *certificateVersion {
	if version == "" {
		return latestCertificate(entry)
	}
	for _, current := range entry.versions {
		if current.record.Version == version {
			return current
		}
	}
	return nil
}

func cloneCertificateRecord(in CertificateRecord) CertificateRecord {
	return CertificateRecord{
		Name:       in.Name,
		Version:    in.Version,
		Cer:        append([]byte(nil), in.Cer...),
		Kid:        in.Kid,
		Sid:        in.Sid,
		Attributes: cloneAttributes(in.Attributes),
		Tags:       cloneTags(in.Tags),
		Policy:     clonePolicy(in.Policy),
	}
}

func parseSubject(subject string) pkix.Name {
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
