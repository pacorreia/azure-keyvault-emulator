package store

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

func (s *Store) CreateKey(name string, req model.CreateKeyRequest) (KeyRecord, error) {
	if name == "" {
		return KeyRecord{}, newError(http.StatusBadRequest, "BadParameter", "Key name is required.")
	}
	if req.Kty == "" {
		return KeyRecord{}, newError(http.StatusBadRequest, "BadParameter", "Key type is required.")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.deletedKeys[name]; ok {
		return KeyRecord{}, newError(http.StatusConflict, "InvalidOperation", fmt.Sprintf("Key %s is currently deleted and cannot be reused until recovered or purged.", name))
	}

	now := nowUnix()
	version := newVersion()
	ops := defaultKeyOps(req.Kty, req.KeyOps)
	material, jwk, err := kvcrypto.GenerateKey(req.Kty, req.KeySize, req.Crv, "", ops)
	if err != nil {
		return KeyRecord{}, newError(http.StatusBadRequest, "BadParameter", err.Error())
	}
	record := KeyRecord{
		Name:       name,
		Version:    version,
		Key:        jwk,
		Attributes: buildAttributes(req.Attributes, now, now),
		Tags:       cloneTags(req.Tags),
	}
	entry := s.keys[name]
	if entry == nil {
		entry = &keyEntry{}
		s.keys[name] = entry
	}
	entry.versions = append(entry.versions, &keyVersion{record: record, material: material})
	return cloneKeyRecord(record), nil
}

func (s *Store) ImportKey(name string, req model.ImportKeyRequest) (KeyRecord, error) {
	if name == "" {
		return KeyRecord{}, newError(http.StatusBadRequest, "BadParameter", "Key name is required.")
	}
	if req.Key.Kty == "" {
		return KeyRecord{}, newError(http.StatusBadRequest, "BadParameter", "Key type is required.")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.deletedKeys[name]; ok {
		return KeyRecord{}, newError(http.StatusConflict, "InvalidOperation", fmt.Sprintf("Key %s is currently deleted and cannot be reused until recovered or purged.", name))
	}
	material, jwk, err := kvcrypto.ImportKey(req.Key, "")
	if err != nil {
		return KeyRecord{}, newError(http.StatusBadRequest, "BadParameter", err.Error())
	}
	ops := defaultKeyOps(req.Key.Kty, req.Key.KeyOps)
	jwk.KeyOps = ops
	now := nowUnix()
	record := KeyRecord{
		Name:       name,
		Version:    newVersion(),
		Key:        jwk,
		Attributes: buildAttributes(req.Attributes, now, now),
		Tags:       cloneTags(req.Tags),
	}
	entry := s.keys[name]
	if entry == nil {
		entry = &keyEntry{}
		s.keys[name] = entry
	}
	entry.versions = append(entry.versions, &keyVersion{record: record, material: material})
	return cloneKeyRecord(record), nil
}

func (s *Store) GetKey(name, version string) (KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.keys[name]
	if entry == nil {
		return KeyRecord{}, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	ver := findKeyVersion(entry, version)
	if ver == nil {
		return KeyRecord{}, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	return cloneKeyRecord(ver.record), nil
}

func (s *Store) ListKeys(maxResults int, skipToken string) ([]KeyRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.keys))
	for name := range s.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]KeyRecord, 0, len(page))
	for _, name := range page {
		latest := latestKey(s.keys[name])
		if latest != nil {
			items = append(items, cloneKeyRecord(latest.record))
		}
	}
	return items, next, nil
}

func (s *Store) ListKeyVersions(name string, maxResults int, skipToken string) ([]KeyRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.keys[name]
	if entry == nil {
		return nil, nil, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	versions := make([]KeyRecord, 0, len(entry.versions))
	for i := len(entry.versions) - 1; i >= 0; i-- {
		versions = append(versions, cloneKeyRecord(entry.versions[i].record))
	}
	page, next, err := paginateNames(versions, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	return page, next, nil
}

func (s *Store) UpdateKey(name, version string, req model.UpdateKeyRequest) (KeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.keys[name]
	if entry == nil {
		return KeyRecord{}, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	ver := findKeyVersion(entry, version)
	if ver == nil {
		return KeyRecord{}, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	ver.record.Attributes = mergeAttributes(ver.record.Attributes, req.Attributes)
	if req.Tags != nil {
		ver.record.Tags = cloneTags(req.Tags)
	}
	if req.KeyOps != nil {
		ver.record.Key.KeyOps = append([]string(nil), req.KeyOps...)
	}
	return cloneKeyRecord(ver.record), nil
}

func (s *Store) DeleteKey(name string) (DeletedKeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.keys[name]
	if entry == nil {
		return DeletedKeyRecord{}, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	if _, ok := s.deletedKeys[name]; ok {
		return DeletedKeyRecord{}, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	delete(s.keys, name)
	now := nowUnix()
	deleted := &deletedKeyEntry{
		entry:              entry,
		recoveryID:         newRecoveryID("keys", name),
		deletedDate:        now,
		scheduledPurgeDate: now + int64(recoverableDays*24*60*60),
	}
	s.deletedKeys[name] = deleted
	latest := cloneKeyRecord(latestKey(entry).record)
	return DeletedKeyRecord{
		KeyRecord:          latest,
		RecoveryID:         deleted.recoveryID,
		DeletedDate:        deleted.deletedDate,
		ScheduledPurgeDate: deleted.scheduledPurgeDate,
	}, nil
}

func (s *Store) ListDeletedKeys(maxResults int, skipToken string) ([]DeletedKeyRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.deletedKeys))
	for name := range s.deletedKeys {
		names = append(names, name)
	}
	sort.Strings(names)
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]DeletedKeyRecord, 0, len(page))
	for _, name := range page {
		deleted := s.deletedKeys[name]
		items = append(items, DeletedKeyRecord{
			KeyRecord:          cloneKeyRecord(latestKey(deleted.entry).record),
			RecoveryID:         deleted.recoveryID,
			DeletedDate:        deleted.deletedDate,
			ScheduledPurgeDate: deleted.scheduledPurgeDate,
		})
	}
	return items, next, nil
}

func (s *Store) GetDeletedKey(name string) (DeletedKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	deleted := s.deletedKeys[name]
	if deleted == nil {
		return DeletedKeyRecord{}, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A deleted key with name %s was not found in this key vault.", name))
	}
	return DeletedKeyRecord{
		KeyRecord:          cloneKeyRecord(latestKey(deleted.entry).record),
		RecoveryID:         deleted.recoveryID,
		DeletedDate:        deleted.deletedDate,
		ScheduledPurgeDate: deleted.scheduledPurgeDate,
	}, nil
}

func (s *Store) PurgeDeletedKey(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.deletedKeys[name]; !ok {
		return newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A deleted key with name %s was not found in this key vault.", name))
	}
	delete(s.deletedKeys, name)
	return nil
}

func (s *Store) RecoverDeletedKey(name string) (KeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[name]; ok {
		return KeyRecord{}, newError(http.StatusConflict, "Conflict", fmt.Sprintf("Key %s already exists.", name))
	}
	deleted := s.deletedKeys[name]
	if deleted == nil {
		return KeyRecord{}, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A deleted key with name %s was not found in this key vault.", name))
	}
	s.keys[name] = deleted.entry
	delete(s.deletedKeys, name)
	return cloneKeyRecord(latestKey(deleted.entry).record), nil
}

func (s *Store) Encrypt(name, version string, req model.EncryptRequest) (string, string, error) {
	ver, err := s.keyMaterial(name, version)
	if err != nil {
		return "", "", err
	}
	value, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", "", newError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	var iv []byte
	if req.IV != "" {
		iv, err = kvcrypto.DecodeBase64URL(req.IV)
		if err != nil {
			return "", "", newError(http.StatusBadRequest, "BadParameter", "The provided iv is not valid base64url data.")
		}
	}
	ciphertext, outIV, err := kvcrypto.Encrypt(ver.material, ver.record.Key.Kty, req.Alg, value, iv)
	if err != nil {
		return "", "", newError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	ivValue := ""
	if len(outIV) > 0 {
		ivValue = kvcrypto.EncodeBase64URL(outIV)
	}
	return kvcrypto.EncodeBase64URL(ciphertext), ivValue, nil
}

func (s *Store) Decrypt(name, version string, req model.EncryptRequest) (string, string, error) {
	ver, err := s.keyMaterial(name, version)
	if err != nil {
		return "", "", err
	}
	value, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", "", newError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	var iv []byte
	if req.IV != "" {
		iv, err = kvcrypto.DecodeBase64URL(req.IV)
		if err != nil {
			return "", "", newError(http.StatusBadRequest, "BadParameter", "The provided iv is not valid base64url data.")
		}
	}
	plaintext, outIV, err := kvcrypto.Decrypt(ver.material, ver.record.Key.Kty, req.Alg, value, iv)
	if err != nil {
		return "", "", newError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	ivValue := ""
	if len(outIV) > 0 {
		ivValue = kvcrypto.EncodeBase64URL(outIV)
	}
	return kvcrypto.EncodeBase64URL(plaintext), ivValue, nil
}

func (s *Store) Sign(name, version string, req model.SignRequest) (string, error) {
	ver, err := s.keyMaterial(name, version)
	if err != nil {
		return "", err
	}
	digest, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", newError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	sig, err := kvcrypto.Sign(ver.material, ver.record.Key.Kty, req.Alg, digest)
	if err != nil {
		return "", newError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	return kvcrypto.EncodeBase64URL(sig), nil
}

func (s *Store) Verify(name, version string, req model.VerifyRequest) (bool, error) {
	ver, err := s.keyMaterial(name, version)
	if err != nil {
		return false, err
	}
	digest, err := kvcrypto.DecodeBase64URL(req.Digest)
	if err != nil {
		return false, newError(http.StatusBadRequest, "BadParameter", "The provided digest is not valid base64url data.")
	}
	sig, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return false, newError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	ok, err := kvcrypto.Verify(ver.material, ver.record.Key.Kty, req.Alg, digest, sig)
	if err != nil {
		return false, newError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	return ok, nil
}

func (s *Store) WrapKey(name, version string, req model.EncryptRequest) (string, error) {
	ver, err := s.keyMaterial(name, version)
	if err != nil {
		return "", err
	}
	value, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", newError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	wrapped, err := kvcrypto.Wrap(ver.material, ver.record.Key.Kty, req.Alg, value)
	if err != nil {
		return "", newError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	return kvcrypto.EncodeBase64URL(wrapped), nil
}

func (s *Store) UnwrapKey(name, version string, req model.EncryptRequest) (string, error) {
	ver, err := s.keyMaterial(name, version)
	if err != nil {
		return "", err
	}
	value, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", newError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	unwrapped, err := kvcrypto.Unwrap(ver.material, ver.record.Key.Kty, req.Alg, value)
	if err != nil {
		return "", newError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	return kvcrypto.EncodeBase64URL(unwrapped), nil
}

func (s *Store) keyMaterial(name, version string) (*keyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry := s.keys[name]
	if entry == nil {
		return nil, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	ver := findKeyVersion(entry, version)
	if ver == nil {
		return nil, newError(http.StatusNotFound, "KeyNotFound", fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	return ver, nil
}

func (s *Store) putKeyVersion(name, version string, record KeyRecord, material kvcrypto.KeyMaterial) KeyRecord {
	entry := s.keys[name]
	if entry == nil {
		entry = &keyEntry{}
		s.keys[name] = entry
	}
	record.Name = name
	record.Version = version
	entry.versions = append(entry.versions, &keyVersion{record: cloneKeyRecord(record), material: material})
	return record
}

func findKeyVersion(entry *keyEntry, version string) *keyVersion {
	if version == "" {
		return latestKey(entry)
	}
	for _, current := range entry.versions {
		if current.record.Version == version {
			return current
		}
	}
	return nil
}

func cloneKeyRecord(in KeyRecord) KeyRecord {
	out := KeyRecord{
		Name:       in.Name,
		Version:    in.Version,
		Attributes: cloneAttributes(in.Attributes),
		Tags:       cloneTags(in.Tags),
		Key:        in.Key,
	}
	out.Key.KeyOps = append([]string(nil), in.Key.KeyOps...)
	return out
}

func defaultKeyOps(kty string, ops []string) []string {
	if len(ops) > 0 {
		return append([]string(nil), ops...)
	}
	switch {
	case strings.HasPrefix(kty, "RSA"):
		return []string{"encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"}
	case strings.HasPrefix(kty, "EC"):
		return []string{"sign", "verify"}
	default:
		return []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"}
	}
}
