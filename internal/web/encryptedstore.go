package web

import (
	"errors"

	"github.com/pacorreia/azure-keyvault-emulator/internal/encryption"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

// encryptedStore wraps a store.Storer and transparently encrypts secret values
// using AES-256-GCM when a key is available. When no key is set (before setup),
// secret values are stored and returned as plaintext.
type encryptedStore struct {
	store.Storer
	getKey   func() []byte
	isLocked func() bool
}

func newEncryptedStore(s store.Storer, getKey func() []byte, isLocked func() bool) *encryptedStore {
	return &encryptedStore{Storer: s, getKey: getKey, isLocked: isLocked}
}

// SetSecret encrypts the secret value before delegating to the underlying store.
// If encryption is configured but the vault is locked (key not yet loaded after
// a restart), SetSecret returns an error to prevent plaintext writes.
func (es *encryptedStore) SetSecret(name string, req model.SecretSetRequest) (store.SecretRecord, error) {
	key := es.getKey()
	if key == nil {
		if es.isLocked != nil && es.isLocked() {
			return store.SecretRecord{}, errors.New("vault is locked: unlock before writing secrets")
		}
	} else if req.Value != "" {
		encrypted, err := encryption.EncryptString(key, req.Value)
		if err != nil {
			return store.SecretRecord{}, err
		}
		req.Value = encrypted
	}
	return es.Storer.SetSecret(name, req)
}

// GetSecret retrieves the secret and decrypts its value when a key is available.
func (es *encryptedStore) GetSecret(name, version string) (store.SecretRecord, error) {
	record, err := es.Storer.GetSecret(name, version)
	if err != nil {
		return record, err
	}
	return es.decryptRecord(record), nil
}

// GetDeletedSecret retrieves a soft-deleted secret and decrypts its value.
func (es *encryptedStore) GetDeletedSecret(name string) (store.DeletedSecretRecord, error) {
	record, err := es.Storer.GetDeletedSecret(name)
	if err != nil {
		return record, err
	}
	record.SecretRecord = es.decryptRecord(record.SecretRecord)
	return record, nil
}

// RecoverDeletedSecret restores a deleted secret and decrypts its value.
func (es *encryptedStore) RecoverDeletedSecret(name string) (store.SecretRecord, error) {
	record, err := es.Storer.RecoverDeletedSecret(name)
	if err != nil {
		return record, err
	}
	return es.decryptRecord(record), nil
}

// UpdateSecret delegates to the underlying store and decrypts the returned record when a key is available.
func (es *encryptedStore) UpdateSecret(name, version string, req model.SecretUpdateRequest) (store.SecretRecord, error) {
	record, err := es.Storer.UpdateSecret(name, version, req)
	if err != nil {
		return record, err
	}
	return es.decryptRecord(record), nil
}

// DeleteSecret delegates to the underlying store and decrypts the returned record when a key is available.
func (es *encryptedStore) DeleteSecret(name string) (store.DeletedSecretRecord, error) {
	record, err := es.Storer.DeleteSecret(name)
	if err != nil {
		return record, err
	}
	record.SecretRecord = es.decryptRecord(record.SecretRecord)
	return record, nil
}
// decryptRecord attempts to decrypt the secret value using the current encryption
// key. If the key is not set or decryption fails (e.g. the value was stored
// before encryption was configured), the original record is returned unchanged.
func (es *encryptedStore) decryptRecord(record store.SecretRecord) store.SecretRecord {
	key := es.getKey()
	if key == nil || record.Value == "" {
		return record
	}
	decrypted, err := encryption.DecryptString(key, record.Value)
	if err != nil {
		// If decryption fails the value may have been stored unencrypted
		// (e.g. before setup). Return as-is.
		return record
	}
	record.Value = decrypted
	return record
}
