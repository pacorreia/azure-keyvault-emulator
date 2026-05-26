package web

import (
	"github.com/pacorreia/azure-keyvault-emulator/internal/encryption"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

// encryptedStore wraps a store.Storer and transparently encrypts secret values
// using AES-256-GCM when a key is available. When no key is set (before setup),
// secret values are stored and returned as plaintext.
type encryptedStore struct {
	store.Storer
	getKey func() []byte
}

func newEncryptedStore(s store.Storer, getKey func() []byte) *encryptedStore {
	return &encryptedStore{Storer: s, getKey: getKey}
}

// SetSecret encrypts the secret value before delegating to the underlying store.
func (es *encryptedStore) SetSecret(name string, req model.SecretSetRequest) (store.SecretRecord, error) {
	key := es.getKey()
	if key != nil && req.Value != "" {
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

// UpdateSecret re-encrypts the value if provided in the update request.
func (es *encryptedStore) UpdateSecret(name, version string, req model.SecretUpdateRequest) (store.SecretRecord, error) {
	record, err := es.Storer.UpdateSecret(name, version, req)
	if err != nil {
		return record, err
	}
	return es.decryptRecord(record), nil
}

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
