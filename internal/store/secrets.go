package store

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

type secretBackup struct {
	Name     string         `json:"name"`
	Versions []SecretRecord `json:"versions"`
}

func (s *Store) SetSecret(name string, req model.SecretSetRequest) (SecretRecord, error) {
	if name == "" {
		return SecretRecord{}, newError(http.StatusBadRequest, "BadParameter", "Secret name is required.")
	}
	if req.Value == "" {
		return SecretRecord{}, newError(http.StatusBadRequest, "BadParameter", "Secret value is required.")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.deletedSecrets[name]; ok {
		return SecretRecord{}, newError(http.StatusConflict, "InvalidOperation", fmt.Sprintf("Secret %s is currently deleted and cannot be reused until recovered or purged.", name))
	}

	now := nowUnix()
	record := SecretRecord{
		Name:        name,
		Version:     newVersion(),
		Value:       req.Value,
		ContentType: req.ContentType,
		Attributes:  buildAttributes(req.Attributes, now, now),
		Tags:        cloneTags(req.Tags),
	}
	entry := s.secrets[name]
	if entry == nil {
		entry = &secretEntry{}
		s.secrets[name] = entry
	}
	entry.versions = append(entry.versions, &secretVersion{record: record})
	return cloneSecretRecord(record), nil
}

func (s *Store) GetSecret(name, version string) (SecretRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.secrets[name]
	if entry == nil {
		return SecretRecord{}, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	ver := findSecretVersion(entry, version)
	if ver == nil {
		return SecretRecord{}, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	return cloneSecretRecord(ver.record), nil
}

func (s *Store) ListSecrets(maxResults int, skipToken string) ([]SecretRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.secrets))
	for name := range s.secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]SecretRecord, 0, len(page))
	for _, name := range page {
		latest := latestSecret(s.secrets[name])
		if latest != nil {
			copy := cloneSecretRecord(latest.record)
			copy.Value = ""
			items = append(items, copy)
		}
	}
	return items, next, nil
}

func (s *Store) ListSecretVersions(name string, maxResults int, skipToken string) ([]SecretRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.secrets[name]
	if entry == nil {
		return nil, nil, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	versions := make([]SecretRecord, 0, len(entry.versions))
	for i := len(entry.versions) - 1; i >= 0; i-- {
		copy := cloneSecretRecord(entry.versions[i].record)
		copy.Value = ""
		versions = append(versions, copy)
	}
	page, next, err := paginateNames(versions, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	return page, next, nil
}

func (s *Store) UpdateSecret(name, version string, req model.SecretUpdateRequest) (SecretRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.secrets[name]
	if entry == nil {
		return SecretRecord{}, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	ver := findSecretVersion(entry, version)
	if ver == nil {
		return SecretRecord{}, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	if req.ContentType != nil {
		ver.record.ContentType = *req.ContentType
	}
	if req.Tags != nil {
		ver.record.Tags = cloneTags(req.Tags)
	}
	ver.record.Attributes = mergeAttributes(ver.record.Attributes, req.Attributes)
	return cloneSecretRecord(ver.record), nil
}

func (s *Store) DeleteSecret(name string) (DeletedSecretRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.secrets[name]
	if entry == nil {
		return DeletedSecretRecord{}, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	if _, ok := s.deletedSecrets[name]; ok {
		return DeletedSecretRecord{}, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	delete(s.secrets, name)
	now := nowUnix()
	deleted := &deletedSecretEntry{
		entry:              entry,
		recoveryID:         newRecoveryID("secrets", name),
		deletedDate:        now,
		scheduledPurgeDate: now + int64(recoverableDays*24*60*60),
	}
	s.deletedSecrets[name] = deleted
	latest := cloneSecretRecord(latestSecret(entry).record)
	return DeletedSecretRecord{
		SecretRecord:       latest,
		RecoveryID:         deleted.recoveryID,
		DeletedDate:        deleted.deletedDate,
		ScheduledPurgeDate: deleted.scheduledPurgeDate,
	}, nil
}

func (s *Store) ListDeletedSecrets(maxResults int, skipToken string) ([]DeletedSecretRecord, *string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.deletedSecrets))
	for name := range s.deletedSecrets {
		names = append(names, name)
	}
	sort.Strings(names)
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]DeletedSecretRecord, 0, len(page))
	for _, name := range page {
		deleted := s.deletedSecrets[name]
		latest := cloneSecretRecord(latestSecret(deleted.entry).record)
		latest.Value = ""
		items = append(items, DeletedSecretRecord{
			SecretRecord:       latest,
			RecoveryID:         deleted.recoveryID,
			DeletedDate:        deleted.deletedDate,
			ScheduledPurgeDate: deleted.scheduledPurgeDate,
		})
	}
	return items, next, nil
}

func (s *Store) GetDeletedSecret(name string) (DeletedSecretRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	deleted := s.deletedSecrets[name]
	if deleted == nil {
		return DeletedSecretRecord{}, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A deleted secret with name %s was not found in this key vault.", name))
	}
	latest := cloneSecretRecord(latestSecret(deleted.entry).record)
	return DeletedSecretRecord{
		SecretRecord:       latest,
		RecoveryID:         deleted.recoveryID,
		DeletedDate:        deleted.deletedDate,
		ScheduledPurgeDate: deleted.scheduledPurgeDate,
	}, nil
}

func (s *Store) PurgeDeletedSecret(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.deletedSecrets[name]; !ok {
		return newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A deleted secret with name %s was not found in this key vault.", name))
	}
	delete(s.deletedSecrets, name)
	return nil
}

func (s *Store) RecoverDeletedSecret(name string) (SecretRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.secrets[name]; ok {
		return SecretRecord{}, newError(http.StatusConflict, "Conflict", fmt.Sprintf("Secret %s already exists.", name))
	}
	deleted := s.deletedSecrets[name]
	if deleted == nil {
		return SecretRecord{}, newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A deleted secret with name %s was not found in this key vault.", name))
	}
	s.secrets[name] = deleted.entry
	delete(s.deletedSecrets, name)
	return cloneSecretRecord(latestSecret(deleted.entry).record), nil
}

func (s *Store) BackupSecret(name string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.secrets[name]
	if entry == nil {
		return "", newError(http.StatusNotFound, "SecretNotFound", fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	payload := secretBackup{Name: name, Versions: make([]SecretRecord, 0, len(entry.versions))}
	for _, version := range entry.versions {
		payload.Versions = append(payload.Versions, cloneSecretRecord(version.record))
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (s *Store) RestoreSecret(token string) (SecretRecord, error) {
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return SecretRecord{}, newError(http.StatusBadRequest, "BadParameter", "The provided backup blob is invalid.")
	}
	var payload secretBackup
	if err := json.Unmarshal(data, &payload); err != nil {
		return SecretRecord{}, newError(http.StatusBadRequest, "BadParameter", "The provided backup blob is invalid.")
	}
	if payload.Name == "" || len(payload.Versions) == 0 {
		return SecretRecord{}, newError(http.StatusBadRequest, "BadParameter", "The provided backup blob is invalid.")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	entry := &secretEntry{versions: make([]*secretVersion, 0, len(payload.Versions))}
	for _, version := range payload.Versions {
		version.Name = payload.Name
		version.Attributes.RecoveryLevel = recoveryLevel
		version.Attributes.RecoverableDays = recoverableDays
		entry.versions = append(entry.versions, &secretVersion{record: cloneSecretRecord(version)})
	}
	s.secrets[payload.Name] = entry
	delete(s.deletedSecrets, payload.Name)
	return cloneSecretRecord(latestSecret(entry).record), nil
}

func (s *Store) putSecretVersion(name, version, value, contentType string, attrs model.Attributes, tags map[string]string) SecretRecord {
	record := SecretRecord{Name: name, Version: version, Value: value, ContentType: contentType, Attributes: cloneAttributes(attrs), Tags: cloneTags(tags)}
	entry := s.secrets[name]
	if entry == nil {
		entry = &secretEntry{}
		s.secrets[name] = entry
	}
	entry.versions = append(entry.versions, &secretVersion{record: record})
	return record
}

func findSecretVersion(entry *secretEntry, version string) *secretVersion {
	if version == "" {
		return latestSecret(entry)
	}
	for _, current := range entry.versions {
		if current.record.Version == version {
			return current
		}
	}
	return nil
}

func cloneSecretRecord(in SecretRecord) SecretRecord {
	return SecretRecord{
		Name:        in.Name,
		Version:     in.Version,
		Value:       in.Value,
		ContentType: in.ContentType,
		Attributes:  cloneAttributes(in.Attributes),
		Tags:        cloneTags(in.Tags),
	}
}
