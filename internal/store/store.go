package store

import (
	crand "crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

const (
	recoveryLevel   = "Recoverable+Purgeable"
	recoverableDays = 90
)

var storeRandRead = crand.Read

type Storer interface {
	SetSecret(name string, req model.SecretSetRequest) (SecretRecord, error)
	GetSecret(name, version string) (SecretRecord, error)
	ListSecrets(maxResults int, skipToken string) ([]SecretRecord, *string, error)
	ListSecretVersions(name string, maxResults int, skipToken string) ([]SecretRecord, *string, error)
	UpdateSecret(name, version string, req model.SecretUpdateRequest) (SecretRecord, error)
	DeleteSecret(name string) (DeletedSecretRecord, error)
	ListDeletedSecrets(maxResults int, skipToken string) ([]DeletedSecretRecord, *string, error)
	GetDeletedSecret(name string) (DeletedSecretRecord, error)
	PurgeDeletedSecret(name string) error
	RecoverDeletedSecret(name string) (SecretRecord, error)
	BackupSecret(name string) (string, error)
	RestoreSecret(token string) (SecretRecord, error)

	CreateKey(name string, req model.CreateKeyRequest) (KeyRecord, error)
	ImportKey(name string, req model.ImportKeyRequest) (KeyRecord, error)
	GetKey(name, version string) (KeyRecord, error)
	ListKeys(maxResults int, skipToken string) ([]KeyRecord, *string, error)
	ListKeyVersions(name string, maxResults int, skipToken string) ([]KeyRecord, *string, error)
	UpdateKey(name, version string, req model.UpdateKeyRequest) (KeyRecord, error)
	DeleteKey(name string) (DeletedKeyRecord, error)
	ListDeletedKeys(maxResults int, skipToken string) ([]DeletedKeyRecord, *string, error)
	GetDeletedKey(name string) (DeletedKeyRecord, error)
	PurgeDeletedKey(name string) error
	RecoverDeletedKey(name string) (KeyRecord, error)
	Encrypt(name, version string, req model.EncryptRequest) (string, string, error)
	Decrypt(name, version string, req model.EncryptRequest) (string, string, error)
	Sign(name, version string, req model.SignRequest) (string, error)
	Verify(name, version string, req model.VerifyRequest) (bool, error)
	WrapKey(name, version string, req model.EncryptRequest) (string, error)
	UnwrapKey(name, version string, req model.EncryptRequest) (string, error)

	CreateCertificate(name string, req model.CreateCertificateRequest) (CertificateRecord, error)
	ImportCertificate(name string, req model.ImportCertificateRequest) (CertificateRecord, error)
	GetCertificate(name, version string) (CertificateRecord, error)
	ListCertificates(maxResults int, skipToken string) ([]CertificateRecord, *string, error)
	ListCertificateVersions(name string, maxResults int, skipToken string) ([]CertificateRecord, *string, error)
	UpdateCertificate(name, version string, req model.UpdateCertificateRequest) (CertificateRecord, error)
	GetCertificatePolicy(name string) (*model.CertificatePolicy, error)
	UpdateCertificatePolicy(name string, policy *model.CertificatePolicy) (*model.CertificatePolicy, error)
	GetPendingCertificateOperation(name string) (model.CertificateOperation, error)
	DeleteCertificate(name string) (DeletedCertificateRecord, error)
	ListDeletedCertificates(maxResults int, skipToken string) ([]DeletedCertificateRecord, *string, error)
	GetDeletedCertificate(name string) (DeletedCertificateRecord, error)
	PurgeDeletedCertificate(name string) error
	RecoverDeletedCertificate(name string) (CertificateRecord, error)
}

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

func newError(status int, code, message string) error {
	return &Error{Status: status, Code: code, Message: message}
}

func NewError(status int, code, message string) error {
	return newError(status, code, message)
}

type Store struct {
	mu                  sync.RWMutex
	secrets             map[string]*secretEntry
	deletedSecrets      map[string]*deletedSecretEntry
	keys                map[string]*keyEntry
	deletedKeys         map[string]*deletedKeyEntry
	certificates        map[string]*certificateEntry
	deletedCertificates map[string]*deletedCertificateEntry
}

type SecretRecord struct {
	Name        string
	Version     string
	Value       string
	ContentType string
	Attributes  model.Attributes
	Tags        map[string]string
}

type DeletedSecretRecord struct {
	SecretRecord
	RecoveryID         string
	DeletedDate        int64
	ScheduledPurgeDate int64
}

type KeyRecord struct {
	Name       string
	Version    string
	Key        model.JSONWebKey
	Attributes model.Attributes
	Tags       map[string]string
}

type DeletedKeyRecord struct {
	KeyRecord
	RecoveryID         string
	DeletedDate        int64
	ScheduledPurgeDate int64
}

type CertificateRecord struct {
	Name       string
	Version    string
	Cer        []byte
	Kid        string
	Sid        string
	Attributes model.Attributes
	Tags       map[string]string
	Policy     *model.CertificatePolicy
}

type DeletedCertificateRecord struct {
	CertificateRecord
	RecoveryID         string
	DeletedDate        int64
	ScheduledPurgeDate int64
}

type secretVersion struct {
	record SecretRecord
}

type secretEntry struct {
	versions []*secretVersion
}

type deletedSecretEntry struct {
	entry              *secretEntry
	recoveryID         string
	deletedDate        int64
	scheduledPurgeDate int64
}

type keyVersion struct {
	record   KeyRecord
	material kvcrypto.KeyMaterial
}

type keyEntry struct {
	versions []*keyVersion
}

type deletedKeyEntry struct {
	entry              *keyEntry
	recoveryID         string
	deletedDate        int64
	scheduledPurgeDate int64
}

type certificateVersion struct {
	record CertificateRecord
	pem    []byte
}

type certificateEntry struct {
	versions []*certificateVersion
}

type deletedCertificateEntry struct {
	entry              *certificateEntry
	recoveryID         string
	deletedDate        int64
	scheduledPurgeDate int64
}

func New() *Store {
	return &Store{
		secrets:             map[string]*secretEntry{},
		deletedSecrets:      map[string]*deletedSecretEntry{},
		keys:                map[string]*keyEntry{},
		deletedKeys:         map[string]*deletedKeyEntry{},
		certificates:        map[string]*certificateEntry{},
		deletedCertificates: map[string]*deletedCertificateEntry{},
	}
}

func cloneTags(tags map[string]string) map[string]string {
	if tags == nil {
		return nil
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		out[k] = v
	}
	return out
}

func cloneAttributes(in model.Attributes) model.Attributes {
	out := in
	if in.Enabled != nil {
		v := *in.Enabled
		out.Enabled = &v
	}
	if in.NotBefore != nil {
		v := *in.NotBefore
		out.NotBefore = &v
	}
	if in.Expires != nil {
		v := *in.Expires
		out.Expires = &v
	}
	return out
}

func buildAttributes(input *model.Attributes, created, updated int64) model.Attributes {
	attrs := model.Attributes{
		Created:         created,
		Updated:         updated,
		RecoveryLevel:   recoveryLevel,
		RecoverableDays: recoverableDays,
	}
	if input != nil {
		if input.Enabled != nil {
			v := *input.Enabled
			attrs.Enabled = &v
		}
		if input.NotBefore != nil {
			v := *input.NotBefore
			attrs.NotBefore = &v
		}
		if input.Expires != nil {
			v := *input.Expires
			attrs.Expires = &v
		}
	}
	return attrs
}

func mergeAttributes(current model.Attributes, patch *model.Attributes) model.Attributes {
	out := cloneAttributes(current)
	if patch != nil {
		if patch.Enabled != nil {
			v := *patch.Enabled
			out.Enabled = &v
		}
		if patch.NotBefore != nil {
			v := *patch.NotBefore
			out.NotBefore = &v
		}
		if patch.Expires != nil {
			v := *patch.Expires
			out.Expires = &v
		}
	}
	out.Updated = nowUnix()
	out.RecoveryLevel = recoveryLevel
	out.RecoverableDays = recoverableDays
	return out
}

func nowUnix() int64 {
	return time.Now().Unix()
}

func newVersion() string {
	buf := make([]byte, 16)
	if _, err := storeRandRead(buf); err != nil {
		panic("failed to generate version id: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

func newRecoveryID(kind, name string) string {
	return "/deleted" + kind + "/" + name + "/" + newVersion()
}

func paginateNames[T any](items []T, skipToken string, maxResults int) ([]T, *string, error) {
	if maxResults <= 0 {
		maxResults = 25
	}
	if maxResults > 100 {
		maxResults = 100
	}
	start := 0
	if skipToken != "" {
		parsed, err := strconv.Atoi(skipToken)
		if err != nil || parsed < 0 {
			return nil, nil, newError(400, "BadParameter", "The provided $skiptoken is invalid.")
		}
		start = parsed
	}
	if start >= len(items) {
		return []T{}, nil, nil
	}
	end := start + maxResults
	if end > len(items) {
		end = len(items)
	}
	page := items[start:end]
	if end >= len(items) {
		return page, nil, nil
	}
	next := strconv.Itoa(end)
	return page, &next, nil
}

func latestSecret(entry *secretEntry) *secretVersion {
	if entry == nil || len(entry.versions) == 0 {
		return nil
	}
	return entry.versions[len(entry.versions)-1]
}

func latestKey(entry *keyEntry) *keyVersion {
	if entry == nil || len(entry.versions) == 0 {
		return nil
	}
	return entry.versions[len(entry.versions)-1]
}

func latestCertificate(entry *certificateEntry) *certificateVersion {
	if entry == nil || len(entry.versions) == 0 {
		return nil
	}
	return entry.versions[len(entry.versions)-1]
}
