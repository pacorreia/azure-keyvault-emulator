package sqlstore

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

const (
	recoveryLevel   = "Recoverable+Purgeable"
	recoverableDays = 90
)

// DBFlavor identifies the database backend.
type DBFlavor int

const (
	FlavorSQLite   DBFlavor = iota
	FlavorPostgres          // requires github.com/lib/pq
	FlavorMSSQL             // requires github.com/microsoft/go-mssqldb
)

// SQLStore is a database/sql-backed implementation of store.Storer.
type SQLStore struct {
	db     *sql.DB
	flavor DBFlavor
}

type serializedKeyMaterial struct {
	RSAPriv string `json:"rsa_priv,omitempty"`
	RSAPub  string `json:"rsa_pub,omitempty"`
	ECPriv  string `json:"ec_priv,omitempty"`
	ECPub   string `json:"ec_pub,omitempty"`
	AES     string `json:"aes,omitempty"`
}

type secretBackup struct {
	Name     string               `json:"name"`
	Versions []store.SecretRecord `json:"versions"`
}

type deletedSecretPayload struct {
	Versions []secretVersionSnapshot `json:"versions"`
}

type deletedKeyPayload struct {
	Versions []keyVersionSnapshot `json:"versions"`
}

type deletedCertificatePayload struct {
	Versions []certificateVersionSnapshot `json:"versions"`
}

type secretVersionSnapshot struct {
	Version     string            `json:"version"`
	Value       string            `json:"value"`
	ContentType string            `json:"content_type"`
	Attributes  model.Attributes  `json:"attributes"`
	Tags        map[string]string `json:"tags"`
	CreatedAt   int64             `json:"created_at"`
}

type keyVersionSnapshot struct {
	Version    string            `json:"version"`
	Key        model.JSONWebKey  `json:"key"`
	Material   string            `json:"material"`
	Attributes model.Attributes  `json:"attributes"`
	Tags       map[string]string `json:"tags"`
	CreatedAt  int64             `json:"created_at"`
}

type certificateVersionSnapshot struct {
	Version    string                   `json:"version"`
	Cer        string                   `json:"cer"`
	Kid        string                   `json:"kid,omitempty"`
	Sid        string                   `json:"sid,omitempty"`
	PEMData    string                   `json:"pem_data,omitempty"`
	Attributes model.Attributes         `json:"attributes"`
	Tags       map[string]string        `json:"tags"`
	Policy     *model.CertificatePolicy `json:"policy,omitempty"`
	CreatedAt  int64                    `json:"created_at"`
}

// NewSQLStore creates a SQLStore backed by db and runs schema migrations.
func NewSQLStore(db *sql.DB, flavor DBFlavor) (*SQLStore, error) {
	s := &SQLStore{db: db, flavor: flavor}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// ===== Placeholder helpers =====

func (f DBFlavor) ph(n int) string {
	switch f {
	case FlavorPostgres:
		return fmt.Sprintf("$%d", n)
	case FlavorMSSQL:
		return fmt.Sprintf("@p%d", n)
	default:
		return "?"
	}
}

func (s *SQLStore) phs(start, count int) string {
	parts := make([]string, count)
	for i := 0; i < count; i++ {
		parts[i] = s.flavor.ph(start + i)
	}
	return strings.Join(parts, ", ")
}

// limitOne returns the SQL suffix to limit results to one row (requires ORDER BY).
func (f DBFlavor) limitOne() string {
	if f == FlavorMSSQL {
		return "OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY"
	}
	return "LIMIT 1"
}

func (f DBFlavor) textType() string {
	if f == FlavorMSSQL {
		return "NVARCHAR(MAX)"
	}
	return "TEXT"
}

// ===== Schema migrations =====

func (s *SQLStore) migrate() error {
	tt := s.flavor.textType()
	stmts := []string{
		s.createTable("kv_secrets", fmt.Sprintf(
			`name %[1]s NOT NULL, version %[1]s NOT NULL, value %[1]s NOT NULL,
			content_type %[1]s NOT NULL, attributes %[1]s NOT NULL, tags %[1]s NOT NULL,
			created_at BIGINT NOT NULL, PRIMARY KEY (name, version)`, tt)),
		s.createTable("kv_deleted_secrets", fmt.Sprintf(
			`name %[1]s NOT NULL PRIMARY KEY, recovery_id %[1]s NOT NULL,
			deleted_date BIGINT NOT NULL, scheduled_purge_date BIGINT NOT NULL, versions %[1]s NOT NULL`, tt)),
		s.createTable("kv_keys", fmt.Sprintf(
			`name %[1]s NOT NULL, version %[1]s NOT NULL, jwk %[1]s NOT NULL,
			key_material %[1]s NOT NULL, attributes %[1]s NOT NULL, tags %[1]s NOT NULL,
			created_at BIGINT NOT NULL, PRIMARY KEY (name, version)`, tt)),
		s.createTable("kv_deleted_keys", fmt.Sprintf(
			`name %[1]s NOT NULL PRIMARY KEY, recovery_id %[1]s NOT NULL,
			deleted_date BIGINT NOT NULL, scheduled_purge_date BIGINT NOT NULL, versions %[1]s NOT NULL`, tt)),
		s.createTable("kv_certificates", fmt.Sprintf(
			`name %[1]s NOT NULL, version %[1]s NOT NULL, cer %[1]s NOT NULL,
			kid %[1]s NOT NULL, sid %[1]s NOT NULL, pem_data %[1]s NOT NULL,
			attributes %[1]s NOT NULL, tags %[1]s NOT NULL, policy %[1]s NULL,
			created_at BIGINT NOT NULL, PRIMARY KEY (name, version)`, tt)),
		s.createTable("kv_deleted_certificates", fmt.Sprintf(
			`name %[1]s NOT NULL PRIMARY KEY, recovery_id %[1]s NOT NULL,
			deleted_date BIGINT NOT NULL, scheduled_purge_date BIGINT NOT NULL, versions %[1]s NOT NULL`, tt)),
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) createTable(name, body string) string {
	if s.flavor == FlavorMSSQL {
		return fmt.Sprintf("IF OBJECT_ID(N'%s', N'U') IS NULL BEGIN CREATE TABLE %s (%s) END", name, name, body)
	}
	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", name, body)
}

// ===== Generic helpers =====

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
	out.Updated = time.Now().Unix()
	out.RecoveryLevel = recoveryLevel
	out.RecoverableDays = recoverableDays
	return out
}

func nowUnix() int64 { return time.Now().Unix() }

func tsNano() int64 { return time.Now().UnixNano() }

func newVersion() string {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		panic("failed to generate version id: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

func newRecoveryID(kind, name string) string {
	return "/deleted" + kind + "/" + name + "/" + newVersion()
}

func marshalTags(tags map[string]string) (string, error) {
	data, err := json.Marshal(tags)
	return string(data), err
}

func unmarshalTags(s string) (map[string]string, error) {
	var tags map[string]string
	err := json.Unmarshal([]byte(s), &tags)
	return tags, err
}

func marshalAttrs(attrs model.Attributes) (string, error) {
	data, err := json.Marshal(attrs)
	return string(data), err
}

func unmarshalAttrs(s string) (model.Attributes, error) {
	var attrs model.Attributes
	err := json.Unmarshal([]byte(s), &attrs)
	return attrs, err
}

func marshalJWK(jwk model.JSONWebKey) (string, error) {
	data, err := json.Marshal(jwk)
	return string(data), err
}

func unmarshalJWK(s string) (model.JSONWebKey, error) {
	var jwk model.JSONWebKey
	err := json.Unmarshal([]byte(s), &jwk)
	return jwk, err
}

func marshalPolicyArg(policy *model.CertificatePolicy) (interface{}, error) {
	if policy == nil {
		return nil, nil
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return string(data), nil
}

func unmarshalPolicyNS(ns sql.NullString) (*model.CertificatePolicy, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	var policy model.CertificatePolicy
	err := json.Unmarshal([]byte(ns.String), &policy)
	return &policy, err
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
			return nil, nil, store.NewError(400, "BadParameter", "The provided $skiptoken is invalid.")
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

// serializeKeyMaterial encodes a KeyMaterial as JSON with base64-encoded DER keys.
func serializeKeyMaterial(material kvcrypto.KeyMaterial) (string, error) {
	s := serializedKeyMaterial{}
	if material.RSA != nil {
		s.RSAPriv = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(material.RSA))
		s.RSAPub = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&material.RSA.PublicKey))
	} else if material.RSAPub != nil {
		s.RSAPub = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(material.RSAPub))
	}
	if material.ECDSA != nil {
		der, err := x509.MarshalECPrivateKey(material.ECDSA)
		if err != nil {
			return "", err
		}
		s.ECPriv = base64.StdEncoding.EncodeToString(der)
		der2, err := x509.MarshalPKIXPublicKey(&material.ECDSA.PublicKey)
		if err != nil {
			return "", err
		}
		s.ECPub = base64.StdEncoding.EncodeToString(der2)
	} else if material.ECDSAPub != nil {
		der, err := x509.MarshalPKIXPublicKey(material.ECDSAPub)
		if err != nil {
			return "", err
		}
		s.ECPub = base64.StdEncoding.EncodeToString(der)
	}
	if material.AES != nil {
		s.AES = base64.StdEncoding.EncodeToString(material.AES)
	}
	data, err := json.Marshal(s)
	return string(data), err
}

// deserializeKeyMaterial decodes a serialized key material JSON string.
func deserializeKeyMaterial(data string) (kvcrypto.KeyMaterial, error) {
	var s serializedKeyMaterial
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return kvcrypto.KeyMaterial{}, err
	}
	var m kvcrypto.KeyMaterial
	if s.RSAPriv != "" {
		der, err := base64.StdEncoding.DecodeString(s.RSAPriv)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		priv, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		m.RSA = priv
		m.RSAPub = &priv.PublicKey
	} else if s.RSAPub != "" {
		der, err := base64.StdEncoding.DecodeString(s.RSAPub)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		pub, err := x509.ParsePKCS1PublicKey(der)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		m.RSAPub = pub
	}
	if s.ECPriv != "" {
		der, err := base64.StdEncoding.DecodeString(s.ECPriv)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		priv, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		m.ECDSA = priv
		m.ECDSAPub = &priv.PublicKey
	} else if s.ECPub != "" {
		der, err := base64.StdEncoding.DecodeString(s.ECPub)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		if ecPub, ok := pub.(*ecdsa.PublicKey); ok {
			m.ECDSAPub = ecPub
		}
	}
	if s.AES != "" {
		key, err := base64.StdEncoding.DecodeString(s.AES)
		if err != nil {
			return kvcrypto.KeyMaterial{}, err
		}
		m.AES = key
	}
	return m, nil
}

// checkNotDeleted returns a Conflict error if name is in the given deleted table.
func (s *SQLStore) checkNotDeleted(table, name, kind string) error {
	var count int
	q := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE name = %s", table, s.flavor.ph(1))
	if err := s.db.QueryRow(q, name).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return store.NewError(http.StatusConflict, "InvalidOperation",
			fmt.Sprintf("%s %s is currently deleted and cannot be reused until recovered or purged.", kind, name))
	}
	return nil
}

// ===== SECRETS =====

func (s *SQLStore) SetSecret(name string, req model.SecretSetRequest) (store.SecretRecord, error) {
	if name == "" {
		return store.SecretRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Secret name is required.")
	}
	if req.Value == "" {
		return store.SecretRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Secret value is required.")
	}
	if err := s.checkNotDeleted("kv_deleted_secrets", name, "Secret"); err != nil {
		return store.SecretRecord{}, err
	}
	now := nowUnix()
	rec := store.SecretRecord{
		Name:        name,
		Version:     newVersion(),
		Value:       req.Value,
		ContentType: req.ContentType,
		Attributes:  buildAttributes(req.Attributes, now, now),
		Tags:        cloneTags(req.Tags),
	}
	if err := s.insertSecretRow(rec, tsNano()); err != nil {
		return store.SecretRecord{}, err
	}
	return rec, nil
}

func (s *SQLStore) insertSecretRow(rec store.SecretRecord, ts int64) error {
	attrsJSON, err := marshalAttrs(rec.Attributes)
	if err != nil {
		return err
	}
	tagsJSON, err := marshalTags(rec.Tags)
	if err != nil {
		return err
	}
	q := fmt.Sprintf(
		"INSERT INTO kv_secrets (name, version, value, content_type, attributes, tags, created_at) VALUES (%s)",
		s.phs(1, 7))
	_, err = s.db.Exec(q, rec.Name, rec.Version, rec.Value, rec.ContentType, attrsJSON, tagsJSON, ts)
	return err
}

func (s *SQLStore) getSecretVersionRow(name, version string) (store.SecretRecord, error) {
	var rec store.SecretRecord
	var attrsJSON, tagsJSON string
	rec.Name = name

	var q string
	var args []any
	if version == "" {
		q = fmt.Sprintf(
			"SELECT version, value, content_type, attributes, tags FROM kv_secrets WHERE name = %s ORDER BY created_at DESC %s",
			s.flavor.ph(1), s.flavor.limitOne())
		args = []any{name}
	} else {
		q = fmt.Sprintf(
			"SELECT version, value, content_type, attributes, tags FROM kv_secrets WHERE name = %s AND version = %s",
			s.flavor.ph(1), s.flavor.ph(2))
		args = []any{name, version}
	}
	err := s.db.QueryRow(q, args...).Scan(&rec.Version, &rec.Value, &rec.ContentType, &attrsJSON, &tagsJSON)
	if err == sql.ErrNoRows {
		return store.SecretRecord{}, store.NewError(http.StatusNotFound, "SecretNotFound",
			fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	if err != nil {
		return store.SecretRecord{}, err
	}
	rec.Attributes, err = unmarshalAttrs(attrsJSON)
	if err != nil {
		return store.SecretRecord{}, err
	}
	rec.Tags, err = unmarshalTags(tagsJSON)
	return rec, err
}

func (s *SQLStore) GetSecret(name, version string) (store.SecretRecord, error) {
	return s.getSecretVersionRow(name, version)
}

func (s *SQLStore) ListSecrets(maxResults int, skipToken string) ([]store.SecretRecord, *string, error) {
	rows, err := s.db.Query("SELECT DISTINCT name FROM kv_secrets ORDER BY name")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]store.SecretRecord, 0, len(page))
	for _, name := range page {
		rec, err := s.getSecretVersionRow(name, "")
		if err != nil {
			return nil, nil, err
		}
		rec.Value = ""
		items = append(items, rec)
	}
	return items, next, nil
}

func (s *SQLStore) ListSecretVersions(name string, maxResults int, skipToken string) ([]store.SecretRecord, *string, error) {
	var count int
	if err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM kv_secrets WHERE name = %s", s.flavor.ph(1)), name).Scan(&count); err != nil {
		return nil, nil, err
	}
	if count == 0 {
		return nil, nil, store.NewError(http.StatusNotFound, "SecretNotFound",
			fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	q := fmt.Sprintf(
		"SELECT version, content_type, attributes, tags FROM kv_secrets WHERE name = %s ORDER BY created_at DESC",
		s.flavor.ph(1))
	rows, err := s.db.Query(q, name)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var versions []store.SecretRecord
	for rows.Next() {
		var rec store.SecretRecord
		var attrsJSON, tagsJSON string
		rec.Name = name
		if err := rows.Scan(&rec.Version, &rec.ContentType, &attrsJSON, &tagsJSON); err != nil {
			return nil, nil, err
		}
		rec.Attributes, err = unmarshalAttrs(attrsJSON)
		if err != nil {
			return nil, nil, err
		}
		rec.Tags, err = unmarshalTags(tagsJSON)
		if err != nil {
			return nil, nil, err
		}
		versions = append(versions, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return paginateNames(versions, skipToken, maxResults)
}

func (s *SQLStore) UpdateSecret(name, version string, req model.SecretUpdateRequest) (store.SecretRecord, error) {
	rec, err := s.getSecretVersionRow(name, version)
	if err != nil {
		return store.SecretRecord{}, err
	}
	if req.ContentType != nil {
		rec.ContentType = *req.ContentType
	}
	if req.Tags != nil {
		rec.Tags = cloneTags(req.Tags)
	}
	rec.Attributes = mergeAttributes(rec.Attributes, req.Attributes)
	attrsJSON, err := marshalAttrs(rec.Attributes)
	if err != nil {
		return store.SecretRecord{}, err
	}
	tagsJSON, err := marshalTags(rec.Tags)
	if err != nil {
		return store.SecretRecord{}, err
	}
	q := fmt.Sprintf(
		"UPDATE kv_secrets SET content_type = %s, attributes = %s, tags = %s WHERE name = %s AND version = %s",
		s.flavor.ph(1), s.flavor.ph(2), s.flavor.ph(3), s.flavor.ph(4), s.flavor.ph(5))
	if _, err := s.db.Exec(q, rec.ContentType, attrsJSON, tagsJSON, rec.Name, rec.Version); err != nil {
		return store.SecretRecord{}, err
	}
	return rec, nil
}

func (s *SQLStore) DeleteSecret(name string) (store.DeletedSecretRecord, error) {
	latest, err := s.getSecretVersionRow(name, "")
	if err != nil {
		return store.DeletedSecretRecord{}, err
	}
	var count int
	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM kv_deleted_secrets WHERE name = %s", s.flavor.ph(1)), name,
	).Scan(&count); err != nil {
		return store.DeletedSecretRecord{}, err
	}
	if count > 0 {
		return store.DeletedSecretRecord{}, store.NewError(http.StatusNotFound, "SecretNotFound",
			fmt.Sprintf("A secret with (name/id) %s was not found in this key vault.", name))
	}
	snapshots, err := s.allSecretVersionSnapshots(name)
	if err != nil {
		return store.DeletedSecretRecord{}, err
	}
	payload, err := json.Marshal(deletedSecretPayload{Versions: snapshots})
	if err != nil {
		return store.DeletedSecretRecord{}, err
	}
	now := nowUnix()
	recoveryID := newRecoveryID("secrets", name)
	scheduledPurgeDate := now + int64(recoverableDays*24*60*60)
	q := fmt.Sprintf(
		"INSERT INTO kv_deleted_secrets (name, recovery_id, deleted_date, scheduled_purge_date, versions) VALUES (%s)",
		s.phs(1, 5))
	if _, err := s.db.Exec(q, name, recoveryID, now, scheduledPurgeDate, string(payload)); err != nil {
		return store.DeletedSecretRecord{}, err
	}
	if _, err := s.db.Exec(fmt.Sprintf("DELETE FROM kv_secrets WHERE name = %s", s.flavor.ph(1)), name); err != nil {
		return store.DeletedSecretRecord{}, err
	}
	return store.DeletedSecretRecord{
		SecretRecord:       latest,
		RecoveryID:         recoveryID,
		DeletedDate:        now,
		ScheduledPurgeDate: scheduledPurgeDate,
	}, nil
}

func (s *SQLStore) allSecretVersionSnapshots(name string) ([]secretVersionSnapshot, error) {
	q := fmt.Sprintf(
		"SELECT version, value, content_type, attributes, tags, created_at FROM kv_secrets WHERE name = %s ORDER BY created_at ASC",
		s.flavor.ph(1))
	rows, err := s.db.Query(q, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []secretVersionSnapshot
	for rows.Next() {
		var snap secretVersionSnapshot
		var attrsJSON, tagsJSON string
		if err := rows.Scan(&snap.Version, &snap.Value, &snap.ContentType, &attrsJSON, &tagsJSON, &snap.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(attrsJSON), &snap.Attributes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(tagsJSON), &snap.Tags); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snap)
	}
	return snapshots, rows.Err()
}

type deletedSecretRow struct {
	Name               string
	RecoveryID         string
	DeletedDate        int64
	ScheduledPurgeDate int64
	Versions           string
}

func (s *SQLStore) getDeletedSecretRow(name string) (deletedSecretRow, error) {
	var r deletedSecretRow
	q := fmt.Sprintf(
		"SELECT name, recovery_id, deleted_date, scheduled_purge_date, versions FROM kv_deleted_secrets WHERE name = %s",
		s.flavor.ph(1))
	err := s.db.QueryRow(q, name).Scan(&r.Name, &r.RecoveryID, &r.DeletedDate, &r.ScheduledPurgeDate, &r.Versions)
	if err == sql.ErrNoRows {
		return deletedSecretRow{}, store.NewError(http.StatusNotFound, "SecretNotFound",
			fmt.Sprintf("A deleted secret with name %s was not found in this key vault.", name))
	}
	return r, err
}

func deletedSecretFromRow(r deletedSecretRow) (store.DeletedSecretRecord, error) {
	var payload deletedSecretPayload
	if err := json.Unmarshal([]byte(r.Versions), &payload); err != nil {
		return store.DeletedSecretRecord{}, err
	}
	if len(payload.Versions) == 0 {
		return store.DeletedSecretRecord{}, fmt.Errorf("deleted secret %s has no versions", r.Name)
	}
	latest := payload.Versions[len(payload.Versions)-1]
	return store.DeletedSecretRecord{
		SecretRecord: store.SecretRecord{
			Name:        r.Name,
			Version:     latest.Version,
			Value:       latest.Value,
			ContentType: latest.ContentType,
			Attributes:  latest.Attributes,
			Tags:        cloneTags(latest.Tags),
		},
		RecoveryID:         r.RecoveryID,
		DeletedDate:        r.DeletedDate,
		ScheduledPurgeDate: r.ScheduledPurgeDate,
	}, nil
}

func (s *SQLStore) ListDeletedSecrets(maxResults int, skipToken string) ([]store.DeletedSecretRecord, *string, error) {
	rows, err := s.db.Query("SELECT name FROM kv_deleted_secrets ORDER BY name")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]store.DeletedSecretRecord, 0, len(page))
	for _, name := range page {
		r, err := s.getDeletedSecretRow(name)
		if err != nil {
			return nil, nil, err
		}
		rec, err := deletedSecretFromRow(r)
		if err != nil {
			return nil, nil, err
		}
		rec.SecretRecord.Value = ""
		items = append(items, rec)
	}
	return items, next, nil
}

func (s *SQLStore) GetDeletedSecret(name string) (store.DeletedSecretRecord, error) {
	r, err := s.getDeletedSecretRow(name)
	if err != nil {
		return store.DeletedSecretRecord{}, err
	}
	return deletedSecretFromRow(r)
}

func (s *SQLStore) PurgeDeletedSecret(name string) error {
	if _, err := s.getDeletedSecretRow(name); err != nil {
		return err
	}
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM kv_deleted_secrets WHERE name = %s", s.flavor.ph(1)), name)
	return err
}

func (s *SQLStore) RecoverDeletedSecret(name string) (store.SecretRecord, error) {
	var count int
	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM kv_secrets WHERE name = %s", s.flavor.ph(1)), name,
	).Scan(&count); err != nil {
		return store.SecretRecord{}, err
	}
	if count > 0 {
		return store.SecretRecord{}, store.NewError(http.StatusConflict, "Conflict",
			fmt.Sprintf("Secret %s already exists.", name))
	}
	r, err := s.getDeletedSecretRow(name)
	if err != nil {
		return store.SecretRecord{}, err
	}
	var payload deletedSecretPayload
	if err := json.Unmarshal([]byte(r.Versions), &payload); err != nil {
		return store.SecretRecord{}, err
	}
	for i, snap := range payload.Versions {
		rec := store.SecretRecord{
			Name:        name,
			Version:     snap.Version,
			Value:       snap.Value,
			ContentType: snap.ContentType,
			Attributes:  snap.Attributes,
			Tags:        cloneTags(snap.Tags),
		}
		if err := s.insertSecretRow(rec, snap.CreatedAt+int64(i)); err != nil {
			return store.SecretRecord{}, err
		}
	}
	if _, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM kv_deleted_secrets WHERE name = %s", s.flavor.ph(1)), name,
	); err != nil {
		return store.SecretRecord{}, err
	}
	latest := payload.Versions[len(payload.Versions)-1]
	return store.SecretRecord{
		Name:        name,
		Version:     latest.Version,
		Value:       latest.Value,
		ContentType: latest.ContentType,
		Attributes:  latest.Attributes,
		Tags:        cloneTags(latest.Tags),
	}, nil
}

func (s *SQLStore) BackupSecret(name string) (string, error) {
	if _, err := s.getSecretVersionRow(name, ""); err != nil {
		return "", err
	}
	snapshots, err := s.allSecretVersionSnapshots(name)
	if err != nil {
		return "", err
	}
	versions := make([]store.SecretRecord, 0, len(snapshots))
	for _, snap := range snapshots {
		versions = append(versions, store.SecretRecord{
			Name:        name,
			Version:     snap.Version,
			Value:       snap.Value,
			ContentType: snap.ContentType,
			Attributes:  snap.Attributes,
			Tags:        cloneTags(snap.Tags),
		})
	}
	data, err := json.Marshal(secretBackup{Name: name, Versions: versions})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (s *SQLStore) RestoreSecret(token string) (store.SecretRecord, error) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return store.SecretRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "The provided backup blob is invalid.")
	}
	var payload secretBackup
	if err := json.Unmarshal(raw, &payload); err != nil {
		return store.SecretRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "The provided backup blob is invalid.")
	}
	if payload.Name == "" || len(payload.Versions) == 0 {
		return store.SecretRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "The provided backup blob is invalid.")
	}
	// Replace all existing versions for this name.
	if _, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM kv_secrets WHERE name = %s", s.flavor.ph(1)), payload.Name,
	); err != nil {
		return store.SecretRecord{}, err
	}
	// Remove from deleted table if present.
	s.db.Exec(fmt.Sprintf("DELETE FROM kv_deleted_secrets WHERE name = %s", s.flavor.ph(1)), payload.Name) //nolint:errcheck
	for i, ver := range payload.Versions {
		ver.Name = payload.Name
		ver.Attributes.RecoveryLevel = recoveryLevel
		ver.Attributes.RecoverableDays = recoverableDays
		if err := s.insertSecretRow(ver, int64(i)); err != nil {
			return store.SecretRecord{}, err
		}
	}
	latest := payload.Versions[len(payload.Versions)-1]
	latest.Name = payload.Name
	return latest, nil
}

// ===== KEYS =====

func (s *SQLStore) insertKeyRow(rec store.KeyRecord, material kvcrypto.KeyMaterial, ts int64) error {
	jwkJSON, err := marshalJWK(rec.Key)
	if err != nil {
		return err
	}
	matJSON, err := serializeKeyMaterial(material)
	if err != nil {
		return err
	}
	attrsJSON, err := marshalAttrs(rec.Attributes)
	if err != nil {
		return err
	}
	tagsJSON, err := marshalTags(rec.Tags)
	if err != nil {
		return err
	}
	q := fmt.Sprintf(
		"INSERT INTO kv_keys (name, version, jwk, key_material, attributes, tags, created_at) VALUES (%s)",
		s.phs(1, 7))
	_, err = s.db.Exec(q, rec.Name, rec.Version, jwkJSON, matJSON, attrsJSON, tagsJSON, ts)
	return err
}

func (s *SQLStore) getKeyVersionRow(name, version string) (store.KeyRecord, kvcrypto.KeyMaterial, error) {
	var rec store.KeyRecord
	var jwkJSON, matJSON, attrsJSON, tagsJSON string
	rec.Name = name

	var q string
	var args []any
	if version == "" {
		q = fmt.Sprintf(
			"SELECT version, jwk, key_material, attributes, tags FROM kv_keys WHERE name = %s ORDER BY created_at DESC %s",
			s.flavor.ph(1), s.flavor.limitOne())
		args = []any{name}
	} else {
		q = fmt.Sprintf(
			"SELECT version, jwk, key_material, attributes, tags FROM kv_keys WHERE name = %s AND version = %s",
			s.flavor.ph(1), s.flavor.ph(2))
		args = []any{name, version}
	}
	err := s.db.QueryRow(q, args...).Scan(&rec.Version, &jwkJSON, &matJSON, &attrsJSON, &tagsJSON)
	if err == sql.ErrNoRows {
		return rec, kvcrypto.KeyMaterial{}, store.NewError(http.StatusNotFound, "KeyNotFound",
			fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	if err != nil {
		return rec, kvcrypto.KeyMaterial{}, err
	}
	rec.Key, err = unmarshalJWK(jwkJSON)
	if err != nil {
		return rec, kvcrypto.KeyMaterial{}, err
	}
	material, err := deserializeKeyMaterial(matJSON)
	if err != nil {
		return rec, kvcrypto.KeyMaterial{}, err
	}
	rec.Attributes, err = unmarshalAttrs(attrsJSON)
	if err != nil {
		return rec, kvcrypto.KeyMaterial{}, err
	}
	rec.Tags, err = unmarshalTags(tagsJSON)
	return rec, material, err
}

func (s *SQLStore) CreateKey(name string, req model.CreateKeyRequest) (store.KeyRecord, error) {
	if name == "" {
		return store.KeyRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Key name is required.")
	}
	if req.Kty == "" {
		return store.KeyRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Key type is required.")
	}
	if err := s.checkNotDeleted("kv_deleted_keys", name, "Key"); err != nil {
		return store.KeyRecord{}, err
	}
	now := nowUnix()
	version := newVersion()
	ops := defaultKeyOps(req.Kty, req.KeyOps)
	material, jwk, err := kvcrypto.GenerateKey(req.Kty, req.KeySize, req.Crv, "", ops)
	if err != nil {
		return store.KeyRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", err.Error())
	}
	rec := store.KeyRecord{
		Name:       name,
		Version:    version,
		Key:        jwk,
		Attributes: buildAttributes(req.Attributes, now, now),
		Tags:       cloneTags(req.Tags),
	}
	if err := s.insertKeyRow(rec, material, tsNano()); err != nil {
		return store.KeyRecord{}, err
	}
	return rec, nil
}

func (s *SQLStore) ImportKey(name string, req model.ImportKeyRequest) (store.KeyRecord, error) {
	if name == "" {
		return store.KeyRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Key name is required.")
	}
	if req.Key.Kty == "" {
		return store.KeyRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Key type is required.")
	}
	if err := s.checkNotDeleted("kv_deleted_keys", name, "Key"); err != nil {
		return store.KeyRecord{}, err
	}
	material, jwk, err := kvcrypto.ImportKey(req.Key, "")
	if err != nil {
		return store.KeyRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", err.Error())
	}
	ops := defaultKeyOps(req.Key.Kty, req.Key.KeyOps)
	jwk.KeyOps = ops
	now := nowUnix()
	rec := store.KeyRecord{
		Name:       name,
		Version:    newVersion(),
		Key:        jwk,
		Attributes: buildAttributes(req.Attributes, now, now),
		Tags:       cloneTags(req.Tags),
	}
	if err := s.insertKeyRow(rec, material, tsNano()); err != nil {
		return store.KeyRecord{}, err
	}
	return rec, nil
}

func (s *SQLStore) GetKey(name, version string) (store.KeyRecord, error) {
	rec, _, err := s.getKeyVersionRow(name, version)
	return rec, err
}

func (s *SQLStore) ListKeys(maxResults int, skipToken string) ([]store.KeyRecord, *string, error) {
	rows, err := s.db.Query("SELECT DISTINCT name FROM kv_keys ORDER BY name")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]store.KeyRecord, 0, len(page))
	for _, name := range page {
		rec, _, err := s.getKeyVersionRow(name, "")
		if err != nil {
			return nil, nil, err
		}
		items = append(items, rec)
	}
	return items, next, nil
}

func (s *SQLStore) ListKeyVersions(name string, maxResults int, skipToken string) ([]store.KeyRecord, *string, error) {
	var count int
	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM kv_keys WHERE name = %s", s.flavor.ph(1)), name,
	).Scan(&count); err != nil {
		return nil, nil, err
	}
	if count == 0 {
		return nil, nil, store.NewError(http.StatusNotFound, "KeyNotFound",
			fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	q := fmt.Sprintf(
		"SELECT version, jwk, attributes, tags FROM kv_keys WHERE name = %s ORDER BY created_at DESC",
		s.flavor.ph(1))
	rows, err := s.db.Query(q, name)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var versions []store.KeyRecord
	for rows.Next() {
		var rec store.KeyRecord
		var jwkJSON, attrsJSON, tagsJSON string
		rec.Name = name
		if err := rows.Scan(&rec.Version, &jwkJSON, &attrsJSON, &tagsJSON); err != nil {
			return nil, nil, err
		}
		rec.Key, err = unmarshalJWK(jwkJSON)
		if err != nil {
			return nil, nil, err
		}
		rec.Attributes, err = unmarshalAttrs(attrsJSON)
		if err != nil {
			return nil, nil, err
		}
		rec.Tags, err = unmarshalTags(tagsJSON)
		if err != nil {
			return nil, nil, err
		}
		versions = append(versions, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return paginateNames(versions, skipToken, maxResults)
}

func (s *SQLStore) UpdateKey(name, version string, req model.UpdateKeyRequest) (store.KeyRecord, error) {
	rec, _, err := s.getKeyVersionRow(name, version)
	if err != nil {
		return store.KeyRecord{}, err
	}
	rec.Attributes = mergeAttributes(rec.Attributes, req.Attributes)
	if req.Tags != nil {
		rec.Tags = cloneTags(req.Tags)
	}
	if req.KeyOps != nil {
		rec.Key.KeyOps = append([]string(nil), req.KeyOps...)
	}
	jwkJSON, err := marshalJWK(rec.Key)
	if err != nil {
		return store.KeyRecord{}, err
	}
	attrsJSON, err := marshalAttrs(rec.Attributes)
	if err != nil {
		return store.KeyRecord{}, err
	}
	tagsJSON, err := marshalTags(rec.Tags)
	if err != nil {
		return store.KeyRecord{}, err
	}
	q := fmt.Sprintf(
		"UPDATE kv_keys SET jwk = %s, attributes = %s, tags = %s WHERE name = %s AND version = %s",
		s.flavor.ph(1), s.flavor.ph(2), s.flavor.ph(3), s.flavor.ph(4), s.flavor.ph(5))
	if _, err := s.db.Exec(q, jwkJSON, attrsJSON, tagsJSON, rec.Name, rec.Version); err != nil {
		return store.KeyRecord{}, err
	}
	return rec, nil
}

func (s *SQLStore) DeleteKey(name string) (store.DeletedKeyRecord, error) {
	latest, _, err := s.getKeyVersionRow(name, "")
	if err != nil {
		return store.DeletedKeyRecord{}, err
	}
	var count int
	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM kv_deleted_keys WHERE name = %s", s.flavor.ph(1)), name,
	).Scan(&count); err != nil {
		return store.DeletedKeyRecord{}, err
	}
	if count > 0 {
		return store.DeletedKeyRecord{}, store.NewError(http.StatusNotFound, "KeyNotFound",
			fmt.Sprintf("A key with (name/id) %s was not found in this key vault.", name))
	}
	snapshots, err := s.allKeyVersionSnapshots(name)
	if err != nil {
		return store.DeletedKeyRecord{}, err
	}
	payload, err := json.Marshal(deletedKeyPayload{Versions: snapshots})
	if err != nil {
		return store.DeletedKeyRecord{}, err
	}
	now := nowUnix()
	recoveryID := newRecoveryID("keys", name)
	scheduledPurgeDate := now + int64(recoverableDays*24*60*60)
	q := fmt.Sprintf(
		"INSERT INTO kv_deleted_keys (name, recovery_id, deleted_date, scheduled_purge_date, versions) VALUES (%s)",
		s.phs(1, 5))
	if _, err := s.db.Exec(q, name, recoveryID, now, scheduledPurgeDate, string(payload)); err != nil {
		return store.DeletedKeyRecord{}, err
	}
	if _, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM kv_keys WHERE name = %s", s.flavor.ph(1)), name,
	); err != nil {
		return store.DeletedKeyRecord{}, err
	}
	return store.DeletedKeyRecord{
		KeyRecord:          latest,
		RecoveryID:         recoveryID,
		DeletedDate:        now,
		ScheduledPurgeDate: scheduledPurgeDate,
	}, nil
}

func (s *SQLStore) allKeyVersionSnapshots(name string) ([]keyVersionSnapshot, error) {
	q := fmt.Sprintf(
		"SELECT version, jwk, key_material, attributes, tags, created_at FROM kv_keys WHERE name = %s ORDER BY created_at ASC",
		s.flavor.ph(1))
	rows, err := s.db.Query(q, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []keyVersionSnapshot
	for rows.Next() {
		var snap keyVersionSnapshot
		var attrsJSON, tagsJSON, jwkJSON string
		if err := rows.Scan(&snap.Version, &jwkJSON, &snap.Material, &attrsJSON, &tagsJSON, &snap.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(jwkJSON), &snap.Key); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(attrsJSON), &snap.Attributes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(tagsJSON), &snap.Tags); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snap)
	}
	return snapshots, rows.Err()
}

type deletedKeyRow struct {
	Name               string
	RecoveryID         string
	DeletedDate        int64
	ScheduledPurgeDate int64
	Versions           string
}

func (s *SQLStore) getDeletedKeyRow(name string) (deletedKeyRow, error) {
	var r deletedKeyRow
	q := fmt.Sprintf(
		"SELECT name, recovery_id, deleted_date, scheduled_purge_date, versions FROM kv_deleted_keys WHERE name = %s",
		s.flavor.ph(1))
	err := s.db.QueryRow(q, name).Scan(&r.Name, &r.RecoveryID, &r.DeletedDate, &r.ScheduledPurgeDate, &r.Versions)
	if err == sql.ErrNoRows {
		return deletedKeyRow{}, store.NewError(http.StatusNotFound, "KeyNotFound",
			fmt.Sprintf("A deleted key with name %s was not found in this key vault.", name))
	}
	return r, err
}

func deletedKeyFromRow(r deletedKeyRow) (store.DeletedKeyRecord, error) {
	var payload deletedKeyPayload
	if err := json.Unmarshal([]byte(r.Versions), &payload); err != nil {
		return store.DeletedKeyRecord{}, err
	}
	if len(payload.Versions) == 0 {
		return store.DeletedKeyRecord{}, fmt.Errorf("deleted key %s has no versions", r.Name)
	}
	latest := payload.Versions[len(payload.Versions)-1]
	return store.DeletedKeyRecord{
		KeyRecord: store.KeyRecord{
			Name:       r.Name,
			Version:    latest.Version,
			Key:        latest.Key,
			Attributes: latest.Attributes,
			Tags:       cloneTags(latest.Tags),
		},
		RecoveryID:         r.RecoveryID,
		DeletedDate:        r.DeletedDate,
		ScheduledPurgeDate: r.ScheduledPurgeDate,
	}, nil
}

func (s *SQLStore) ListDeletedKeys(maxResults int, skipToken string) ([]store.DeletedKeyRecord, *string, error) {
	rows, err := s.db.Query("SELECT name FROM kv_deleted_keys ORDER BY name")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]store.DeletedKeyRecord, 0, len(page))
	for _, name := range page {
		r, err := s.getDeletedKeyRow(name)
		if err != nil {
			return nil, nil, err
		}
		rec, err := deletedKeyFromRow(r)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, rec)
	}
	return items, next, nil
}

func (s *SQLStore) GetDeletedKey(name string) (store.DeletedKeyRecord, error) {
	r, err := s.getDeletedKeyRow(name)
	if err != nil {
		return store.DeletedKeyRecord{}, err
	}
	return deletedKeyFromRow(r)
}

func (s *SQLStore) PurgeDeletedKey(name string) error {
	if _, err := s.getDeletedKeyRow(name); err != nil {
		return err
	}
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM kv_deleted_keys WHERE name = %s", s.flavor.ph(1)), name)
	return err
}

func (s *SQLStore) RecoverDeletedKey(name string) (store.KeyRecord, error) {
	var count int
	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM kv_keys WHERE name = %s", s.flavor.ph(1)), name,
	).Scan(&count); err != nil {
		return store.KeyRecord{}, err
	}
	if count > 0 {
		return store.KeyRecord{}, store.NewError(http.StatusConflict, "Conflict",
			fmt.Sprintf("Key %s already exists.", name))
	}
	r, err := s.getDeletedKeyRow(name)
	if err != nil {
		return store.KeyRecord{}, err
	}
	var payload deletedKeyPayload
	if err := json.Unmarshal([]byte(r.Versions), &payload); err != nil {
		return store.KeyRecord{}, err
	}
	for i, snap := range payload.Versions {
		material, err := deserializeKeyMaterial(snap.Material)
		if err != nil {
			return store.KeyRecord{}, err
		}
		rec := store.KeyRecord{
			Name:       name,
			Version:    snap.Version,
			Key:        snap.Key,
			Attributes: snap.Attributes,
			Tags:       cloneTags(snap.Tags),
		}
		if err := s.insertKeyRow(rec, material, snap.CreatedAt+int64(i)); err != nil {
			return store.KeyRecord{}, err
		}
	}
	if _, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM kv_deleted_keys WHERE name = %s", s.flavor.ph(1)), name,
	); err != nil {
		return store.KeyRecord{}, err
	}
	latest := payload.Versions[len(payload.Versions)-1]
	return store.KeyRecord{
		Name:       name,
		Version:    latest.Version,
		Key:        latest.Key,
		Attributes: latest.Attributes,
		Tags:       cloneTags(latest.Tags),
	}, nil
}

// ===== KEY CRYPTO OPS =====

func (s *SQLStore) Encrypt(name, version string, req model.EncryptRequest) (string, string, error) {
	rec, material, err := s.getKeyVersionRow(name, version)
	if err != nil {
		return "", "", err
	}
	value, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	var iv []byte
	if req.IV != "" {
		if iv, err = kvcrypto.DecodeBase64URL(req.IV); err != nil {
			return "", "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided iv is not valid base64url data.")
		}
	}
	ciphertext, outIV, err := kvcrypto.Encrypt(material, rec.Key.Kty, req.Alg, value, iv)
	if err != nil {
		return "", "", store.NewError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	ivValue := ""
	if len(outIV) > 0 {
		ivValue = kvcrypto.EncodeBase64URL(outIV)
	}
	return kvcrypto.EncodeBase64URL(ciphertext), ivValue, nil
}

func (s *SQLStore) Decrypt(name, version string, req model.EncryptRequest) (string, string, error) {
	rec, material, err := s.getKeyVersionRow(name, version)
	if err != nil {
		return "", "", err
	}
	value, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	var iv []byte
	if req.IV != "" {
		if iv, err = kvcrypto.DecodeBase64URL(req.IV); err != nil {
			return "", "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided iv is not valid base64url data.")
		}
	}
	plaintext, outIV, err := kvcrypto.Decrypt(material, rec.Key.Kty, req.Alg, value, iv)
	if err != nil {
		return "", "", store.NewError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	ivValue := ""
	if len(outIV) > 0 {
		ivValue = kvcrypto.EncodeBase64URL(outIV)
	}
	return kvcrypto.EncodeBase64URL(plaintext), ivValue, nil
}

func (s *SQLStore) Sign(name, version string, req model.SignRequest) (string, error) {
	rec, material, err := s.getKeyVersionRow(name, version)
	if err != nil {
		return "", err
	}
	digest, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	sig, err := kvcrypto.Sign(material, rec.Key.Kty, req.Alg, digest)
	if err != nil {
		return "", store.NewError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	return kvcrypto.EncodeBase64URL(sig), nil
}

func (s *SQLStore) Verify(name, version string, req model.VerifyRequest) (bool, error) {
	rec, material, err := s.getKeyVersionRow(name, version)
	if err != nil {
		return false, err
	}
	digest, err := kvcrypto.DecodeBase64URL(req.Digest)
	if err != nil {
		return false, store.NewError(http.StatusBadRequest, "BadParameter", "The provided digest is not valid base64url data.")
	}
	sig, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return false, store.NewError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	ok, err := kvcrypto.Verify(material, rec.Key.Kty, req.Alg, digest, sig)
	if err != nil {
		return false, store.NewError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	return ok, nil
}

func (s *SQLStore) WrapKey(name, version string, req model.EncryptRequest) (string, error) {
	rec, material, err := s.getKeyVersionRow(name, version)
	if err != nil {
		return "", err
	}
	value, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	wrapped, err := kvcrypto.Wrap(material, rec.Key.Kty, req.Alg, value)
	if err != nil {
		return "", store.NewError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	return kvcrypto.EncodeBase64URL(wrapped), nil
}

func (s *SQLStore) UnwrapKey(name, version string, req model.EncryptRequest) (string, error) {
	rec, material, err := s.getKeyVersionRow(name, version)
	if err != nil {
		return "", err
	}
	value, err := kvcrypto.DecodeBase64URL(req.Value)
	if err != nil {
		return "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided value is not valid base64url data.")
	}
	unwrapped, err := kvcrypto.Unwrap(material, rec.Key.Kty, req.Alg, value)
	if err != nil {
		return "", store.NewError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	return kvcrypto.EncodeBase64URL(unwrapped), nil
}

// ===== CERTIFICATES =====

func (s *SQLStore) insertCertRow(rec store.CertificateRecord, pemData []byte, ts int64) error {
	cerB64 := base64.StdEncoding.EncodeToString(rec.Cer)
	attrsJSON, err := marshalAttrs(rec.Attributes)
	if err != nil {
		return err
	}
	tagsJSON, err := marshalTags(rec.Tags)
	if err != nil {
		return err
	}
	policyArg, err := marshalPolicyArg(rec.Policy)
	if err != nil {
		return err
	}
	q := fmt.Sprintf(
		"INSERT INTO kv_certificates (name, version, cer, kid, sid, pem_data, attributes, tags, policy, created_at) VALUES (%s)",
		s.phs(1, 10))
	_, err = s.db.Exec(q,
		rec.Name, rec.Version, cerB64, rec.Kid, rec.Sid,
		string(pemData), attrsJSON, tagsJSON, policyArg, ts)
	return err
}

func (s *SQLStore) getCertVersionRow(name, version string) (store.CertificateRecord, []byte, error) {
	var rec store.CertificateRecord
	var cerB64, pemStr, attrsJSON, tagsJSON string
	var policyNS sql.NullString
	rec.Name = name

	var q string
	var args []any
	if version == "" {
		q = fmt.Sprintf(
			"SELECT version, cer, kid, sid, pem_data, attributes, tags, policy FROM kv_certificates WHERE name = %s ORDER BY created_at DESC %s",
			s.flavor.ph(1), s.flavor.limitOne())
		args = []any{name}
	} else {
		q = fmt.Sprintf(
			"SELECT version, cer, kid, sid, pem_data, attributes, tags, policy FROM kv_certificates WHERE name = %s AND version = %s",
			s.flavor.ph(1), s.flavor.ph(2))
		args = []any{name, version}
	}
	err := s.db.QueryRow(q, args...).Scan(
		&rec.Version, &cerB64, &rec.Kid, &rec.Sid, &pemStr, &attrsJSON, &tagsJSON, &policyNS)
	if err == sql.ErrNoRows {
		return rec, nil, store.NewError(http.StatusNotFound, "CertificateNotFound",
			fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	if err != nil {
		return rec, nil, err
	}
	rec.Cer, err = base64.StdEncoding.DecodeString(cerB64)
	if err != nil {
		return rec, nil, err
	}
	rec.Attributes, err = unmarshalAttrs(attrsJSON)
	if err != nil {
		return rec, nil, err
	}
	rec.Tags, err = unmarshalTags(tagsJSON)
	if err != nil {
		return rec, nil, err
	}
	rec.Policy, err = unmarshalPolicyNS(policyNS)
	if err != nil {
		return rec, nil, err
	}
	return rec, []byte(pemStr), nil
}

func (s *SQLStore) CreateCertificate(name string, req model.CreateCertificateRequest) (store.CertificateRecord, error) {
	if name == "" {
		return store.CertificateRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Certificate name is required.")
	}
	if err := s.checkNotDeleted("kv_deleted_certificates", name, "Certificate"); err != nil {
		return store.CertificateRecord{}, err
	}
	policy := defaultCertificatePolicy(name, req.Policy)
	now := nowUnix()
	version := newVersion()
	attrs := buildAttributes(req.Attributes, now, now)

	priv, der, err := kvcrypto.GenerateSelfSignedCert(name, policy)
	if err != nil {
		return store.CertificateRecord{}, store.NewError(http.StatusBadRequest, "InvalidOperation", err.Error())
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	managedSecret := string(append(certPEM, keyPEM...))

	rec := store.CertificateRecord{
		Name:       name,
		Version:    version,
		Cer:        append([]byte(nil), der...),
		Kid:        name,
		Sid:        name,
		Attributes: attrs,
		Tags:       cloneTags(req.Tags),
		Policy:     clonePolicy(policy),
	}
	ts := tsNano()
	if err := s.insertCertRow(rec, certPEM, ts); err != nil {
		return store.CertificateRecord{}, err
	}

	keyRec := store.KeyRecord{
		Name:       name,
		Version:    version,
		Key:        kvcrypto.RSAToJWK("", "RSA", defaultKeyOps("RSA", nil), &priv.PublicKey),
		Attributes: attrs,
		Tags:       cloneTags(req.Tags),
	}
	if err := s.insertKeyRow(keyRec, kvcrypto.KeyMaterial{RSA: priv, RSAPub: &priv.PublicKey}, ts); err != nil {
		return store.CertificateRecord{}, err
	}

	secretRec := store.SecretRecord{
		Name:        name,
		Version:     version,
		Value:       managedSecret,
		ContentType: "application/x-pkcs12",
		Attributes:  attrs,
		Tags:        cloneTags(req.Tags),
	}
	if err := s.insertSecretRow(secretRec, ts); err != nil {
		return store.CertificateRecord{}, err
	}
	return cloneCertRecord(rec), nil
}

func (s *SQLStore) ImportCertificate(name string, req model.ImportCertificateRequest) (store.CertificateRecord, error) {
	if name == "" {
		return store.CertificateRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Certificate name is required.")
	}
	if req.Value == "" {
		return store.CertificateRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", "Certificate value is required.")
	}
	cert, priv, pemValue, err := kvcrypto.ParseImportedCertificate(req.Value)
	if err != nil {
		return store.CertificateRecord{}, store.NewError(http.StatusBadRequest, "BadParameter", err.Error())
	}
	if err := s.checkNotDeleted("kv_deleted_certificates", name, "Certificate"); err != nil {
		return store.CertificateRecord{}, err
	}
	policy := defaultCertificatePolicy(name, req.Policy)
	now := nowUnix()
	version := newVersion()
	attrs := buildAttributes(req.Attributes, now, now)

	rec := store.CertificateRecord{
		Name:       name,
		Version:    version,
		Cer:        append([]byte(nil), cert.Raw...),
		Kid:        name,
		Sid:        name,
		Attributes: attrs,
		Tags:       cloneTags(req.Tags),
		Policy:     clonePolicy(policy),
	}
	ts := tsNano()
	certPEM := extractCertPEM(pemValue)
	if err := s.insertCertRow(rec, certPEM, ts); err != nil {
		return store.CertificateRecord{}, err
	}

	if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		material := kvcrypto.KeyMaterial{RSAPub: rsaPub}
		if priv != nil {
			material.RSA = priv
			material.RSAPub = &priv.PublicKey
		}
		keyRec := store.KeyRecord{
			Name:       name,
			Version:    version,
			Key:        kvcrypto.RSAToJWK("", "RSA", defaultKeyOps("RSA", nil), rsaPub),
			Attributes: attrs,
			Tags:       cloneTags(req.Tags),
		}
		if err := s.insertKeyRow(keyRec, material, ts); err != nil {
			return store.CertificateRecord{}, err
		}
	}
	secretRec := store.SecretRecord{
		Name:        name,
		Version:     version,
		Value:       string(pemValue),
		ContentType: "application/x-pkcs12",
		Attributes:  attrs,
		Tags:        cloneTags(req.Tags),
	}
	if err := s.insertSecretRow(secretRec, ts); err != nil {
		return store.CertificateRecord{}, err
	}
	return cloneCertRecord(rec), nil
}

// extractCertPEM returns the CERTIFICATE block(s) from a PEM bundle, dropping private keys.
func extractCertPEM(pemData []byte) []byte {
	var out []byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, pem.EncodeToMemory(block)...)
		}
	}
	if len(out) == 0 {
		return pemData
	}
	return out
}

func (s *SQLStore) GetCertificate(name, version string) (store.CertificateRecord, error) {
	rec, _, err := s.getCertVersionRow(name, version)
	return rec, err
}

func (s *SQLStore) ListCertificates(maxResults int, skipToken string) ([]store.CertificateRecord, *string, error) {
	rows, err := s.db.Query("SELECT DISTINCT name FROM kv_certificates ORDER BY name")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]store.CertificateRecord, 0, len(page))
	for _, name := range page {
		rec, _, err := s.getCertVersionRow(name, "")
		if err != nil {
			return nil, nil, err
		}
		items = append(items, rec)
	}
	return items, next, nil
}

func (s *SQLStore) ListCertificateVersions(name string, maxResults int, skipToken string) ([]store.CertificateRecord, *string, error) {
	var count int
	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM kv_certificates WHERE name = %s", s.flavor.ph(1)), name,
	).Scan(&count); err != nil {
		return nil, nil, err
	}
	if count == 0 {
		return nil, nil, store.NewError(http.StatusNotFound, "CertificateNotFound",
			fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	q := fmt.Sprintf(
		"SELECT version, cer, kid, sid, attributes, tags, policy FROM kv_certificates WHERE name = %s ORDER BY created_at DESC",
		s.flavor.ph(1))
	rows, err := s.db.Query(q, name)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var versions []store.CertificateRecord
	for rows.Next() {
		var rec store.CertificateRecord
		var cerB64, attrsJSON, tagsJSON string
		var policyNS sql.NullString
		rec.Name = name
		if err := rows.Scan(&rec.Version, &cerB64, &rec.Kid, &rec.Sid, &attrsJSON, &tagsJSON, &policyNS); err != nil {
			return nil, nil, err
		}
		rec.Cer, err = base64.StdEncoding.DecodeString(cerB64)
		if err != nil {
			return nil, nil, err
		}
		rec.Attributes, err = unmarshalAttrs(attrsJSON)
		if err != nil {
			return nil, nil, err
		}
		rec.Tags, err = unmarshalTags(tagsJSON)
		if err != nil {
			return nil, nil, err
		}
		rec.Policy, err = unmarshalPolicyNS(policyNS)
		if err != nil {
			return nil, nil, err
		}
		versions = append(versions, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return paginateNames(versions, skipToken, maxResults)
}

func (s *SQLStore) UpdateCertificate(name, version string, req model.UpdateCertificateRequest) (store.CertificateRecord, error) {
	rec, _, err := s.getCertVersionRow(name, version)
	if err != nil {
		return store.CertificateRecord{}, err
	}
	rec.Attributes = mergeAttributes(rec.Attributes, req.Attributes)
	if req.Tags != nil {
		rec.Tags = cloneTags(req.Tags)
	}
	attrsJSON, err := marshalAttrs(rec.Attributes)
	if err != nil {
		return store.CertificateRecord{}, err
	}
	tagsJSON, err := marshalTags(rec.Tags)
	if err != nil {
		return store.CertificateRecord{}, err
	}
	q := fmt.Sprintf(
		"UPDATE kv_certificates SET attributes = %s, tags = %s WHERE name = %s AND version = %s",
		s.flavor.ph(1), s.flavor.ph(2), s.flavor.ph(3), s.flavor.ph(4))
	if _, err := s.db.Exec(q, attrsJSON, tagsJSON, rec.Name, rec.Version); err != nil {
		return store.CertificateRecord{}, err
	}
	return rec, nil
}

func (s *SQLStore) GetCertificatePolicy(name string) (*model.CertificatePolicy, error) {
	rec, _, err := s.getCertVersionRow(name, "")
	if err != nil {
		return nil, err
	}
	return clonePolicy(rec.Policy), nil
}

func (s *SQLStore) UpdateCertificatePolicy(name string, policy *model.CertificatePolicy) (*model.CertificatePolicy, error) {
	rec, _, err := s.getCertVersionRow(name, "")
	if err != nil {
		return nil, err
	}
	newPolicy := defaultCertificatePolicy(name, policy)
	policyArg, err := marshalPolicyArg(newPolicy)
	if err != nil {
		return nil, err
	}
	rec.Attributes.Updated = nowUnix()
	attrsJSON, err := marshalAttrs(rec.Attributes)
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf(
		"UPDATE kv_certificates SET policy = %s, attributes = %s WHERE name = %s AND version = %s",
		s.flavor.ph(1), s.flavor.ph(2), s.flavor.ph(3), s.flavor.ph(4))
	if _, err := s.db.Exec(q, policyArg, attrsJSON, rec.Name, rec.Version); err != nil {
		return nil, err
	}
	return newPolicy, nil
}

func (s *SQLStore) GetPendingCertificateOperation(name string) (model.CertificateOperation, error) {
	rec, _, err := s.getCertVersionRow(name, "")
	if err != nil {
		return model.CertificateOperation{}, err
	}
	return model.CertificateOperation{ID: name, Status: "completed", Target: rec.Name}, nil
}

func (s *SQLStore) DeleteCertificate(name string) (store.DeletedCertificateRecord, error) {
	latest, _, err := s.getCertVersionRow(name, "")
	if err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	var count int
	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM kv_deleted_certificates WHERE name = %s", s.flavor.ph(1)), name,
	).Scan(&count); err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	if count > 0 {
		return store.DeletedCertificateRecord{}, store.NewError(http.StatusNotFound, "CertificateNotFound",
			fmt.Sprintf("A certificate with (name/id) %s was not found in this key vault.", name))
	}
	snapshots, err := s.allCertVersionSnapshots(name)
	if err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	payload, err := json.Marshal(deletedCertificatePayload{Versions: snapshots})
	if err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	now := nowUnix()
	recoveryID := newRecoveryID("certificates", name)
	scheduledPurgeDate := now + int64(recoverableDays*24*60*60)
	q := fmt.Sprintf(
		"INSERT INTO kv_deleted_certificates (name, recovery_id, deleted_date, scheduled_purge_date, versions) VALUES (%s)",
		s.phs(1, 5))
	if _, err := s.db.Exec(q, name, recoveryID, now, scheduledPurgeDate, string(payload)); err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	if _, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM kv_certificates WHERE name = %s", s.flavor.ph(1)), name,
	); err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	return store.DeletedCertificateRecord{
		CertificateRecord:  latest,
		RecoveryID:         recoveryID,
		DeletedDate:        now,
		ScheduledPurgeDate: scheduledPurgeDate,
	}, nil
}

func (s *SQLStore) allCertVersionSnapshots(name string) ([]certificateVersionSnapshot, error) {
	q := fmt.Sprintf(
		"SELECT version, cer, kid, sid, pem_data, attributes, tags, policy, created_at FROM kv_certificates WHERE name = %s ORDER BY created_at ASC",
		s.flavor.ph(1))
	rows, err := s.db.Query(q, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []certificateVersionSnapshot
	for rows.Next() {
		var snap certificateVersionSnapshot
		var attrsJSON, tagsJSON, cerB64 string
		var policyNS sql.NullString
		if err := rows.Scan(&snap.Version, &cerB64, &snap.Kid, &snap.Sid, &snap.PEMData, &attrsJSON, &tagsJSON, &policyNS, &snap.CreatedAt); err != nil {
			return nil, err
		}
		snap.Cer = cerB64
		if err := json.Unmarshal([]byte(attrsJSON), &snap.Attributes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(tagsJSON), &snap.Tags); err != nil {
			return nil, err
		}
		snap.Policy, err = unmarshalPolicyNS(policyNS)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snap)
	}
	return snapshots, rows.Err()
}

type deletedCertRow struct {
	Name               string
	RecoveryID         string
	DeletedDate        int64
	ScheduledPurgeDate int64
	Versions           string
}

func (s *SQLStore) getDeletedCertRow(name string) (deletedCertRow, error) {
	var r deletedCertRow
	q := fmt.Sprintf(
		"SELECT name, recovery_id, deleted_date, scheduled_purge_date, versions FROM kv_deleted_certificates WHERE name = %s",
		s.flavor.ph(1))
	err := s.db.QueryRow(q, name).Scan(&r.Name, &r.RecoveryID, &r.DeletedDate, &r.ScheduledPurgeDate, &r.Versions)
	if err == sql.ErrNoRows {
		return deletedCertRow{}, store.NewError(http.StatusNotFound, "CertificateNotFound",
			fmt.Sprintf("A deleted certificate with name %s was not found in this key vault.", name))
	}
	return r, err
}

func deletedCertFromRow(r deletedCertRow) (store.DeletedCertificateRecord, error) {
	var payload deletedCertificatePayload
	if err := json.Unmarshal([]byte(r.Versions), &payload); err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	if len(payload.Versions) == 0 {
		return store.DeletedCertificateRecord{}, fmt.Errorf("deleted certificate %s has no versions", r.Name)
	}
	latest := payload.Versions[len(payload.Versions)-1]
	cer, err := base64.StdEncoding.DecodeString(latest.Cer)
	if err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	return store.DeletedCertificateRecord{
		CertificateRecord: store.CertificateRecord{
			Name:       r.Name,
			Version:    latest.Version,
			Cer:        cer,
			Kid:        latest.Kid,
			Sid:        latest.Sid,
			Attributes: latest.Attributes,
			Tags:       cloneTags(latest.Tags),
			Policy:     clonePolicy(latest.Policy),
		},
		RecoveryID:         r.RecoveryID,
		DeletedDate:        r.DeletedDate,
		ScheduledPurgeDate: r.ScheduledPurgeDate,
	}, nil
}

func (s *SQLStore) ListDeletedCertificates(maxResults int, skipToken string) ([]store.DeletedCertificateRecord, *string, error) {
	rows, err := s.db.Query("SELECT name FROM kv_deleted_certificates ORDER BY name")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	page, next, err := paginateNames(names, skipToken, maxResults)
	if err != nil {
		return nil, nil, err
	}
	items := make([]store.DeletedCertificateRecord, 0, len(page))
	for _, name := range page {
		r, err := s.getDeletedCertRow(name)
		if err != nil {
			return nil, nil, err
		}
		rec, err := deletedCertFromRow(r)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, rec)
	}
	return items, next, nil
}

func (s *SQLStore) GetDeletedCertificate(name string) (store.DeletedCertificateRecord, error) {
	r, err := s.getDeletedCertRow(name)
	if err != nil {
		return store.DeletedCertificateRecord{}, err
	}
	return deletedCertFromRow(r)
}

func (s *SQLStore) PurgeDeletedCertificate(name string) error {
	if _, err := s.getDeletedCertRow(name); err != nil {
		return err
	}
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM kv_deleted_certificates WHERE name = %s", s.flavor.ph(1)), name)
	return err
}

func (s *SQLStore) RecoverDeletedCertificate(name string) (store.CertificateRecord, error) {
	var count int
	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM kv_certificates WHERE name = %s", s.flavor.ph(1)), name,
	).Scan(&count); err != nil {
		return store.CertificateRecord{}, err
	}
	if count > 0 {
		return store.CertificateRecord{}, store.NewError(http.StatusConflict, "Conflict",
			fmt.Sprintf("Certificate %s already exists.", name))
	}
	r, err := s.getDeletedCertRow(name)
	if err != nil {
		return store.CertificateRecord{}, err
	}
	var payload deletedCertificatePayload
	if err := json.Unmarshal([]byte(r.Versions), &payload); err != nil {
		return store.CertificateRecord{}, err
	}
	for i, snap := range payload.Versions {
		cer, err := base64.StdEncoding.DecodeString(snap.Cer)
		if err != nil {
			return store.CertificateRecord{}, err
		}
		rec := store.CertificateRecord{
			Name:       name,
			Version:    snap.Version,
			Cer:        cer,
			Kid:        snap.Kid,
			Sid:        snap.Sid,
			Attributes: snap.Attributes,
			Tags:       cloneTags(snap.Tags),
			Policy:     clonePolicy(snap.Policy),
		}
		if err := s.insertCertRow(rec, []byte(snap.PEMData), snap.CreatedAt+int64(i)); err != nil {
			return store.CertificateRecord{}, err
		}
	}
	if _, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM kv_deleted_certificates WHERE name = %s", s.flavor.ph(1)), name,
	); err != nil {
		return store.CertificateRecord{}, err
	}
	latest := payload.Versions[len(payload.Versions)-1]
	cer, err := base64.StdEncoding.DecodeString(latest.Cer)
	if err != nil {
		return store.CertificateRecord{}, err
	}
	return store.CertificateRecord{
		Name:       name,
		Version:    latest.Version,
		Cer:        cer,
		Kid:        latest.Kid,
		Sid:        latest.Sid,
		Attributes: latest.Attributes,
		Tags:       cloneTags(latest.Tags),
		Policy:     clonePolicy(latest.Policy),
	}, nil
}

func cloneCertRecord(in store.CertificateRecord) store.CertificateRecord {
	return store.CertificateRecord{
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

// Ensure unused imports are referenced.
var _ = sort.Strings
var _ = pkix.Name{}
