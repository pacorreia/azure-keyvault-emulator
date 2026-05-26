package sqlstore_test

import (
	"strings"
	"testing"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store/sqlstore"
)

func newTestStore(t *testing.T) store.Storer {
	t.Helper()
	db, err := sqlstore.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	s, err := sqlstore.NewSQLStore(db, sqlstore.FlavorSQLite)
	if err != nil {
		t.Fatalf("sqlstore.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return s
}

// ===== SECRETS =====

func TestSQLStore_SecretSetGet(t *testing.T) {
	s := newTestStore(t)

	rec, err := s.SetSecret("mysecret", model.SecretSetRequest{Value: "hello", ContentType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "mysecret" || rec.Value != "hello" {
		t.Fatalf("unexpected record: %+v", rec)
	}

	got, err := s.GetSecret("mysecret", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "hello" {
		t.Fatalf("expected hello, got %q", got.Value)
	}
}

func TestSQLStore_SecretNilTags(t *testing.T) {
	s := newTestStore(t)

	rec, err := s.SetSecret("t1", model.SecretSetRequest{Value: "v", Tags: nil})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSecret("t1", rec.Version)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tags != nil {
		t.Fatalf("expected nil tags, got %v", got.Tags)
	}
}

func TestSQLStore_SecretVersions(t *testing.T) {
	s := newTestStore(t)

	r1, _ := s.SetSecret("sec", model.SecretSetRequest{Value: "v1"})
	r2, _ := s.SetSecret("sec", model.SecretSetRequest{Value: "v2"})

	if r1.Version == r2.Version {
		t.Fatal("versions must differ")
	}

	got1, err := s.GetSecret("sec", r1.Version)
	if err != nil || got1.Value != "v1" {
		t.Fatalf("v1 mismatch: %v %v", got1, err)
	}
	got2, err := s.GetSecret("sec", "")
	if err != nil || got2.Value != "v2" {
		t.Fatalf("latest mismatch: %v %v", got2, err)
	}
}

func TestSQLStore_SecretDeleteRecover(t *testing.T) {
	s := newTestStore(t)

	s.SetSecret("del", model.SecretSetRequest{Value: "x"})

	deleted, err := s.DeleteSecret("del")
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Name != "del" {
		t.Fatalf("unexpected deleted name: %v", deleted.Name)
	}

	// Should not be accessible as active
	if _, err := s.GetSecret("del", ""); err == nil {
		t.Fatal("expected not-found after delete")
	}

	// Recover
	rec, err := s.RecoverDeletedSecret("del")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Value != "x" {
		t.Fatalf("recovered value mismatch: %v", rec.Value)
	}
}

func TestSQLStore_SecretPurge(t *testing.T) {
	s := newTestStore(t)

	s.SetSecret("purge", model.SecretSetRequest{Value: "y"})
	s.DeleteSecret("purge")

	if err := s.PurgeDeletedSecret("purge"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDeletedSecret("purge"); err == nil {
		t.Fatal("expected not-found after purge")
	}
}

func TestSQLStore_SecretBackupRestore(t *testing.T) {
	s := newTestStore(t)

	s.SetSecret("bk", model.SecretSetRequest{Value: "backup-val", Tags: map[string]string{"k": "v"}})

	token, err := s.BackupSecret("bk")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("empty backup token")
	}

	// Restore into a fresh store
	s2 := newTestStore(t)
	rec, err := s2.RestoreSecret(token)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Value != "backup-val" {
		t.Fatalf("restore value mismatch: %q", rec.Value)
	}
	if rec.Tags["k"] != "v" {
		t.Fatalf("restore tags mismatch: %v", rec.Tags)
	}
}

func TestSQLStore_ListSecrets(t *testing.T) {
	s := newTestStore(t)

	for _, name := range []string{"a", "b", "c"} {
		s.SetSecret(name, model.SecretSetRequest{Value: "val"})
	}

	page, next, err := s.ListSecrets(2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("expected 2 results, got %d", len(page))
	}
	if next == nil {
		t.Fatal("expected next token")
	}

	page2, next2, err := s.ListSecrets(2, *next)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 1 {
		t.Fatalf("expected 1 result, got %d", len(page2))
	}
	if next2 != nil {
		t.Fatal("expected no next token")
	}
}

func TestSQLStore_UpdateSecret(t *testing.T) {
	s := newTestStore(t)

	r, _ := s.SetSecret("upd", model.SecretSetRequest{Value: "orig", Tags: map[string]string{"old": "tag"}})

	newTags := map[string]string{"new": "tag"}
	updated, err := s.UpdateSecret("upd", r.Version, model.SecretUpdateRequest{Tags: newTags})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Tags["new"] != "tag" {
		t.Fatalf("tag not updated: %v", updated.Tags)
	}
}

// ===== KEYS =====

func TestSQLStore_KeyCreateGet(t *testing.T) {
	s := newTestStore(t)

	rec, err := s.CreateKey("mykey", model.CreateKeyRequest{Kty: "RSA", KeySize: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "mykey" {
		t.Fatalf("unexpected name: %v", rec.Name)
	}

	got, err := s.GetKey("mykey", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != rec.Version {
		t.Fatalf("version mismatch: %v vs %v", got.Version, rec.Version)
	}
}

func TestSQLStore_KeyDeleteRecover(t *testing.T) {
	s := newTestStore(t)

	s.CreateKey("kd", model.CreateKeyRequest{Kty: "RSA", KeySize: 2048})

	deleted, err := s.DeleteKey("kd")
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Name != "kd" {
		t.Fatalf("wrong name: %v", deleted.Name)
	}

	if _, err := s.GetKey("kd", ""); err == nil {
		t.Fatal("expected not-found")
	}

	rec, err := s.RecoverDeletedKey("kd")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "kd" {
		t.Fatalf("recovered name: %v", rec.Name)
	}
}

func TestSQLStore_KeyEncryptDecrypt(t *testing.T) {
	s := newTestStore(t)

	s.CreateKey("enckey", model.CreateKeyRequest{Kty: "RSA", KeySize: 2048})

	// base64 RawURL (no padding) encoding of "hello"
	plaintext := "aGVsbG8"
	ct, _, err := s.Encrypt("enckey", "", model.EncryptRequest{Alg: "RSA-OAEP", Value: plaintext})
	if err != nil {
		t.Fatal(err)
	}

	pt, _, err := s.Decrypt("enckey", "", model.EncryptRequest{Alg: "RSA-OAEP", Value: ct})
	if err != nil {
		t.Fatal(err)
	}
	if pt != plaintext {
		t.Fatalf("decrypt mismatch: got %q want %q", pt, plaintext)
	}
}

func TestSQLStore_KeySignVerify(t *testing.T) {
	s := newTestStore(t)

	s.CreateKey("sigkey", model.CreateKeyRequest{Kty: "RSA", KeySize: 2048})

	digest := "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" // SHA256 of empty string, base64 RawURL
	sig, err := s.Sign("sigkey", "", model.SignRequest{Alg: "RS256", Value: digest})
	if err != nil {
		t.Fatal(err)
	}
	if sig == "" {
		t.Fatal("empty signature")
	}

	ok, err := s.Verify("sigkey", "", model.VerifyRequest{Alg: "RS256", Digest: digest, Value: sig})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature verification failed")
	}
}

func TestSQLStore_KeyNilTags(t *testing.T) {
	s := newTestStore(t)

	rec, err := s.CreateKey("ntk", model.CreateKeyRequest{Kty: "RSA", KeySize: 2048})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetKey("ntk", rec.Version)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tags != nil {
		t.Fatalf("expected nil tags, got %v", got.Tags)
	}
}

// ===== CERTIFICATES =====

func TestSQLStore_CertificateCreateGet(t *testing.T) {
	s := newTestStore(t)

	rec, err := s.CreateCertificate("mycert", model.CreateCertificateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "mycert" {
		t.Fatalf("unexpected name: %v", rec.Name)
	}

	got, err := s.GetCertificate("mycert", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != rec.Version {
		t.Fatalf("version mismatch: %v vs %v", got.Version, rec.Version)
	}
}

func TestSQLStore_CertificateCoCreation(t *testing.T) {
	s := newTestStore(t)

	certRec, err := s.CreateCertificate("cocert", model.CreateCertificateRequest{})
	if err != nil {
		t.Fatal(err)
	}

	// The associated key should exist with the same name
	keyRec, err := s.GetKey("cocert", "")
	if err != nil {
		t.Fatalf("associated key not created: %v", err)
	}
	if keyRec.Version != certRec.Version {
		t.Fatalf("key version %q != cert version %q", keyRec.Version, certRec.Version)
	}

	// The associated secret should exist with the same name
	secRec, err := s.GetSecret("cocert", "")
	if err != nil {
		t.Fatalf("associated secret not created: %v", err)
	}
	if secRec.Version != certRec.Version {
		t.Fatalf("secret version %q != cert version %q", secRec.Version, certRec.Version)
	}
	if !strings.HasPrefix(secRec.ContentType, "application/") {
		t.Fatalf("unexpected content type: %q", secRec.ContentType)
	}
}

func TestSQLStore_CertificateDeleteRecover(t *testing.T) {
	s := newTestStore(t)

	s.CreateCertificate("dc", model.CreateCertificateRequest{})

	deleted, err := s.DeleteCertificate("dc")
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Name != "dc" {
		t.Fatalf("wrong deleted name: %v", deleted.Name)
	}

	if _, err := s.GetCertificate("dc", ""); err == nil {
		t.Fatal("expected not-found after delete")
	}

	rec, err := s.RecoverDeletedCertificate("dc")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "dc" {
		t.Fatalf("recovered name: %v", rec.Name)
	}
}

func TestSQLStore_CertificatePolicyRoundtrip(t *testing.T) {
	s := newTestStore(t)

	policy := &model.CertificatePolicy{
		Issuer: map[string]any{"name": "self"},
	}
	s.CreateCertificate("polcert", model.CreateCertificateRequest{Policy: policy})

	got, err := s.GetCertificatePolicy("polcert")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected non-nil policy")
	}
	if got.Issuer["name"] != "self" {
		t.Fatalf("policy issuer mismatch: %v", got.Issuer)
	}

	updated := &model.CertificatePolicy{
		Issuer: map[string]any{"name": "updated"},
	}
	got2, err := s.UpdateCertificatePolicy("polcert", updated)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Issuer["name"] != "updated" {
		t.Fatalf("updated policy mismatch: %v", got2.Issuer)
	}
}

func TestSQLStore_ListDeletedSecrets(t *testing.T) {
	s := newTestStore(t)

	s.SetSecret("ds1", model.SecretSetRequest{Value: "v1"})
	s.SetSecret("ds2", model.SecretSetRequest{Value: "v2"})
	s.DeleteSecret("ds1")
	s.DeleteSecret("ds2")

	list, _, err := s.ListDeletedSecrets(10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 deleted secrets, got %d", len(list))
	}
}

func TestSQLStore_ListDeletedKeys(t *testing.T) {
	s := newTestStore(t)

	s.CreateKey("dk1", model.CreateKeyRequest{Kty: "RSA", KeySize: 2048})
	s.CreateKey("dk2", model.CreateKeyRequest{Kty: "RSA", KeySize: 2048})
	s.DeleteKey("dk1")
	s.DeleteKey("dk2")

	list, _, err := s.ListDeletedKeys(10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 deleted keys, got %d", len(list))
	}
}
