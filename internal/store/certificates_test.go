package store

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

func importedCertificateValue(t *testing.T) string {
	t.Helper()
	priv, der, err := kvcrypto.GenerateSelfSignedCert("imported", nil)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return string(append(certPEM, keyPEM...))
}

func TestCertificateLifecycle(t *testing.T) {
	t.Run("CreateCertificate", func(t *testing.T) {
		s := New()
		rec, err := s.CreateCertificate("cert", model.CreateCertificateRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if rec.Name != "cert" || len(rec.Cer) == 0 || rec.Policy == nil {
			t.Fatalf("unexpected certificate %+v", rec)
		}
		if _, err := s.GetKey("cert", rec.Version); err != nil {
			t.Fatal(err)
		}
		if secret, err := s.GetSecret("cert", rec.Version); err != nil || secret.Value == "" {
			t.Fatalf("expected managed secret %v %v", secret, err)
		}
		_, _ = s.DeleteCertificate("cert")
		if _, err := s.CreateCertificate("cert", model.CreateCertificateRequest{}); err == nil {
			t.Fatal("expected deleted conflict")
		}
	})

	t.Run("ImportCertificate", func(t *testing.T) {
		s := New()
		rec, err := s.ImportCertificate("imported", model.ImportCertificateRequest{Value: importedCertificateValue(t)})
		if err != nil || len(rec.Cer) == 0 {
			t.Fatalf("unexpected import %+v %v", rec, err)
		}
		if _, err := s.GetSecret("imported", rec.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ImportCertificate("imported2", model.ImportCertificateRequest{}); err == nil {
			t.Fatal("expected empty value error")
		}
	})

	t.Run("GetAndList", func(t *testing.T) {
		s := New()
		first := mustCreateCertificate(t, s, "name")
		second, err := s.ImportCertificate("name", model.ImportCertificateRequest{Value: importedCertificateValue(t)})
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.GetCertificate("name", "")
		if err != nil || got.Version != second.Version {
			t.Fatalf("unexpected latest %+v %v", got, err)
		}
		got, err = s.GetCertificate("name", first.Version)
		if err != nil || got.Version != first.Version {
			t.Fatalf("unexpected version %+v %v", got, err)
		}
		if _, err := s.GetCertificate("missing", ""); err == nil {
			t.Fatal("expected not found")
		}
		list, next, err := s.ListCertificates(10, "")
		if err != nil || len(list) != 1 || next != nil {
			t.Fatalf("unexpected list %v %v %v", list, next, err)
		}
		mustCreateCertificate(t, s, "a")
		mustCreateCertificate(t, s, "z")
		page, next, err := s.ListCertificates(2, "")
		if err != nil || len(page) != 2 || next == nil {
			t.Fatalf("unexpected page %v %v %v", page, next, err)
		}
		versions, next, err := s.ListCertificateVersions("name", 10, "")
		if err != nil || len(versions) != 2 || next != nil {
			t.Fatalf("unexpected version list %v %v %v", versions, next, err)
		}
		if _, _, err := s.ListCertificateVersions("missing", 10, ""); err == nil {
			t.Fatal("expected version not found")
		}
	})

	t.Run("UpdateCertificate", func(t *testing.T) {
		s := New()
		rec := mustCreateCertificate(t, s, "name")
		updated, err := s.UpdateCertificate("name", rec.Version, model.UpdateCertificateRequest{Tags: map[string]string{"env": "test"}, Attributes: &model.Attributes{Enabled: boolPtr(false)}})
		if err != nil {
			t.Fatal(err)
		}
		if updated.Tags["env"] != "test" || updated.Attributes.Enabled == nil || *updated.Attributes.Enabled {
			t.Fatalf("unexpected update %+v", updated)
		}
		if _, err := s.UpdateCertificate("name", "missing", model.UpdateCertificateRequest{}); err == nil {
			t.Fatal("expected update not found")
		}
	})

	t.Run("PolicyAndPending", func(t *testing.T) {
		s := New()
		mustCreateCertificate(t, s, "name")
		policy, err := s.GetCertificatePolicy("name")
		if err != nil || policy == nil {
			t.Fatalf("unexpected policy %+v %v", policy, err)
		}
		if _, err := s.GetCertificatePolicy("missing"); err == nil {
			t.Fatal("expected policy not found")
		}
		policy, err = s.UpdateCertificatePolicy("name", &model.CertificatePolicy{X509Props: map[string]any{"subject": "CN=updated"}})
		if err != nil || policy.X509Props["subject"] != "CN=updated" {
			t.Fatalf("unexpected policy update %+v %v", policy, err)
		}
		if _, err := s.UpdateCertificatePolicy("missing", &model.CertificatePolicy{}); err == nil {
			t.Fatal("expected update policy not found")
		}
		op, err := s.GetPendingCertificateOperation("name")
		if err != nil || op.Status != "completed" {
			t.Fatalf("unexpected pending op %+v %v", op, err)
		}
		if _, err := s.GetPendingCertificateOperation("missing"); err == nil {
			t.Fatal("expected pending op not found")
		}
		defaults := defaultCertificatePolicy("name", nil)
		if defaults.Issuer["name"] != "Self" || defaults.KeyProps["kty"] != "RSA" || defaults.SecretProps["contentType"] != "application/x-pkcs12" {
			t.Fatalf("unexpected defaults %+v", defaults)
		}
		cloned := clonePolicy(defaults)
		cloned.X509Props["subject"] = "CN=changed"
		if defaults.X509Props["subject"] == "CN=changed" {
			t.Fatal("expected deep cloned policy")
		}
	})

	t.Run("DeleteAndRecover", func(t *testing.T) {
		s := New()
		mustCreateCertificate(t, s, "name")
		deleted, err := s.DeleteCertificate("name")
		if err != nil || deleted.RecoveryID == "" {
			t.Fatalf("unexpected delete %+v %v", deleted, err)
		}
		if _, err := s.DeleteCertificate("missing"); err == nil {
			t.Fatal("expected delete not found")
		}
		got, err := s.GetDeletedCertificate("name")
		if err != nil || got.Name != "name" {
			t.Fatalf("unexpected deleted get %+v %v", got, err)
		}
		if _, err := s.GetDeletedCertificate("missing"); err == nil {
			t.Fatal("expected deleted get not found")
		}
		mustCreateCertificate(t, s, "other")
		_, _ = s.DeleteCertificate("other")
		list, _, err := s.ListDeletedCertificates(10, "")
		if err != nil || len(list) != 2 {
			t.Fatalf("unexpected deleted list %v %v", list, err)
		}
		recovered, err := s.RecoverDeletedCertificate("name")
		if err != nil || recovered.Name != "name" {
			t.Fatalf("unexpected recover %+v %v", recovered, err)
		}
		if _, err := s.RecoverDeletedCertificate("missing"); err == nil {
			t.Fatal("expected recover not found")
		}
		s.deletedCertificates["name"] = &deletedCertificateEntry{entry: &certificateEntry{versions: []*certificateVersion{{record: recovered}}}}
		if _, err := s.RecoverDeletedCertificate("name"); err == nil {
			t.Fatal("expected recover conflict")
		}
		if err := s.PurgeDeletedCertificate("name"); err != nil {
			t.Fatal(err)
		}
		if err := s.PurgeDeletedCertificate("name"); err == nil {
			t.Fatal("expected purge not found")
		}
	})
}
