package store

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

func TestSecretLifecycle(t *testing.T) {
	s := New()
	t.Run("SetSecret", func(t *testing.T) {
		if _, err := s.SetSecret("", model.SecretSetRequest{Value: "v"}); err == nil {
			t.Fatal("expected empty name error")
		}
		if _, err := s.SetSecret("name", model.SecretSetRequest{}); err == nil {
			t.Fatal("expected empty value error")
		}
		rec1, err := s.SetSecret("name", model.SecretSetRequest{Value: "v1", ContentType: "text/plain", Tags: map[string]string{"a": "b"}})
		if err != nil {
			t.Fatal(err)
		}
		rec2, err := s.SetSecret("name", model.SecretSetRequest{Value: "v2"})
		if err != nil {
			t.Fatal(err)
		}
		if rec1.Version == rec2.Version {
			t.Fatal("expected new version")
		}
		if _, err := s.DeleteSecret("name"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetSecret("name", model.SecretSetRequest{Value: "v3"}); err == nil {
			t.Fatal("expected deleted conflict")
		}
	})

	t.Run("GetSecret", func(t *testing.T) {
		s := New()
		rec1 := mustSetSecret(t, s, "name", "v1")
		rec2 := mustSetSecret(t, s, "name", "v2")
		got, err := s.GetSecret("name", "")
		if err != nil || got.Value != "v2" {
			t.Fatalf("unexpected latest %v %v", got, err)
		}
		got, err = s.GetSecret("name", rec1.Version)
		if err != nil || got.Value != "v1" {
			t.Fatalf("unexpected version %v %v", got, err)
		}
		if _, err := s.GetSecret("missing", ""); err == nil {
			t.Fatal("expected not found")
		}
		if _, err := s.GetSecret("name", "missing"); err == nil {
			t.Fatal("expected version not found")
		}
		_, _ = s.DeleteSecret("name")
		if _, err := s.GetSecret("name", rec2.Version); err == nil {
			t.Fatal("expected deleted not found")
		}
	})

	t.Run("ListSecrets", func(t *testing.T) {
		s := New()
		list, next, err := s.ListSecrets(10, "")
		if err != nil || len(list) != 0 || next != nil {
			t.Fatalf("unexpected empty list %v %v %v", list, next, err)
		}
		mustSetSecret(t, s, "a", "1")
		one, next, err := s.ListSecrets(10, "")
		if err != nil || len(one) != 1 || one[0].Value != "" {
			t.Fatalf("unexpected single list %v %v %v", one, next, err)
		}
		mustSetSecret(t, s, "b", "2")
		mustSetSecret(t, s, "c", "3")
		page, next, err := s.ListSecrets(2, "")
		if err != nil || len(page) != 2 || next == nil {
			t.Fatalf("unexpected first page %v %v %v", page, next, err)
		}
		page, next, err = s.ListSecrets(2, *next)
		if err != nil || len(page) != 1 || next != nil {
			t.Fatalf("unexpected second page %v %v %v", page, next, err)
		}
	})

	t.Run("ListSecretVersions", func(t *testing.T) {
		s := New()
		mustSetSecret(t, s, "name", "v1")
		mustSetSecret(t, s, "name", "v2")
		versions, next, err := s.ListSecretVersions("name", 10, "")
		if err != nil || len(versions) != 2 || next != nil || versions[0].Value != "" {
			t.Fatalf("unexpected versions %v %v %v", versions, next, err)
		}
		if _, _, err := s.ListSecretVersions("missing", 10, ""); err == nil {
			t.Fatal("expected not found")
		}
	})

	t.Run("UpdateSecret", func(t *testing.T) {
		s := New()
		rec := mustSetSecret(t, s, "name", "value")
		contentType := "application/json"
		updated, err := s.UpdateSecret("name", rec.Version, model.SecretUpdateRequest{
			ContentType: &contentType,
			Tags:        map[string]string{"k": "v"},
			Attributes:  &model.Attributes{Enabled: boolPtr(false)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if updated.ContentType != contentType || updated.Tags["k"] != "v" || updated.Attributes.Enabled == nil || *updated.Attributes.Enabled {
			t.Fatalf("unexpected updated secret %+v", updated)
		}
		if _, err := s.UpdateSecret("name", "missing", model.SecretUpdateRequest{}); err == nil {
			t.Fatal("expected not found")
		}
	})

	t.Run("DeleteAndDeletedViews", func(t *testing.T) {
		s := New()
		mustSetSecret(t, s, "one", "1")
		mustSetSecret(t, s, "two", "2")
		deleted, err := s.DeleteSecret("one")
		if err != nil || deleted.RecoveryID == "" {
			t.Fatalf("unexpected delete %v %v", deleted, err)
		}
		if _, err := s.DeleteSecret("missing"); err == nil {
			t.Fatal("expected delete not found")
		}
		got, err := s.GetDeletedSecret("one")
		if err != nil || got.Name != "one" {
			t.Fatalf("unexpected deleted get %v %v", got, err)
		}
		if _, err := s.GetDeletedSecret("missing"); err == nil {
			t.Fatal("expected deleted not found")
		}
		list, next, err := s.ListDeletedSecrets(10, "")
		if err != nil || len(list) != 1 || next != nil {
			t.Fatalf("unexpected deleted list %v %v %v", list, next, err)
		}
		_, _ = s.DeleteSecret("two")
		list, next, err = s.ListDeletedSecrets(1, "")
		if err != nil || len(list) != 1 || next == nil {
			t.Fatalf("unexpected deleted page %v %v %v", list, next, err)
		}
	})

	t.Run("PurgeDeletedSecret", func(t *testing.T) {
		s := New()
		mustSetSecret(t, s, "name", "value")
		_, _ = s.DeleteSecret("name")
		if err := s.PurgeDeletedSecret("name"); err != nil {
			t.Fatal(err)
		}
		if err := s.PurgeDeletedSecret("name"); err == nil {
			t.Fatal("expected not found")
		}
	})

	t.Run("RecoverDeletedSecret", func(t *testing.T) {
		s := New()
		mustSetSecret(t, s, "name", "value")
		_, _ = s.DeleteSecret("name")
		recovered, err := s.RecoverDeletedSecret("name")
		if err != nil || recovered.Value != "value" {
			t.Fatalf("unexpected recover %v %v", recovered, err)
		}
		if _, err := s.RecoverDeletedSecret("missing"); err == nil {
			t.Fatal("expected not found")
		}
		mustSetSecret(t, s, "other", "value")
		s.deletedSecrets["other"] = &deletedSecretEntry{entry: &secretEntry{versions: []*secretVersion{{record: SecretRecord{Name: "other", Value: "old"}}}}}
		if _, err := s.RecoverDeletedSecret("other"); err == nil {
			t.Fatal("expected conflict")
		}
	})

	t.Run("BackupRestore", func(t *testing.T) {
		s := New()
		mustSetSecret(t, s, "name", "v1")
		mustSetSecret(t, s, "name", "v2")
		backup, err := s.BackupSecret("name")
		if err != nil {
			t.Fatal(err)
		}
		data, err := base64.StdEncoding.DecodeString(backup)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["name"] != "name" {
			t.Fatalf("unexpected payload %+v", payload)
		}
		if _, err := s.BackupSecret("missing"); err == nil {
			t.Fatal("expected not found")
		}
		restored, err := New().RestoreSecret(backup)
		if err != nil || restored.Name != "name" || restored.Value != "v2" {
			t.Fatalf("unexpected restore %v %v", restored, err)
		}
		if _, err := New().RestoreSecret("***"); err == nil {
			t.Fatal("expected invalid base64")
		}
		if _, err := New().RestoreSecret(base64.StdEncoding.EncodeToString([]byte("{"))); err == nil {
			t.Fatal("expected invalid json")
		}
		badPayload, _ := json.Marshal(map[string]any{"name": "", "versions": []any{}})
		if _, err := New().RestoreSecret(base64.StdEncoding.EncodeToString(badPayload)); err == nil {
			t.Fatal("expected empty name error")
		}
	})
}
