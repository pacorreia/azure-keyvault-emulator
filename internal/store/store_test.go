package store

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

func boolPtr(v bool) *bool    { return &v }
func int64Ptr(v int64) *int64 { return &v }

func expectStoreError(t *testing.T, err error, status int, code string) {
	t.Helper()
	kvErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T (%v)", err, err)
	}
	if kvErr.Status != status || kvErr.Code != code {
		t.Fatalf("unexpected error %+v", kvErr)
	}
}

func mustSetSecret(t *testing.T, s *Store, name, value string) SecretRecord {
	t.Helper()
	rec, err := s.SetSecret(name, model.SecretSetRequest{Value: value})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func mustCreateKey(t *testing.T, s *Store, name, kty string) KeyRecord {
	t.Helper()
	rec, err := s.CreateKey(name, model.CreateKeyRequest{Kty: kty, KeySize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func mustCreateCertificate(t *testing.T, s *Store, name string) CertificateRecord {
	t.Helper()
	rec, err := s.CreateCertificate(name, model.CreateCertificateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestStoreUtilities(t *testing.T) {
	t.Run("paginateNames", func(t *testing.T) {
		items := []string{"a", "b", "c", "d", "e"}
		page, next, err := paginateNames([]string{}, "", 2)
		if err != nil || len(page) != 0 || next != nil {
			t.Fatalf("unexpected empty page %v %v %v", page, next, err)
		}
		page, next, err = paginateNames(items, "", 2)
		if err != nil || len(page) != 2 || *next != "2" {
			t.Fatalf("unexpected first page %v %v %v", page, next, err)
		}
		page, next, err = paginateNames(items, "2", 2)
		if err != nil || len(page) != 2 || *next != "4" || page[0] != "c" {
			t.Fatalf("unexpected middle page %v %v %v", page, next, err)
		}
		page, next, err = paginateNames(items, "4", 2)
		if err != nil || len(page) != 1 || next != nil || page[0] != "e" {
			t.Fatalf("unexpected last page %v %v %v", page, next, err)
		}
		if _, _, err := paginateNames(items, "bad", 2); err == nil {
			t.Fatal("expected invalid skiptoken error")
		}
	})

	t.Run("buildAttributes", func(t *testing.T) {
		attrs := buildAttributes(nil, 1, 2)
		if attrs.Created != 1 || attrs.Updated != 2 || attrs.RecoveryLevel == "" || attrs.RecoverableDays == 0 {
			t.Fatalf("unexpected attrs %+v", attrs)
		}
		input := &model.Attributes{Enabled: boolPtr(true), NotBefore: int64Ptr(10), Expires: int64Ptr(20)}
		attrs = buildAttributes(input, 3, 4)
		if attrs.Enabled == nil || !*attrs.Enabled || *attrs.NotBefore != 10 || *attrs.Expires != 20 {
			t.Fatalf("unexpected attrs %+v", attrs)
		}
	})

	t.Run("mergeAttributes", func(t *testing.T) {
		current := model.Attributes{Enabled: boolPtr(true), NotBefore: int64Ptr(10), Expires: int64Ptr(20), Created: 1, Updated: 1}
		patch := &model.Attributes{Enabled: boolPtr(false), Expires: int64Ptr(30)}
		merged := mergeAttributes(current, patch)
		if merged.Enabled == nil || *merged.Enabled || merged.NotBefore == nil || *merged.NotBefore != 10 || *merged.Expires != 30 || merged.Updated == 0 {
			t.Fatalf("unexpected merged attrs %+v", merged)
		}
	})

	t.Run("cloneAttributes", func(t *testing.T) {
		in := model.Attributes{Enabled: boolPtr(true), NotBefore: int64Ptr(1), Expires: int64Ptr(2)}
		out := cloneAttributes(in)
		*out.Enabled = false
		*out.NotBefore = 10
		if *in.Enabled == false || *in.NotBefore == 10 {
			t.Fatal("expected deep copy")
		}
	})

	t.Run("cloneTags", func(t *testing.T) {
		if tags := cloneTags(nil); tags != nil {
			t.Fatalf("unexpected tags %#v", tags)
		}
		in := map[string]string{"a": "b"}
		out := cloneTags(in)
		out["a"] = "c"
		if in["a"] != "b" {
			t.Fatal("expected deep copy")
		}
	})

	t.Run("newVersion", func(t *testing.T) {
		v := newVersion()
		if len(v) != 32 {
			t.Fatalf("unexpected version %q", v)
		}
		if _, err := hex.DecodeString(v); err != nil {
			t.Fatal(err)
		}
		oldRead := storeRandRead
		storeRandRead = func([]byte) (int, error) { return 0, errors.New("boom") }
		defer func() { storeRandRead = oldRead }()
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		_ = newVersion()
	})

	t.Run("newRecoveryID", func(t *testing.T) {
		id := newRecoveryID("keys", "name")
		if !strings.HasPrefix(id, "/deletedkeys/name/") {
			t.Fatalf("unexpected recovery id %q", id)
		}
	})

	t.Run("error", func(t *testing.T) {
		var err error = &Error{Status: 400, Code: "BadParameter", Message: "bad"}
		if err.Error() != "bad" {
			t.Fatalf("unexpected message %q", err.Error())
		}
		if err := NewError(401, "Unauthorized", "nope"); err == nil {
			t.Fatal("expected NewError")
		}
	})

	t.Run("latestHelpers", func(t *testing.T) {
		if latestSecret(nil) != nil || latestKey(nil) != nil || latestCertificate(nil) != nil {
			t.Fatal("expected nil latest helpers")
		}
		secret := &secretEntry{versions: []*secretVersion{{record: SecretRecord{Version: "v1"}}}}
		key := &keyEntry{versions: []*keyVersion{{record: KeyRecord{Version: "v1"}}}}
		cert := &certificateEntry{versions: []*certificateVersion{{record: CertificateRecord{Version: "v1"}}}}
		if latestSecret(secret).record.Version != "v1" || latestKey(key).record.Version != "v1" || latestCertificate(cert).record.Version != "v1" {
			t.Fatal("unexpected latest helper value")
		}
	})
}
