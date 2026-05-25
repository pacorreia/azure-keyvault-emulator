package handler_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/server"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

func TestSecretCRUD(t *testing.T) {
	ts := httptest.NewServer(server.NewMux(store.New()))
	defer ts.Close()

	secret := doJSON[model.SecretBundle](t, ts, http.MethodPut, "/secrets/test-secret?api-version=7.4", map[string]any{
		"value":       "super-secret",
		"contentType": "text/plain",
		"attributes":  map[string]any{"enabled": true},
		"tags":        map[string]string{"env": "test"},
	})
	if secret.Value != "super-secret" {
		t.Fatalf("expected secret value, got %q", secret.Value)
	}
	if !strings.HasSuffix(secret.ID, "/secrets/test-secret/"+versionFromID(secret.ID)) {
		t.Fatalf("unexpected secret id %q", secret.ID)
	}

	latest := doJSON[model.SecretBundle](t, ts, http.MethodGet, "/secrets/test-secret?api-version=7.4", nil)
	if latest.Value != "super-secret" {
		t.Fatalf("expected latest secret value, got %q", latest.Value)
	}

	listed := doJSON[model.ListResult[model.SecretItem]](t, ts, http.MethodGet, "/secrets?api-version=7.4&$maxresults=10", nil)
	if len(listed.Value) != 1 {
		t.Fatalf("expected one listed secret, got %d", len(listed.Value))
	}
	if listed.Value[0].ID == "" {
		t.Fatal("expected listed secret id")
	}
}

func TestSecretSoftDeleteAndRecover(t *testing.T) {
	ts := httptest.NewServer(server.NewMux(store.New()))
	defer ts.Close()

	_ = doJSON[model.SecretBundle](t, ts, http.MethodPut, "/secrets/delete-me?api-version=7.4", map[string]any{"value": "value"})
	deleted := doJSON[model.DeletedSecretBundle](t, ts, http.MethodDelete, "/secrets/delete-me?api-version=7.4", nil)
	if deleted.RecoveryID == "" {
		t.Fatal("expected recovery id")
	}
	resp := doRequest(t, ts, http.MethodGet, "/secrets/delete-me?api-version=7.4", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for deleted secret, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	recovered := doJSON[model.SecretBundle](t, ts, http.MethodPost, "/deletedsecrets/delete-me/recover?api-version=7.4", map[string]any{})
	if recovered.Value != "value" {
		t.Fatalf("expected recovered secret value, got %q", recovered.Value)
	}
}

func TestKeyCreateEncryptDecrypt(t *testing.T) {
	ts := httptest.NewServer(server.NewMux(store.New()))
	defer ts.Close()

	created := doJSON[model.KeyBundle](t, ts, http.MethodPost, "/keys/mykey/create?api-version=7.4", map[string]any{
		"kty":     "RSA",
		"key_ops": []string{"encrypt", "decrypt"},
	})
	version := versionFromID(created.Key.Kid)
	plaintext := kvcrypto.EncodeBase64URL([]byte("hello world"))
	encrypted := doJSON[model.CryptoResponse](t, ts, http.MethodPost, "/keys/mykey/"+version+"/encrypt?api-version=7.4", map[string]any{
		"alg":   "RSA-OAEP",
		"value": plaintext,
	})
	if encrypted.Value == "" {
		t.Fatal("expected ciphertext")
	}
	decrypted := doJSON[model.CryptoResponse](t, ts, http.MethodPost, "/keys/mykey/"+version+"/decrypt?api-version=7.4", map[string]any{
		"alg":   "RSA-OAEP",
		"value": encrypted.Value,
	})
	if string(mustDecode(t, decrypted.Value)) != "hello world" {
		t.Fatalf("expected decrypted plaintext, got %q", string(mustDecode(t, decrypted.Value)))
	}
}

func doRequest(t *testing.T, ts *httptest.Server, method, path string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "myvault.vault.azure.net"
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func doJSON[T any](t *testing.T, ts *httptest.Server, method, path string, body any) T {
	t.Helper()
	resp := doRequest(t, ts, method, path, body)
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, string(payload))
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func versionFromID(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := kvcrypto.DecodeBase64URL(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
