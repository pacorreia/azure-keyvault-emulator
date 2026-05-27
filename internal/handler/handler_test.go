package handler_test

import (
	"bytes"
	"encoding/base64"
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

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(server.NewMux(store.New()))
}

func doRequest(t *testing.T, ts *httptest.Server, method, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		switch v := body.(type) {
		case json.RawMessage:
			reader = bytes.NewReader(v)
		case []byte:
			reader = bytes.NewReader(v)
		case string:
			reader = strings.NewReader(v)
		default:
			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(payload)
		}
	}
	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "myvault.vault.azure.net"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func doJSON[T any](t *testing.T, ts *httptest.Server, method, path string, body any) T {
	t.Helper()
	return doJSONHeaders[T](t, ts, method, path, body, nil)
}

func doJSONHeaders[T any](t *testing.T, ts *httptest.Server, method, path string, body any, headers map[string]string) T {
	t.Helper()
	resp := doRequest(t, ts, method, path, body, headers)
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

func expectStatus(t *testing.T, resp *http.Response, status int) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("expected %d got %d body=%s", status, resp.StatusCode, string(body))
	}
	return body
}

func versionFromID(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
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

func TestGeneralRoutesAndPagination(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	resp := doRequest(t, ts, http.MethodGet, "/", nil, nil)
	body := expectStatus(t, resp, http.StatusNotFound)
	if !strings.Contains(string(body), "NotFound") {
		t.Fatalf("unexpected body %s", string(body))
	}

	health := doJSON[map[string]string](t, ts, http.MethodGet, "/healthz", nil)
	if health["status"] != "ok" {
		t.Fatalf("unexpected health response %+v", health)
	}

	_ = doJSON[model.SecretBundle](t, ts, http.MethodPut, "/secrets/a?api-version=7.4", map[string]any{"value": "1"})
	_ = doJSON[model.SecretBundle](t, ts, http.MethodPut, "/secrets/b?api-version=7.4", map[string]any{"value": "2"})
	list := doJSONHeaders[model.ListResult[model.SecretItem]](t, ts, http.MethodGet, "/secrets?api-version=7.4&$maxresults=1", nil, map[string]string{"X-Forwarded-Proto": "https"})
	if len(list.Value) != 1 || list.NextLink == nil || !strings.HasPrefix(*list.NextLink, "https://myvault.vault.azure.net/secrets?") {
		t.Fatalf("unexpected list %+v", list)
	}
	resp = doRequest(t, ts, http.MethodGet, "/secrets?$maxresults=bad", nil, nil)
	body = expectStatus(t, resp, http.StatusBadRequest)
	if !strings.Contains(string(body), "$maxresults") {
		t.Fatalf("unexpected body %s", string(body))
	}
}

func TestSecretHandlers(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	secret := doJSON[model.SecretBundle](t, ts, http.MethodPut, "/secrets/test-secret?api-version=7.4", map[string]any{
		"value":       "super-secret",
		"contentType": "text/plain",
		"attributes":  map[string]any{"enabled": true},
		"tags":        map[string]string{"env": "test"},
	})
	version := versionFromID(secret.ID)
	if secret.Value != "super-secret" || secret.Attributes.Enabled == nil || !*secret.Attributes.Enabled {
		t.Fatalf("unexpected secret %+v", secret)
	}

	resp := doRequest(t, ts, http.MethodPut, "/secrets/bad?api-version=7.4", json.RawMessage(`{"value":`), nil)
	expectStatus(t, resp, http.StatusBadRequest)

	latest := doJSON[model.SecretBundle](t, ts, http.MethodGet, "/secrets/test-secret?api-version=7.4", nil)
	if latest.Value != "super-secret" {
		t.Fatalf("unexpected latest %+v", latest)
	}
	resp = doRequest(t, ts, http.MethodGet, "/secrets/missing?api-version=7.4", nil, nil)
	expectStatus(t, resp, http.StatusNotFound)

	versioned := doJSON[model.SecretBundle](t, ts, http.MethodGet, "/secrets/test-secret/"+version+"?api-version=7.4", nil)
	if versioned.ID != secret.ID {
		t.Fatalf("unexpected versioned secret %+v", versioned)
	}
	resp = doRequest(t, ts, http.MethodGet, "/secrets/test-secret/missing?api-version=7.4", nil, nil)
	expectStatus(t, resp, http.StatusNotFound)

	versions := doJSON[model.ListResult[model.SecretItem]](t, ts, http.MethodGet, "/secrets/test-secret/versions?api-version=7.4", nil)
	if len(versions.Value) != 1 {
		t.Fatalf("unexpected versions %+v", versions)
	}
	resp = doRequest(t, ts, http.MethodGet, "/secrets/missing/versions?api-version=7.4", nil, nil)
	expectStatus(t, resp, http.StatusNotFound)

	updated := doJSON[model.SecretBundle](t, ts, http.MethodPatch, "/secrets/test-secret/"+version+"?api-version=7.4", map[string]any{"attributes": map[string]any{"enabled": false}})
	if updated.Attributes.Enabled == nil || *updated.Attributes.Enabled {
		t.Fatalf("unexpected update %+v", updated)
	}

	backup := doJSON[map[string]string](t, ts, http.MethodPost, "/secrets/test-secret/backup?api-version=7.4", map[string]any{})
	if backup["value"] == "" {
		t.Fatal("expected backup token")
	}
	resp = doRequest(t, ts, http.MethodPost, "/secrets/missing/backup?api-version=7.4", map[string]any{}, nil)
	expectStatus(t, resp, http.StatusNotFound)

	deleted := doJSON[model.DeletedSecretBundle](t, ts, http.MethodDelete, "/secrets/test-secret?api-version=7.4", nil)
	if deleted.RecoveryID == "" {
		t.Fatal("expected recovery id")
	}
	deletedList := doJSON[model.ListResult[model.DeletedSecretBundle]](t, ts, http.MethodGet, "/deletedsecrets?api-version=7.4", nil)
	if len(deletedList.Value) != 1 {
		t.Fatalf("unexpected deleted secrets %+v", deletedList)
	}
	gotDeleted := doJSON[model.DeletedSecretBundle](t, ts, http.MethodGet, "/deletedsecrets/test-secret?api-version=7.4", nil)
	if gotDeleted.ID == "" {
		t.Fatalf("unexpected deleted secret %+v", gotDeleted)
	}
	resp = doRequest(t, ts, http.MethodGet, "/deletedsecrets/missing?api-version=7.4", nil, nil)
	expectStatus(t, resp, http.StatusNotFound)

	recovered := doJSON[model.SecretBundle](t, ts, http.MethodPost, "/deletedsecrets/test-secret/recover?api-version=7.4", map[string]any{})
	if recovered.Value != "super-secret" {
		t.Fatalf("unexpected recovered %+v", recovered)
	}
	_, _ = doJSON[model.DeletedSecretBundle](t, ts, http.MethodDelete, "/secrets/test-secret?api-version=7.4", nil), doJSON[model.SecretBundle](t, ts, http.MethodPut, "/secrets/restored?api-version=7.4", map[string]any{"value": "value"})
	resp = doRequest(t, ts, http.MethodDelete, "/deletedsecrets/test-secret?api-version=7.4", nil, nil)
	expectStatus(t, resp, http.StatusNoContent)

	restored := doJSON[model.SecretBundle](t, ts, http.MethodPost, "/secrets/restore?api-version=7.4", map[string]any{"value": backup["value"]})
	if restored.ID == "" || restored.Value != "super-secret" {
		t.Fatalf("unexpected restored %+v", restored)
	}
	resp = doRequest(t, ts, http.MethodPost, "/secrets/restore?api-version=7.4", map[string]any{"value": "not-base64"}, nil)
	expectStatus(t, resp, http.StatusBadRequest)
}

func TestKeyHandlers(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	rsa := doJSON[model.KeyBundle](t, ts, http.MethodPost, "/keys/mykey/create?api-version=7.4", map[string]any{"kty": "RSA", "key_size": 1024})
	version := versionFromID(rsa.Key.Kid)
	if rsa.Key.Kty != "RSA" {
		t.Fatalf("unexpected key %+v", rsa)
	}
	_ = doJSON[model.KeyBundle](t, ts, http.MethodPost, "/keys/eckey/create?api-version=7.4", map[string]any{"kty": "EC", "crv": "P-256"})
	resp := doRequest(t, ts, http.MethodPost, "/keys/bad/create?api-version=7.4", map[string]any{"kty": "BAD"}, nil)
	expectStatus(t, resp, http.StatusBadRequest)

	_, jwk, err := kvcrypto.GenerateKey("RSA", 1024, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	imported := doJSON[model.KeyBundle](t, ts, http.MethodPost, "/keys/imported/import?api-version=7.4", map[string]any{"key": jwk})
	if imported.Key.Kty != "RSA" {
		t.Fatalf("unexpected imported key %+v", imported)
	}

	got := doJSON[model.KeyBundle](t, ts, http.MethodGet, "/keys/mykey?api-version=7.4", nil)
	if got.Key.Kid == "" {
		t.Fatalf("unexpected get %+v", got)
	}
	resp = doRequest(t, ts, http.MethodGet, "/keys/missing?api-version=7.4", nil, nil)
	expectStatus(t, resp, http.StatusNotFound)

	versioned := doJSON[model.KeyBundle](t, ts, http.MethodGet, "/keys/mykey/"+version+"?api-version=7.4", nil)
	if versioned.Key.Kid != rsa.Key.Kid {
		t.Fatalf("unexpected versioned key %+v", versioned)
	}
	versions := doJSON[model.ListResult[model.KeyItem]](t, ts, http.MethodGet, "/keys/mykey/versions?api-version=7.4", nil)
	if len(versions.Value) != 1 {
		t.Fatalf("unexpected key versions %+v", versions)
	}

	updated := doJSON[model.KeyBundle](t, ts, http.MethodPatch, "/keys/mykey/"+version+"?api-version=7.4", map[string]any{"key_ops": []string{"sign"}, "tags": map[string]string{"env": "test"}})
	if len(updated.Key.KeyOps) != 1 || updated.Tags["env"] != "test" {
		t.Fatalf("unexpected key update %+v", updated)
	}

	plaintext := kvcrypto.EncodeBase64URL([]byte("hello world"))
	encrypted := doJSON[model.CryptoResponse](t, ts, http.MethodPost, "/keys/mykey/"+version+"/encrypt?api-version=7.4", map[string]any{"alg": "RSA-OAEP", "value": plaintext})
	decrypted := doJSON[model.CryptoResponse](t, ts, http.MethodPost, "/keys/mykey/"+version+"/decrypt?api-version=7.4", map[string]any{"alg": "RSA-OAEP", "value": encrypted.Value})
	if string(mustDecode(t, decrypted.Value)) != "hello world" {
		t.Fatalf("unexpected decrypt %+v", decrypted)
	}
	resp = doRequest(t, ts, http.MethodPost, "/keys/missing/"+version+"/encrypt?api-version=7.4", map[string]any{"alg": "RSA-OAEP", "value": plaintext}, nil)
	expectStatus(t, resp, http.StatusNotFound)

	digest := kvcrypto.EncodeBase64URL(kvcrypto.DigestForAlg("RS256", []byte("payload")))
	signed := doJSON[model.CryptoResponse](t, ts, http.MethodPost, "/keys/mykey/"+version+"/sign?api-version=7.4", map[string]any{"alg": "RS256", "value": digest})
	verified := doJSON[model.VerifyResponse](t, ts, http.MethodPost, "/keys/mykey/"+version+"/verify?api-version=7.4", map[string]any{"alg": "RS256", "digest": digest, "value": signed.Value})
	if !verified.Value {
		t.Fatalf("unexpected verify %+v", verified)
	}
	resp = doRequest(t, ts, http.MethodPost, "/keys/missing/"+version+"/verify?api-version=7.4", map[string]any{"alg": "RS256", "digest": digest, "value": signed.Value}, nil)
	expectStatus(t, resp, http.StatusNotFound)

	wrapped := doJSON[model.CryptoResponse](t, ts, http.MethodPost, "/keys/mykey/"+version+"/wrapkey?api-version=7.4", map[string]any{"alg": "RSA-OAEP", "value": kvcrypto.EncodeBase64URL([]byte("12345678"))})
	unwrapped := doJSON[model.CryptoResponse](t, ts, http.MethodPost, "/keys/mykey/"+version+"/unwrapkey?api-version=7.4", map[string]any{"alg": "RSA-OAEP", "value": wrapped.Value})
	if string(mustDecode(t, unwrapped.Value)) != "12345678" {
		t.Fatalf("unexpected unwrap %+v", unwrapped)
	}

	deleted := doJSON[model.DeletedKeyBundle](t, ts, http.MethodDelete, "/keys/mykey?api-version=7.4", nil)
	if deleted.RecoveryID == "" {
		t.Fatal("expected deleted key recovery id")
	}
	deletedList := doJSON[model.ListResult[model.DeletedKeyBundle]](t, ts, http.MethodGet, "/deletedkeys?api-version=7.4", nil)
	if len(deletedList.Value) == 0 {
		t.Fatalf("unexpected deleted key list %+v", deletedList)
	}
	gotDeleted := doJSON[model.DeletedKeyBundle](t, ts, http.MethodGet, "/deletedkeys/mykey?api-version=7.4", nil)
	if gotDeleted.Key.Kid == "" {
		t.Fatalf("unexpected deleted key %+v", gotDeleted)
	}
	recovered := doJSON[model.KeyBundle](t, ts, http.MethodPost, "/deletedkeys/mykey/recover?api-version=7.4", map[string]any{})
	if recovered.Key.Kid == "" {
		t.Fatalf("unexpected recovered key %+v", recovered)
	}
	_, _ = doJSON[model.DeletedKeyBundle](t, ts, http.MethodDelete, "/keys/mykey?api-version=7.4", nil), doJSON[model.KeyBundle](t, ts, http.MethodGet, "/keys/imported?api-version=7.4", nil)
	resp = doRequest(t, ts, http.MethodDelete, "/deletedkeys/mykey?api-version=7.4", nil, nil)
	expectStatus(t, resp, http.StatusNoContent)
}

func TestCertificateHandlers(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	created := doJSON[model.CertificateBundle](t, ts, http.MethodPost, "/certificates/cert/create?api-version=7.4", map[string]any{})
	version := versionFromID(created.ID)
	if created.Cer == "" || created.Policy == nil {
		t.Fatalf("unexpected certificate %+v", created)
	}
	list := doJSON[model.ListResult[model.CertificateItem]](t, ts, http.MethodGet, "/certificates?api-version=7.4", nil)
	if len(list.Value) != 1 {
		t.Fatalf("unexpected certificate list %+v", list)
	}
	got := doJSON[model.CertificateBundle](t, ts, http.MethodGet, "/certificates/cert?api-version=7.4", nil)
	if got.ID == "" {
		t.Fatalf("unexpected certificate %+v", got)
	}
	versions := doJSON[model.ListResult[model.CertificateItem]](t, ts, http.MethodGet, "/certificates/cert/versions?api-version=7.4", nil)
	if len(versions.Value) != 1 {
		t.Fatalf("unexpected cert versions %+v", versions)
	}
	policy := doJSON[model.CertificatePolicy](t, ts, http.MethodGet, "/certificates/cert/policy?api-version=7.4", nil)
	if policy.X509Props == nil {
		t.Fatalf("unexpected policy %+v", policy)
	}
	policy = doJSON[model.CertificatePolicy](t, ts, http.MethodPatch, "/certificates/cert/policy?api-version=7.4", map[string]any{"policy": map[string]any{"x509_props": map[string]any{"subject": "CN=updated"}}})
	if policy.X509Props["subject"] != "CN=updated" {
		t.Fatalf("unexpected updated policy %+v", policy)
	}
	pending := doJSON[model.CertificateOperation](t, ts, http.MethodGet, "/certificates/cert/pending?api-version=7.4", nil)
	if pending.Status != "completed" {
		t.Fatalf("unexpected pending %+v", pending)
	}

	resp := doRequest(t, ts, http.MethodPost, "/certificates/imported/import?api-version=7.4", map[string]any{"value": importedPEMValue(t)}, nil)
	expectStatus(t, resp, http.StatusOK)
	_ = doJSON[model.CertificateBundle](t, ts, http.MethodGet, "/certificates/cert/"+version+"?api-version=7.4", nil)

	deleted := doJSON[model.DeletedCertificateBundle](t, ts, http.MethodDelete, "/certificates/cert?api-version=7.4", nil)
	if deleted.RecoveryID == "" {
		t.Fatal("expected recovery id")
	}
	deletedList := doJSON[model.ListResult[model.DeletedCertificateBundle]](t, ts, http.MethodGet, "/deletedcertificates?api-version=7.4", nil)
	if len(deletedList.Value) == 0 {
		t.Fatalf("unexpected deleted certs %+v", deletedList)
	}
	gotDeleted := doJSON[model.DeletedCertificateBundle](t, ts, http.MethodGet, "/deletedcertificates/cert?api-version=7.4", nil)
	if gotDeleted.ID == "" {
		t.Fatalf("unexpected deleted cert %+v", gotDeleted)
	}
	recovered := doJSON[model.CertificateBundle](t, ts, http.MethodPost, "/deletedcertificates/cert/recover?api-version=7.4", map[string]any{})
	if recovered.ID == "" {
		t.Fatalf("unexpected recovered cert %+v", recovered)
	}
	_ = doJSON[model.DeletedCertificateBundle](t, ts, http.MethodDelete, "/certificates/cert?api-version=7.4", nil)
	resp = doRequest(t, ts, http.MethodDelete, "/deletedcertificates/cert?api-version=7.4", nil, nil)
	expectStatus(t, resp, http.StatusNoContent)
}

func importedPEMValue(t *testing.T) string {
	t.Helper()
	priv, der, err := kvcrypto.GenerateSelfSignedCert("handler-import", nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := base64.StdEncoding.EncodeToString(der)
	parsed, key, pemData, err := kvcrypto.ParseImportedCertificate(cert, "")
	if err != nil || parsed == nil || key != nil {
		t.Fatalf("unexpected parse %v %v %v", parsed, key, err)
	}
	pemData = append(pemData, []byte("\n")...)
	pemData = append(pemData, []byte(kvcrypto.EncodeBase64URL([]byte("ignored")))...)
	_ = priv
	return string(pemData)
}
