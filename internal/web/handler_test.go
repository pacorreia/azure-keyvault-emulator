package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pacorreia/azure-keyvault-emulator/internal/auth"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

func TestStatusEndpoint(t *testing.T) {
	h, _, _, mux := newTestHandler(t)

	rr := performRequest(mux, http.MethodGet, "/ui/api/status", nil, "")
	assertStatus(t, rr, http.StatusOK)
	var status statusResponse
	decodeBody(t, rr, &status)
	if status.Initialized {
		t.Fatalf("expected uninitialized status")
	}
	if status.Locked {
		t.Fatalf("expected not locked when encryption not configured")
	}

	performSetup(t, mux, h)

	rr = performRequest(mux, http.MethodGet, "/ui/api/status", nil, "")
	assertStatus(t, rr, http.StatusOK)
	decodeBody(t, rr, &status)
	if !status.Initialized {
		t.Fatalf("expected initialized status")
	}
	if status.Locked {
		t.Fatalf("expected not locked immediately after setup (key is already in memory)")
	}

	// Simulate a server restart by clearing the in-memory key.
	h.setEncryptionKey(nil)
	rr = performRequest(mux, http.MethodGet, "/ui/api/status", nil, "")
	assertStatus(t, rr, http.StatusOK)
	decodeBody(t, rr, &status)
	if !status.Initialized {
		t.Fatalf("expected initialized status")
	}
	if !status.Locked {
		t.Fatalf("expected locked after key is cleared from memory")
	}
}

func TestUnlockEndpoint(t *testing.T) {
	h, _, _, mux := newTestHandler(t)
	performSetup(t, mux, h)

	// Simulate a server restart by clearing the in-memory encryption key.
	h.setEncryptionKey(nil)
	if len(h.getEncryptionKey()) != 0 {
		t.Fatal("expected key to be cleared")
	}

	// Wrong passphrase must be rejected.
	rr := performRequest(mux, http.MethodPost, "/ui/api/unlock", map[string]string{
		"passphrase": "wrong passphrase",
	}, "")
	assertStatus(t, rr, http.StatusUnauthorized)
	if len(h.getEncryptionKey()) != 0 {
		t.Fatal("key must not be set after wrong passphrase")
	}

	// Correct passphrase must succeed and restore the key.
	rr = performRequest(mux, http.MethodPost, "/ui/api/unlock", map[string]string{
		"passphrase": "correct horse battery staple",
	}, "")
	assertStatus(t, rr, http.StatusOK)
	var resp map[string]bool
	decodeBody(t, rr, &resp)
	if !resp["ok"] {
		t.Fatalf("expected ok response")
	}
	if len(h.getEncryptionKey()) != 32 {
		t.Fatalf("expected 32-byte encryption key after unlock")
	}

	// Unlock when encryption is not configured must return an error.
	h2, _, _, mux2 := newTestHandler(t)
	// No setup performed on h2, so enc_salt is not in config.
	rr = performRequest(mux2, http.MethodPost, "/ui/api/unlock", map[string]string{
		"passphrase": "some passphrase",
	}, "")
	assertStatus(t, rr, http.StatusBadRequest)
	if len(h2.getEncryptionKey()) != 0 {
		t.Fatal("key must not be set when encryption is not configured")
	}
}

func TestSetupSuccessAndConflict(t *testing.T) {
	h, a, _, mux := newTestHandler(t)

	rr := performRequest(mux, http.MethodPost, "/ui/api/setup", map[string]string{
		"username":   "admin",
		"password":   "Password123!",
		"passphrase": "correct horse battery staple",
	}, "")
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]bool
	decodeBody(t, rr, &resp)
	if !resp["ok"] {
		t.Fatalf("expected ok response")
	}
	if len(h.getEncryptionKey()) != 32 {
		t.Fatalf("expected 32-byte encryption key")
	}
	if _, ok, err := a.GetConfig("enc_salt"); !ok || err != nil {
		t.Fatalf("expected enc_salt config to be stored")
	}
	if _, ok, err := a.GetConfig("enc_verify"); !ok || err != nil {
		t.Fatalf("expected enc_verify config to be stored")
	}

	rr = performRequest(mux, http.MethodPost, "/ui/api/setup", map[string]string{
		"username":   "admin2",
		"password":   "Password123!",
		"passphrase": "another passphrase",
	}, "")
	assertStatus(t, rr, http.StatusConflict)
}

func TestLoginSuccessAndFailure(t *testing.T) {
	_, _, _, mux := newTestHandler(t)
	performSetup(t, mux, nil)

	rr := performRequest(mux, http.MethodPost, "/ui/api/login", map[string]string{
		"username": "admin",
		"password": "Password123!",
	}, "")
	assertStatus(t, rr, http.StatusOK)
	if cookie := sessionCookie(t, rr); cookie == "" {
		t.Fatalf("expected session cookie")
	}
	var resp authResponse
	decodeBody(t, rr, &resp)
	if resp.Username != "admin" || resp.Role != auth.RoleAdmin {
		t.Fatalf("unexpected login response: %+v", resp)
	}

	rr = performRequest(mux, http.MethodPost, "/ui/api/login", map[string]string{
		"username": "admin",
		"password": "wrong",
	}, "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestLogout(t *testing.T) {
	_, _, _, mux := newTestHandler(t)
	performSetup(t, mux, nil)
	cookie := loginAndGetCookie(t, mux, "admin", "Password123!")

	rr := performRequest(mux, http.MethodPost, "/ui/api/logout", nil, cookie)
	assertStatus(t, rr, http.StatusOK)
	if !strings.Contains(rr.Header().Get("Set-Cookie"), "kv_session=") {
		t.Fatalf("expected session cookie to be cleared")
	}

	rr = performRequest(mux, http.MethodGet, "/ui/api/me", nil, cookie)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestMeEndpointRequiresAuth(t *testing.T) {
	_, _, _, mux := newTestHandler(t)
	performSetup(t, mux, nil)

	rr := performRequest(mux, http.MethodGet, "/ui/api/me", nil, "")
	assertStatus(t, rr, http.StatusUnauthorized)

	cookie := loginAndGetCookie(t, mux, "admin", "Password123!")
	rr = performRequest(mux, http.MethodGet, "/ui/api/me", nil, cookie)
	assertStatus(t, rr, http.StatusOK)

	var resp authResponse
	decodeBody(t, rr, &resp)
	if resp.Username != "admin" || resp.Role != auth.RoleAdmin {
		t.Fatalf("unexpected me response: %+v", resp)
	}
}

func TestListUsersAdminOnly(t *testing.T) {
	_, a, _, mux := newTestHandler(t)
	performSetup(t, mux, nil)
	if _, err := a.CreateUser("contributor", "Password123!", auth.RoleContributor); err != nil {
		t.Fatalf("create contributor: %v", err)
	}

	adminCookie := loginAndGetCookie(t, mux, "admin", "Password123!")
	rr := performRequest(mux, http.MethodGet, "/ui/api/users", nil, adminCookie)
	assertStatus(t, rr, http.StatusOK)

	var users []userResponse
	decodeBody(t, rr, &users)
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	contributorCookie := loginAndGetCookie(t, mux, "contributor", "Password123!")
	rr = performRequest(mux, http.MethodGet, "/ui/api/users", nil, contributorCookie)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestCreateUserAdminOnly(t *testing.T) {
	_, a, _, mux := newTestHandler(t)
	performSetup(t, mux, nil)
	adminCookie := loginAndGetCookie(t, mux, "admin", "Password123!")

	rr := performRequest(mux, http.MethodPost, "/ui/api/users", map[string]string{
		"username": "reader",
		"password": "Password123!",
		"role":     string(auth.RoleReader),
	}, adminCookie)
	assertStatus(t, rr, http.StatusOK)

	var user userResponse
	decodeBody(t, rr, &user)
	if user.Username != "reader" || user.Role != auth.RoleReader || user.ID == "" {
		t.Fatalf("unexpected user response: %+v", user)
	}

	users, err := a.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestDeleteUser(t *testing.T) {
	_, a, _, mux := newTestHandler(t)
	performSetup(t, mux, nil)
	user, err := a.CreateUser("reader", "Password123!", auth.RoleReader)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	adminCookie := loginAndGetCookie(t, mux, "admin", "Password123!")

	rr := performRequest(mux, http.MethodDelete, "/ui/api/users/"+user.ID, nil, adminCookie)
	assertStatus(t, rr, http.StatusNoContent)

	users, err := a.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user after delete, got %d", len(users))
	}
}

func TestListSecretsKeysAndCertificates(t *testing.T) {
	_, _, s, mux := newTestHandler(t)
	performSetup(t, mux, nil)
	cookie := loginAndGetCookie(t, mux, "admin", "Password123!")
	seedStore(t, s)

	rr := performRequest(mux, http.MethodGet, "/ui/api/secrets", nil, cookie)
	assertStatus(t, rr, http.StatusOK)
	var secrets []secretResponse
	decodeBody(t, rr, &secrets)
	secret, ok := findByName(secrets, "db-password", func(item secretResponse) string { return item.Name })
	if !ok || secret.ContentType != "text/plain" || !secret.Enabled {
		t.Fatalf("unexpected secrets response: %+v", secrets)
	}

	rr = performRequest(mux, http.MethodGet, "/ui/api/keys", nil, cookie)
	assertStatus(t, rr, http.StatusOK)
	var keys []keyResponse
	decodeBody(t, rr, &keys)
	key, ok := findByName(keys, "signing-key", func(item keyResponse) string { return item.Name })
	if !ok || key.Kty == "" || key.Version == "" {
		t.Fatalf("unexpected keys response: %+v", keys)
	}

	rr = performRequest(mux, http.MethodGet, "/ui/api/certificates", nil, cookie)
	assertStatus(t, rr, http.StatusOK)
	var certs []certificateResponse
	decodeBody(t, rr, &certs)
	cert, ok := findByName(certs, "tls-cert", func(item certificateResponse) string { return item.Name })
	if !ok || cert.Version == "" {
		t.Fatalf("unexpected certificates response: %+v", certs)
	}
}

func TestContributorCanListButNotManageUsers(t *testing.T) {
	_, a, s, mux := newTestHandler(t)
	performSetup(t, mux, nil)
	user, err := a.CreateUser("contributor", "Password123!", auth.RoleContributor)
	if err != nil {
		t.Fatalf("create contributor: %v", err)
	}
	seedStore(t, s)
	cookie := loginAndGetCookie(t, mux, "contributor", "Password123!")

	for _, path := range []string{"/ui/api/secrets", "/ui/api/keys", "/ui/api/certificates"} {
		rr := performRequest(mux, http.MethodGet, path, nil, cookie)
		assertStatus(t, rr, http.StatusOK)
	}

	rr := performRequest(mux, http.MethodGet, "/ui/api/users", nil, cookie)
	assertStatus(t, rr, http.StatusForbidden)

	rr = performRequest(mux, http.MethodPost, "/ui/api/users", map[string]string{
		"username": "reader",
		"password": "Password123!",
		"role":     string(auth.RoleReader),
	}, cookie)
	assertStatus(t, rr, http.StatusForbidden)

	rr = performRequest(mux, http.MethodDelete, "/ui/api/users/"+user.ID, nil, cookie)
	assertStatus(t, rr, http.StatusForbidden)
}

func newTestHandler(t *testing.T) (*Handler, *auth.Service, *store.Store, *http.ServeMux) {
	t.Helper()
	a, err := auth.NewMemory()
	if err != nil {
		t.Fatalf("new auth service: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	s := store.New()
	t.Cleanup(func() { _ = s.Close() })

	h := New(a, s)
	mux := http.NewServeMux()
	h.Register(mux)
	return h, a, s, mux
}

func performSetup(t *testing.T, mux *http.ServeMux, h *Handler) {
	t.Helper()
	rr := performRequest(mux, http.MethodPost, "/ui/api/setup", map[string]string{
		"username":   "admin",
		"password":   "Password123!",
		"passphrase": "correct horse battery staple",
	}, "")
	assertStatus(t, rr, http.StatusOK)
	if h != nil && len(h.getEncryptionKey()) != 32 {
		t.Fatalf("expected setup to set encryption key")
	}
}

func loginAndGetCookie(t *testing.T, mux *http.ServeMux, username, password string) string {
	t.Helper()
	rr := performRequest(mux, http.MethodPost, "/ui/api/login", map[string]string{
		"username": username,
		"password": password,
	}, "")
	assertStatus(t, rr, http.StatusOK)
	return sessionCookie(t, rr)
}

func sessionCookie(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		return ""
	}
	return cookies[0].Name + "=" + cookies[0].Value
}

func performRequest(mux *http.ServeMux, method, target string, body any, cookie string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		payload, _ := json.Marshal(body)
		reader = strings.NewReader(string(payload))
	}
	req := httptest.NewRequest(method, target, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestEncryptedStoreEncryptsSecretValues(t *testing.T) {
	h, _, s, _ := newTestHandler(t)

	// Before setup, no key is set: values stored and retrieved as plaintext.
	if _, err := h.kvStore.SetSecret("plain-secret", model.SecretSetRequest{Value: "plaintext"}); err != nil {
		t.Fatalf("set secret (no key): %v", err)
	}
	rawBefore, err := s.GetSecret("plain-secret", "")
	if err != nil {
		t.Fatalf("raw get (no key): %v", err)
	}
	if rawBefore.Value != "plaintext" {
		t.Fatalf("expected plaintext stored without key, got %q", rawBefore.Value)
	}

	// Set an encryption key directly on the handler.
	h.setEncryptionKey(make([]byte, 32))

	// After key is set: values must be stored encrypted.
	if _, err := h.kvStore.SetSecret("enc-secret", model.SecretSetRequest{Value: "my-secret-value"}); err != nil {
		t.Fatalf("set secret (with key): %v", err)
	}
	rawAfter, err := s.GetSecret("enc-secret", "")
	if err != nil {
		t.Fatalf("raw get (with key): %v", err)
	}
	if rawAfter.Value == "my-secret-value" {
		t.Fatal("expected secret value to be stored encrypted, but got plaintext")
	}

	// Retrieval via the encrypted store must return the decrypted value.
	decrypted, err := h.kvStore.GetSecret("enc-secret", "")
	if err != nil {
		t.Fatalf("get secret (with key): %v", err)
	}
	if decrypted.Value != "my-secret-value" {
		t.Fatalf("expected decrypted value %q, got %q", "my-secret-value", decrypted.Value)
	}
}

func seedStore(t *testing.T, s *store.Store) {
	t.Helper()
	enabled := true
	if _, err := s.SetSecret("db-password", model.SecretSetRequest{
		Value:       "secret-value",
		ContentType: "text/plain",
		Attributes:  &model.Attributes{Enabled: &enabled},
	}); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	if _, err := s.CreateKey("signing-key", model.CreateKeyRequest{Kty: "RSA"}); err != nil {
		t.Fatalf("create key: %v", err)
	}
	if _, err := s.CreateCertificate("tls-cert", model.CreateCertificateRequest{}); err != nil {
		t.Fatalf("create certificate: %v", err)
	}
}

func decodeBody(t *testing.T, rr *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(dst); err != nil {
		t.Fatalf("decode body: %v", err)
	}
}

func findByName[T any](items []T, name string, getName func(T) string) (T, bool) {
	var zero T
	for _, item := range items {
		if getName(item) == name {
			return item, true
		}
	}
	return zero, false
}

func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Fatalf("unexpected status: got %d want %d body=%s", rr.Code, want, rr.Body.String())
	}
}
