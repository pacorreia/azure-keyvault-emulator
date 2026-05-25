package handler

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

func TestHandlerHelpers(t *testing.T) {
	h := New(store.New())

	t.Run("vaultBaseURL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example/secrets", nil)
		req.Host = "myvault.vault.azure.net:443"
		if got := h.vaultBaseURL(req); got != "http://myvault.vault.azure.net" {
			t.Fatalf("unexpected base url %q", got)
		}
		req.Header.Set("X-Forwarded-Proto", "https")
		if got := h.vaultBaseURL(req); got != "https://myvault.vault.azure.net" {
			t.Fatalf("unexpected forwarded base url %q", got)
		}
		req.Host = "localhost:8080"
		if got := h.vaultBaseURL(req); got != "https://emulator" {
			t.Fatalf("unexpected fallback base url %q", got)
		}
	})

	t.Run("parsePagination", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?maxresults=5&skiptoken=2", nil)
		max, skip, err := h.parsePagination(req)
		if err != nil || max != 5 || skip != "2" {
			t.Fatalf("unexpected pagination %d %q %v", max, skip, err)
		}
		req = httptest.NewRequest(http.MethodGet, "/?$maxresults=101", nil)
		max, _, err = h.parsePagination(req)
		if err != nil || max != 100 {
			t.Fatalf("unexpected capped max %d %v", max, err)
		}
		req = httptest.NewRequest(http.MethodGet, "/?$maxresults=0", nil)
		if _, _, err := h.parsePagination(req); err == nil {
			t.Fatal("expected invalid $maxresults")
		}
	})

	t.Run("buildNextLink", func(t *testing.T) {
		next := "2"
		req := httptest.NewRequest(http.MethodGet, "/secrets?api-version=7.4", nil)
		req.Host = "myvault.vault.azure.net"
		link := h.buildNextLink(req, &next)
		if link == nil || !strings.Contains(*link, "skiptoken=2") {
			t.Fatalf("unexpected next link %v", link)
		}
		if h.buildNextLink(req, nil) != nil {
			t.Fatal("expected nil next link")
		}
	})

	t.Run("parseBody and writeError", func(t *testing.T) {
		var payload map[string]any
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"a":1}`))
		if err := h.parseBody(req, &payload); err != nil || payload["a"].(float64) != 1 {
			t.Fatalf("unexpected parseBody %v %+v", err, payload)
		}
		req = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"a":`))
		if err := h.parseBody(req, &payload); err == nil {
			t.Fatal("expected invalid json error")
		}
		rec := httptest.NewRecorder()
		h.writeError(rec, store.NewError(http.StatusBadRequest, "BadParameter", "bad"))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "BadParameter") {
			t.Fatalf("unexpected store error response %d %s", rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		h.writeError(rec, errors.New("boom"))
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "boom") {
			t.Fatalf("unexpected generic error response %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("misc helpers", func(t *testing.T) {
		values := cloneValues(map[string][]string{"a": {"1"}})
		values.Set("a", "2")
		if split := splitPath("/secrets/name/ver", "/secrets/"); len(split) != 2 || split[0] != "name" {
			t.Fatalf("unexpected split %v", split)
		}
		if err := modelError(http.StatusBadRequest, "BadParameter", "bad"); err == nil {
			t.Fatal("expected modelError")
		}
		if got := recoveryID("https://emulator", "/deletedkeys/name/1"); got != "https://emulator/deletedkeys/name/1" {
			t.Fatalf("unexpected recovery id %q", got)
		}
		if got := recoveryID("https://emulator", "https://other/path"); got != "https://other/path" {
			t.Fatalf("unexpected absolute recovery id %q", got)
		}
	})
}

func TestRouteEdgeCases(t *testing.T) {
	s := store.New()
	h := New(s)
	_, err := s.SetSecret("secret", model.SecretSetRequest{Value: "value"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateKey("key", model.CreateKeyRequest{Kty: "RSA", KeySize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateCertificate("cert", model.CreateCertificateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.DeleteSecret("secret")
	_, _ = s.DeleteKey("key")
	_, _ = s.DeleteCertificate("cert")

	cases := []struct {
		name   string
		method string
		path   string
		fn     func(http.ResponseWriter, *http.Request)
		code   int
	}{
		{name: "secret route missing segments", method: http.MethodGet, path: "/secrets/", fn: h.handleSecretRoutes, code: http.StatusNotFound},
		{name: "secret route bad post path", method: http.MethodPost, path: "/secrets/name/unknown", fn: h.handleSecretRoutes, code: http.StatusNotFound},
		{name: "secret route method not allowed", method: http.MethodOptions, path: "/secrets/name", fn: h.handleSecretRoutes, code: http.StatusMethodNotAllowed},
		{name: "deleted secret bad path", method: http.MethodGet, path: "/deletedsecrets/secret/extra", fn: h.handleDeletedSecretRoutes, code: http.StatusNotFound},
		{name: "deleted secret method not allowed", method: http.MethodPut, path: "/deletedsecrets/secret", fn: h.handleDeletedSecretRoutes, code: http.StatusMethodNotAllowed},
		{name: "key route missing segments", method: http.MethodGet, path: "/keys/", fn: h.handleKeyRoutes, code: http.StatusNotFound},
		{name: "key patch wrong length", method: http.MethodPatch, path: "/keys/name", fn: h.handleKeyRoutes, code: http.StatusNotFound},
		{name: "key post unknown operation", method: http.MethodPost, path: "/keys/name/version/unknown", fn: h.handleKeyRoutes, code: http.StatusNotFound},
		{name: "key method not allowed", method: http.MethodOptions, path: "/keys/name", fn: h.handleKeyRoutes, code: http.StatusMethodNotAllowed},
		{name: "deleted key bad path", method: http.MethodGet, path: "/deletedkeys/key/extra", fn: h.handleDeletedKeyRoutes, code: http.StatusNotFound},
		{name: "deleted key method not allowed", method: http.MethodPut, path: "/deletedkeys/key", fn: h.handleDeletedKeyRoutes, code: http.StatusMethodNotAllowed},
		{name: "certificate bad post path", method: http.MethodPost, path: "/certificates/cert/bad", fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate get too many segments", method: http.MethodGet, path: "/certificates/cert/a/b", fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate patch wrong length", method: http.MethodPatch, path: "/certificates/cert", fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate method not allowed", method: http.MethodPut, path: "/certificates/cert", fn: h.handleCertificateRoutes, code: http.StatusMethodNotAllowed},
		{name: "deleted certificate bad path", method: http.MethodGet, path: "/deletedcertificates/cert/extra", fn: h.handleDeletedCertificateRoutes, code: http.StatusNotFound},
		{name: "deleted certificate method not allowed", method: http.MethodPut, path: "/deletedcertificates/cert", fn: h.handleDeletedCertificateRoutes, code: http.StatusMethodNotAllowed},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			tt.fn(rec, req)
			if rec.Code != tt.code {
				t.Fatalf("expected %d got %d body=%s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}

	t.Run("list routes and bad bodies", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.listKeys(rec, httptest.NewRequest(http.MethodGet, "/keys?api-version=7.4", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected listKeys code %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.listDeletedKeys(rec, httptest.NewRequest(http.MethodGet, "/deletedkeys?api-version=7.4", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected listDeletedKeys code %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.listDeletedSecrets(rec, httptest.NewRequest(http.MethodGet, "/deletedsecrets?api-version=7.4", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected listDeletedSecrets code %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.listDeletedCertificates(rec, httptest.NewRequest(http.MethodGet, "/deletedcertificates?api-version=7.4", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected listDeletedCertificates code %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.restoreSecret(rec, httptest.NewRequest(http.MethodPost, "/secrets/restore", bytes.NewBufferString("{")))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unexpected restore code %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.handleKeyPost(rec, httptest.NewRequest(http.MethodPost, "/keys/key/create", bytes.NewBufferString("{")), "key", []string{"key", "create"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unexpected key create body code %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.handleCertificateRoutes(rec, httptest.NewRequest(http.MethodPatch, "/certificates/cert/policy", bytes.NewBufferString("{")))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unexpected policy body code %d", rec.Code)
		}
	})

}

func TestAdditionalHandlerCoverage(t *testing.T) {
	s := store.New()
	h := New(s)
	secret, err := s.SetSecret("name", model.SecretSetRequest{Value: "value"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.CreateKey("name", model.CreateKeyRequest{Kty: "RSA", KeySize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := s.CreateCertificate("name", model.CreateCertificateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.DeleteSecret("name")
	_, _ = s.DeleteKey("name")
	_, _ = s.DeleteCertificate("name")

	for _, tc := range []struct {
		name string
		path string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{name: "listKeys bad pagination", path: "/keys?$maxresults=bad", fn: h.listKeys},
		{name: "listKeyVersions bad pagination", path: "/keys/name/versions?$maxresults=bad", fn: func(w http.ResponseWriter, r *http.Request) { h.listKeyVersions(w, r, "name") }},
		{name: "listKeyVersions missing", path: "/keys/missing/versions?api-version=7.4", fn: func(w http.ResponseWriter, r *http.Request) { h.listKeyVersions(w, r, "missing") }},
		{name: "listDeletedKeys bad pagination", path: "/deletedkeys?$maxresults=bad", fn: h.listDeletedKeys},
		{name: "listSecretVersions bad pagination", path: "/secrets/name/versions?$maxresults=bad", fn: func(w http.ResponseWriter, r *http.Request) { h.listSecretVersions(w, r, "name") }},
		{name: "listDeletedSecrets bad pagination", path: "/deletedsecrets?$maxresults=bad", fn: h.listDeletedSecrets},
		{name: "listCertificates bad pagination", path: "/certificates?$maxresults=bad", fn: h.listCertificates},
		{name: "listCertificateVersions bad pagination", path: "/certificates/name/versions?$maxresults=bad", fn: func(w http.ResponseWriter, r *http.Request) { h.listCertificateVersions(w, r, "name") }},
		{name: "listCertificateVersions missing", path: "/certificates/missing/versions?api-version=7.4", fn: func(w http.ResponseWriter, r *http.Request) { h.listCertificateVersions(w, r, "missing") }},
		{name: "listDeletedCertificates bad pagination", path: "/deletedcertificates?$maxresults=bad", fn: h.listDeletedCertificates},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.fn(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
				t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
		fn     func(http.ResponseWriter, *http.Request)
		code   int
	}{
		{name: "secret get too many segments", method: http.MethodGet, path: "/secrets/name/a/b", fn: h.handleSecretRoutes, code: http.StatusNotFound},
		{name: "secret delete wrong len", method: http.MethodDelete, path: "/secrets/name/v1", fn: h.handleSecretRoutes, code: http.StatusNotFound},
		{name: "secret patch wrong len", method: http.MethodPatch, path: "/secrets/name", body: `{}`, fn: h.handleSecretRoutes, code: http.StatusNotFound},
		{name: "deleted secret invalid recover path", method: http.MethodPost, path: "/deletedsecrets/name/nope", body: `{}`, fn: h.handleDeletedSecretRoutes, code: http.StatusNotFound},
		{name: "deleted secret delete wrong len", method: http.MethodDelete, path: "/deletedsecrets/name/extra", fn: h.handleDeletedSecretRoutes, code: http.StatusNotFound},
		{name: "key delete wrong len", method: http.MethodDelete, path: "/keys/name/version", fn: h.handleKeyRoutes, code: http.StatusNotFound},
		{name: "key patch bad body", method: http.MethodPatch, path: "/keys/name/" + key.Version, body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "key get too many segments", method: http.MethodGet, path: "/keys/name/a/b", fn: h.handleKeyRoutes, code: http.StatusNotFound},
		{name: "key create invalid body", method: http.MethodPost, path: "/keys/name/create", body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "key import invalid body", method: http.MethodPost, path: "/keys/name/import", body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "key encrypt invalid body", method: http.MethodPost, path: "/keys/name/" + key.Version + "/encrypt", body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "key decrypt invalid body", method: http.MethodPost, path: "/keys/name/" + key.Version + "/decrypt", body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "key sign invalid body", method: http.MethodPost, path: "/keys/name/" + key.Version + "/sign", body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "key verify invalid body", method: http.MethodPost, path: "/keys/name/" + key.Version + "/verify", body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "key wrap invalid body", method: http.MethodPost, path: "/keys/name/" + key.Version + "/wrapkey", body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "key unwrap invalid body", method: http.MethodPost, path: "/keys/name/" + key.Version + "/unwrapkey", body: `{`, fn: h.handleKeyRoutes, code: http.StatusBadRequest},
		{name: "deleted key invalid recover path", method: http.MethodPost, path: "/deletedkeys/name/nope", body: `{}`, fn: h.handleDeletedKeyRoutes, code: http.StatusNotFound},
		{name: "deleted key delete wrong len", method: http.MethodDelete, path: "/deletedkeys/name/extra", fn: h.handleDeletedKeyRoutes, code: http.StatusNotFound},
		{name: "certificate create invalid body", method: http.MethodPost, path: "/certificates/name/create", body: `{`, fn: h.handleCertificateRoutes, code: http.StatusBadRequest},
		{name: "certificate import invalid body", method: http.MethodPost, path: "/certificates/name/import", body: `{`, fn: h.handleCertificateRoutes, code: http.StatusBadRequest},
		{name: "certificate get missing", method: http.MethodGet, path: "/certificates/missing", fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate policy missing", method: http.MethodGet, path: "/certificates/missing/policy", fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate pending missing", method: http.MethodGet, path: "/certificates/missing/pending", fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate patch body", method: http.MethodPatch, path: "/certificates/name/" + cert.Version, body: `{`, fn: h.handleCertificateRoutes, code: http.StatusBadRequest},
		{name: "certificate patch missing", method: http.MethodPatch, path: "/certificates/missing/" + cert.Version, body: `{}`, fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate delete missing", method: http.MethodDelete, path: "/certificates/missing", fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "deleted certificate invalid recover path", method: http.MethodPost, path: "/deletedcertificates/name/nope", body: `{}`, fn: h.handleDeletedCertificateRoutes, code: http.StatusNotFound},
		{name: "deleted certificate delete wrong len", method: http.MethodDelete, path: "/deletedcertificates/name/extra", fn: h.handleDeletedCertificateRoutes, code: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			var body *bytes.Buffer
			if tc.body != "" {
				body = bytes.NewBufferString(tc.body)
			} else {
				body = &bytes.Buffer{}
			}
			tc.fn(rec, httptest.NewRequest(tc.method, tc.path, body))
			if rec.Code != tc.code {
				t.Fatalf("expected %d got %d body=%s", tc.code, rec.Code, rec.Body.String())
			}
		})
	}

	rec := httptest.NewRecorder()
	h.writeError(rec, nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("unexpected nil error write status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := recoveryID("https://emulator", "deletedkeys/name/1"); got != "https://emulator/deletedkeys/name/1" {
		t.Fatalf("unexpected relative recovery id %q", got)
	}
	if got := secretID("https://emulator", "name", ""); got != "https://emulator/secrets/name" {
		t.Fatalf("unexpected secret id %q", got)
	}
	if got := keyID("https://emulator", "name", ""); got != "https://emulator/keys/name" {
		t.Fatalf("unexpected key id %q", got)
	}
	if got := certificateID("https://emulator", "name", ""); got != "https://emulator/certificates/name" {
		t.Fatalf("unexpected certificate id %q", got)
	}
	_ = secret
}

func TestMoreHandlerBranches(t *testing.T) {
	s := store.New()
	h := New(s)
	key, err := s.CreateKey("k", model.CreateKeyRequest{Kty: "RSA", KeySize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := s.CreateCertificate("c", model.CreateCertificateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	activeCert, err := s.CreateCertificate("active", model.CreateCertificateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SetSecret("s", model.SecretSetRequest{Value: "v"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.DeleteKey("k")
	_, _ = s.DeleteCertificate("c")
	_, _ = s.DeleteSecret("s")

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		fn     func(http.ResponseWriter, *http.Request)
		code   int
	}{
		{name: "deleted secret empty path", method: http.MethodGet, path: "/deletedsecrets/", fn: h.handleDeletedSecretRoutes, code: http.StatusNotFound},
		{name: "deleted secret purge missing", method: http.MethodDelete, path: "/deletedsecrets/missing", fn: h.handleDeletedSecretRoutes, code: http.StatusNotFound},
		{name: "deleted secret recover missing", method: http.MethodPost, path: "/deletedsecrets/missing/recover", body: `{}`, fn: h.handleDeletedSecretRoutes, code: http.StatusNotFound},
		{name: "deleted key empty path", method: http.MethodGet, path: "/deletedkeys/", fn: h.handleDeletedKeyRoutes, code: http.StatusNotFound},
		{name: "deleted key purge missing", method: http.MethodDelete, path: "/deletedkeys/missing", fn: h.handleDeletedKeyRoutes, code: http.StatusNotFound},
		{name: "deleted key recover missing", method: http.MethodPost, path: "/deletedkeys/missing/recover", body: `{}`, fn: h.handleDeletedKeyRoutes, code: http.StatusNotFound},
		{name: "deleted cert empty path", method: http.MethodGet, path: "/deletedcertificates/", fn: h.handleDeletedCertificateRoutes, code: http.StatusNotFound},
		{name: "deleted cert purge missing", method: http.MethodDelete, path: "/deletedcertificates/missing", fn: h.handleDeletedCertificateRoutes, code: http.StatusNotFound},
		{name: "deleted cert recover missing", method: http.MethodPost, path: "/deletedcertificates/missing/recover", body: `{}`, fn: h.handleDeletedCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate empty path", method: http.MethodGet, path: "/certificates/", fn: h.handleCertificateRoutes, code: http.StatusNotFound},
		{name: "certificate create conflict", method: http.MethodPost, path: "/certificates/c/create", body: `{}`, fn: h.handleCertificateRoutes, code: http.StatusConflict},
		{name: "certificate import bad value", method: http.MethodPost, path: "/certificates/x/import", body: `{"value":"bad"}`, fn: h.handleCertificateRoutes, code: http.StatusBadRequest},
		{name: "key get missing version", method: http.MethodGet, path: "/keys/k/missing", fn: h.handleKeyRoutes, code: http.StatusNotFound},
		{name: "key delete missing", method: http.MethodDelete, path: "/keys/missing", fn: h.handleKeyRoutes, code: http.StatusNotFound},
		{name: "secret empty path", method: http.MethodGet, path: "/secrets/", fn: h.handleSecretRoutes, code: http.StatusNotFound},
		{name: "secret delete missing", method: http.MethodDelete, path: "/secrets/missing", fn: h.handleSecretRoutes, code: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body := bytes.NewBufferString(tc.body)
			tc.fn(rec, httptest.NewRequest(tc.method, tc.path, body))
			if rec.Code != tc.code {
				t.Fatalf("expected %d got %d body=%s", tc.code, rec.Code, rec.Body.String())
			}
		})
	}

	rec := httptest.NewRecorder()
	h.handleCertificateRoutes(rec, httptest.NewRequest(http.MethodPatch, "/certificates/active/"+activeCert.Version, bytes.NewBufferString(`{"tags":{"x":"y"}}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected certificate patch code %d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.handleKeyRoutes(rec, httptest.NewRequest(http.MethodGet, "/keys/k/versions?api-version=7.4", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unexpected deleted key versions code %d body=%s", rec.Code, rec.Body.String())
	}
	_ = key
	_ = cert
}

func TestListHandlersAndHelpersCoverage(t *testing.T) {
	s := store.New()
	h := New(s)
	for _, name := range []string{"a", "b", "c", "d"} {
		_, _ = s.CreateKey(name, model.CreateKeyRequest{Kty: "RSA", KeySize: 1024})
		_, _ = s.SetSecret(name, model.SecretSetRequest{Value: name})
		_, _ = s.CreateCertificate(name, model.CreateCertificateRequest{})
	}
	for _, name := range []string{"a", "b"} {
		_, _ = s.DeleteKey(name)
		_, _ = s.DeleteSecret(name)
		_, _ = s.DeleteCertificate(name)
	}

	for _, tc := range []struct {
		name string
		url  string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{name: "keys", url: "/keys?api-version=7.4&$maxresults=1", fn: h.listKeys},
		{name: "deleted-keys", url: "/deletedkeys?api-version=7.4&$maxresults=1", fn: h.listDeletedKeys},
		{name: "deleted-secrets", url: "/deletedsecrets?api-version=7.4&$maxresults=1", fn: h.listDeletedSecrets},
		{name: "certificates", url: "/certificates?api-version=7.4&$maxresults=1", fn: h.listCertificates},
		{name: "deleted-certificates", url: "/deletedcertificates?api-version=7.4&$maxresults=1", fn: h.listDeletedCertificates},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.Host = "myvault.vault.azure.net:443"
			tc.fn(rec, req)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "nextLink") {
				t.Fatalf("unexpected response code=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "myvault.vault.azure.net:443"
	req.TLS = &tls.ConnectionState{}
	if got := h.vaultBaseURL(req); got != "https://myvault.vault.azure.net" {
		t.Fatalf("unexpected tls base url %q", got)
	}
	next := "1"
	link := h.buildNextLink(httptest.NewRequest(http.MethodGet, "/keys?$maxresults=1", nil), &next)
	if link == nil || !strings.Contains(*link, "api-version=7.4") {
		t.Fatalf("unexpected link %v", link)
	}
	for _, path := range []string{"/keys/name", "/keys/name/unknown"} {
		rec := httptest.NewRecorder()
		h.handleKeyPost(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`)), "name", splitPath(path, "/keys/"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unexpected handleKeyPost code=%d body=%s", rec.Code, rec.Body.String())
		}
	}
}

func TestListHandlersInvalidSkipToken(t *testing.T) {
	h := New(store.New())
	for _, tc := range []struct {
		name string
		url  string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{name: "listKeys", url: "/keys?$skiptoken=bad", fn: h.listKeys},
		{name: "listSecrets", url: "/secrets?$skiptoken=bad", fn: h.listSecrets},
		{name: "listDeletedKeys", url: "/deletedkeys?$skiptoken=bad", fn: h.listDeletedKeys},
		{name: "listDeletedSecrets", url: "/deletedsecrets?$skiptoken=bad", fn: h.listDeletedSecrets},
		{name: "listCertificates", url: "/certificates?$skiptoken=bad", fn: h.listCertificates},
		{name: "listDeletedCertificates", url: "/deletedcertificates?$skiptoken=bad", fn: h.listDeletedCertificates},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.fn(rec, httptest.NewRequest(http.MethodGet, tc.url, nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 got %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
