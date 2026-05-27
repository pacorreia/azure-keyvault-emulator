package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pacorreia/azure-keyvault-emulator/internal/auth"
	"github.com/pacorreia/azure-keyvault-emulator/internal/encryption"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

//go:embed static
var staticFiles embed.FS

const sessionCookieName = "kv_session"

type contextKey string

const sessionContextKey contextKey = "session"

type Handler struct {
	auth     *auth.Service
	kvStore  store.Storer
	encKey   []byte
	encKeyMu sync.RWMutex
}

type statusResponse struct {
	Initialized bool `json:"initialized"`
	Locked      bool `json:"locked"`
}

type unlockRequest struct {
	Passphrase string `json:"passphrase"`
}

type setupRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Passphrase string `json:"passphrase"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userRequest struct {
	Username string    `json:"username"`
	Password string    `json:"password"`
	Role     auth.Role `json:"role"`
}

type authResponse struct {
	Username string    `json:"username"`
	Role     auth.Role `json:"role"`
}

type userResponse struct {
	ID        string    `json:"id,omitempty"`
	Username  string    `json:"username"`
	Role      auth.Role `json:"role"`
	CreatedAt int64     `json:"createdAt,omitempty"`
}

type secretResponse struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Enabled     bool    `json:"enabled"`
	ContentType string  `json:"contentType"`
	Created     int64   `json:"created,omitempty"`
	Updated     int64   `json:"updated,omitempty"`
	NotBefore   *int64  `json:"notBefore,omitempty"`
	Expires     *int64  `json:"expires,omitempty"`
}

type keyResponse struct {
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	Kty       string  `json:"kty"`
	Crv       string  `json:"crv"`
	Kid       string  `json:"kid"`
	Created   int64   `json:"created,omitempty"`
	Updated   int64   `json:"updated,omitempty"`
	NotBefore *int64  `json:"notBefore,omitempty"`
	Expires   *int64  `json:"expires,omitempty"`
}

type certificateResponse struct {
	Name    string  `json:"name"`
	Version string  `json:"version"`
	Created int64   `json:"created,omitempty"`
	Updated int64   `json:"updated,omitempty"`
	Expires *int64  `json:"expires,omitempty"`
}

type keyDetailResponse struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Kty          string   `json:"kty"`
	Crv          string   `json:"crv,omitempty"`
	Kid          string   `json:"kid"`
	KeyOps       []string `json:"keyOps,omitempty"`
	N            string   `json:"n,omitempty"`
	E            string   `json:"e,omitempty"`
	X            string   `json:"x,omitempty"`
	Y            string   `json:"y,omitempty"`
	PublicKeyPem string   `json:"publicKeyPem,omitempty"`
	Created      int64    `json:"created,omitempty"`
	Updated      int64    `json:"updated,omitempty"`
	NotBefore    *int64   `json:"notBefore,omitempty"`
	Expires      *int64   `json:"expires,omitempty"`
}

type certificateDetailResponse struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Serial     string `json:"serial"`
	Thumbprint string `json:"thumbprint"`
	NotBefore  int64  `json:"notBefore,omitempty"`
	NotAfter   int64  `json:"notAfter,omitempty"`
	Pem        string `json:"pem"`
	Created    int64  `json:"created,omitempty"`
	Updated    int64  `json:"updated,omitempty"`
	Expires    *int64 `json:"expires,omitempty"`
}

func New(a *auth.Service, s store.Storer) *Handler {
	h := &Handler{auth: a}
	h.kvStore = newEncryptedStore(s, h.getEncryptionKey, h.isLocked)
	return h
}

// Store returns the store used by this handler. When a key is configured the
// store transparently encrypts/decrypts secret values, so passing it to the
// main KV API handler ensures encryption-at-rest applies to all write paths.
func (h *Handler) Store() store.Storer {
	return h.kvStore
}

func (h *Handler) Register(mux *http.ServeMux) {
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}

	mux.Handle("GET /ui/static/", http.StripPrefix("/ui/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("GET /ui/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ui/" {
			http.NotFound(w, r)
			return
		}
		h.servePage(w, "index.html")
	})
	mux.HandleFunc("GET /ui/setup", func(w http.ResponseWriter, _ *http.Request) { h.servePage(w, "setup.html") })
	mux.HandleFunc("GET /ui/login", func(w http.ResponseWriter, _ *http.Request) { h.servePage(w, "login.html") })
	mux.HandleFunc("GET /ui/dashboard", func(w http.ResponseWriter, _ *http.Request) { h.servePage(w, "dashboard.html") })

	mux.HandleFunc("GET /ui/api/status", h.handleStatus)
	mux.HandleFunc("POST /ui/api/setup", h.handleSetup)
	mux.HandleFunc("POST /ui/api/unlock", h.handleUnlock)
	mux.HandleFunc("POST /ui/api/login", h.handleLogin)
	mux.HandleFunc("POST /ui/api/logout", h.handleLogout)
	mux.HandleFunc("GET /ui/api/me", h.requireSession(h.handleMe))
	mux.HandleFunc("GET /ui/api/users", h.requireAdmin(h.handleListUsers))
	mux.HandleFunc("POST /ui/api/users", h.requireAdmin(h.handleCreateUser))
	mux.HandleFunc("DELETE /ui/api/users/{id}", h.requireAdmin(h.handleDeleteUser))
	mux.HandleFunc("GET /ui/api/secrets", h.requireSession(h.handleListSecrets))
	mux.HandleFunc("POST /ui/api/secrets", h.requireSession(h.handleCreateSecret))
	mux.HandleFunc("GET /ui/api/secrets/{name}", h.requireSession(h.handleGetSecret))
	mux.HandleFunc("DELETE /ui/api/secrets/{name}", h.requireSession(h.handleDeleteSecret))
	mux.HandleFunc("GET /ui/api/keys", h.requireSession(h.handleListKeys))
	mux.HandleFunc("POST /ui/api/keys", h.requireSession(h.handleCreateKey))
	mux.HandleFunc("GET /ui/api/keys/{name}", h.requireSession(h.handleGetKey))
	mux.HandleFunc("DELETE /ui/api/keys/{name}", h.requireSession(h.handleDeleteKey))
	mux.HandleFunc("GET /ui/api/certificates", h.requireSession(h.handleListCertificates))
	mux.HandleFunc("POST /ui/api/certificates/generate", h.requireSession(h.handleGenerateCertificate))
	mux.HandleFunc("POST /ui/api/certificates/import", h.requireSession(h.handleImportCertificate))
	mux.HandleFunc("GET /ui/api/certificates/{name}", h.requireSession(h.handleGetCertificate))
	mux.HandleFunc("DELETE /ui/api/certificates/{name}", h.requireSession(h.handleDeleteCertificate))
}

func (h *Handler) setEncryptionKey(key []byte) {
	h.encKeyMu.Lock()
	defer h.encKeyMu.Unlock()
	if len(key) == 0 {
		h.encKey = nil
		return
	}
	h.encKey = append([]byte(nil), key...)
}

func (h *Handler) getEncryptionKey() []byte {
	h.encKeyMu.RLock()
	defer h.encKeyMu.RUnlock()
	if len(h.encKey) == 0 {
		return nil
	}
	return append([]byte(nil), h.encKey...)
}

func (h *Handler) servePage(w http.ResponseWriter, name string) {
	data, err := staticFiles.ReadFile(path.Join("static", name))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) handleStatus(w http.ResponseWriter, _ *http.Request) {
	initialized, err := h.auth.IsInitialized()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	locked := initialized && h.isLocked()
	h.writeJSON(w, http.StatusOK, statusResponse{Initialized: initialized, Locked: locked})
}

func (h *Handler) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Passphrase == "" {
		h.writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}

	salt, err := encryption.GenerateSalt()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	key := encryption.DeriveKey(req.Passphrase, salt)
	verify, err := encryption.EncryptString(key, "verify")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	createdUser, err := h.auth.Setup(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrAlreadyInitialized) {
			h.writeError(w, http.StatusConflict, "auth service already initialized")
			return
		}
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rollback := func() {
		if createdUser != nil {
			_ = h.auth.DeleteUser(createdUser.ID)
		}
	}

	if err := h.auth.SetConfig("enc_salt", hex.EncodeToString(salt)); err != nil {
		rollback()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := h.auth.SetConfig("enc_verify", verify); err != nil {
		rollback()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.setEncryptionKey(key)
	h.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// isLocked reports whether encryption is configured (enc_salt is stored) but the
// in-memory key has not yet been loaded. When the server restarts, callers must
// POST /ui/api/unlock with the original passphrase to restore the key.
func (h *Handler) isLocked() bool {
	if h.auth == nil {
		return false
	}
	if _, ok, err := h.auth.GetConfig("enc_salt"); err != nil || !ok {
		return false // encryption not configured; server is not in a locked state
	}
	return len(h.getEncryptionKey()) == 0
}

func (h *Handler) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req unlockRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Passphrase == "" {
		h.writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}

	saltHex, ok, err := h.auth.GetConfig("enc_salt")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read encryption configuration")
		return
	}
	if !ok {
		h.writeError(w, http.StatusBadRequest, "encryption not configured")
		return
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "invalid encryption salt")
		return
	}

	encVerify, ok, err := h.auth.GetConfig("enc_verify")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read encryption configuration")
		return
	}
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "encryption verification token missing")
		return
	}

	key := encryption.DeriveKey(req.Passphrase, salt)
	plaintext, err := encryption.DecryptString(key, encVerify)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "incorrect passphrase")
		return
	}
	if plaintext != "verify" {
		h.writeError(w, http.StatusInternalServerError, "invalid encryption verification token")
		return
	}

	h.setEncryptionKey(key)
	h.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	session, err := h.auth.Login(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			h.writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.Token,
		Path:     "/ui",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Unix(session.ExpiresAt, 0),
		SameSite: http.SameSiteLaxMode,
	})
	h.writeJSON(w, http.StatusOK, authResponse{Username: session.Username, Role: session.Role})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		h.auth.Logout(cookie.Value)
	}
	h.clearSessionCookie(w)
	h.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	h.writeJSON(w, http.StatusOK, authResponse{Username: session.Username, Role: session.Role})
}

func (h *Handler) handleListUsers(w http.ResponseWriter, _ *http.Request) {
	users, err := h.auth.ListUsers()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := make([]userResponse, 0, len(users))
	for _, user := range users {
		response = append(response, userResponse{
			ID:        user.ID,
			Username:  user.Username,
			Role:      user.Role,
			CreatedAt: user.CreatedAt,
		})
	}
	h.writeJSON(w, http.StatusOK, response)
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req userRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !req.Role.Valid() {
		h.writeError(w, http.StatusBadRequest, "invalid role")
		return
	}
	user, err := h.auth.CreateUser(req.Username, req.Password, req.Role)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, userResponse{ID: user.ID, Username: user.Username, Role: user.Role})
}

func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if err := h.auth.DeleteUser(r.PathValue("id")); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleListSecrets(w http.ResponseWriter, _ *http.Request) {
	records, _, err := h.kvStore.ListSecrets(100, "")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := make([]secretResponse, 0, len(records))
	for _, record := range records {
		response = append(response, secretResponse{
			Name:        record.Name,
			Version:     record.Version,
			Enabled:     record.Attributes.Enabled != nil && *record.Attributes.Enabled,
			ContentType: record.ContentType,
			Created:     record.Attributes.Created,
			Updated:     record.Attributes.Updated,
			NotBefore:   record.Attributes.NotBefore,
			Expires:     record.Attributes.Expires,
		})
	}
	h.writeJSON(w, http.StatusOK, response)
}

func (h *Handler) handleListKeys(w http.ResponseWriter, _ *http.Request) {
	records, _, err := h.kvStore.ListKeys(100, "")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := make([]keyResponse, 0, len(records))
	for _, record := range records {
		response = append(response, keyResponse{
			Name:      record.Name,
			Version:   record.Version,
			Kty:       record.Key.Kty,
			Crv:       record.Key.Crv,
			Kid:       record.Key.Kid,
			Created:   record.Attributes.Created,
			Updated:   record.Attributes.Updated,
			NotBefore: record.Attributes.NotBefore,
			Expires:   record.Attributes.Expires,
		})
	}
	h.writeJSON(w, http.StatusOK, response)
}

func (h *Handler) handleListCertificates(w http.ResponseWriter, _ *http.Request) {
	records, _, err := h.kvStore.ListCertificates(100, "")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := make([]certificateResponse, 0, len(records))
	for _, record := range records {
		response = append(response, certificateResponse{
			Name:    record.Name,
			Version: record.Version,
			Created: record.Attributes.Created,
			Updated: record.Attributes.Updated,
			Expires: record.Attributes.Expires,
		})
	}
	h.writeJSON(w, http.StatusOK, response)
}

type createSecretRequest struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	ContentType string `json:"contentType"`
	NotBefore   *int64 `json:"notBefore,omitempty"`
	Expires     *int64 `json:"expires,omitempty"`
}

type createKeyRequest struct {
	Name      string `json:"name"`
	Kty       string `json:"kty"`
	KeySize   int    `json:"keySize"`
	Crv       string `json:"crv"`
	NotBefore *int64 `json:"notBefore,omitempty"`
	Expires   *int64 `json:"expires,omitempty"`
}

type secretDetailResponse struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Value       string  `json:"value"`
	Enabled     bool    `json:"enabled"`
	ContentType string  `json:"contentType"`
	Created     int64   `json:"created,omitempty"`
	Updated     int64   `json:"updated,omitempty"`
	NotBefore   *int64  `json:"notBefore,omitempty"`
	Expires     *int64  `json:"expires,omitempty"`
}

func (h *Handler) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	var req createSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	record, err := h.kvStore.SetSecret(req.Name, model.SecretSetRequest{
		Value:       req.Value,
		ContentType: req.ContentType,
		Attributes: &model.Attributes{
			NotBefore: req.NotBefore,
			Expires:   req.Expires,
		},
	})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, secretResponse{
		Name:        record.Name,
		Version:     record.Version,
		Enabled:     record.Attributes.Enabled != nil && *record.Attributes.Enabled,
		ContentType: record.ContentType,
		Created:     record.Attributes.Created,
		Updated:     record.Attributes.Updated,
		NotBefore:   record.Attributes.NotBefore,
		Expires:     record.Attributes.Expires,
	})
}

func (h *Handler) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	record, err := h.kvStore.GetSecret(name, "")
	if err != nil {
		h.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, secretDetailResponse{
		Name:        record.Name,
		Version:     record.Version,
		Value:       record.Value,
		Enabled:     record.Attributes.Enabled != nil && *record.Attributes.Enabled,
		ContentType: record.ContentType,
		Created:     record.Attributes.Created,
		Updated:     record.Attributes.Updated,
		NotBefore:   record.Attributes.NotBefore,
		Expires:     record.Attributes.Expires,
	})
}

func (h *Handler) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := h.kvStore.DeleteSecret(name); err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req createKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Kty == "" {
		h.writeError(w, http.StatusBadRequest, "kty is required")
		return
	}
	record, err := h.kvStore.CreateKey(req.Name, model.CreateKeyRequest{
		Kty:     req.Kty,
		KeySize: req.KeySize,
		Crv:     req.Crv,
		Attributes: &model.Attributes{
			NotBefore: req.NotBefore,
			Expires:   req.Expires,
		},
	})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, keyResponse{
		Name:      record.Name,
		Version:   record.Version,
		Kty:       record.Key.Kty,
		Crv:       record.Key.Crv,
		Kid:       record.Key.Kid,
		Created:   record.Attributes.Created,
		Updated:   record.Attributes.Updated,
		NotBefore: record.Attributes.NotBefore,
		Expires:   record.Attributes.Expires,
	})
}

func (h *Handler) handleGetKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	record, err := h.kvStore.GetKey(name, "")
	if err != nil {
		h.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	resp := keyDetailResponse{
		Name:      record.Name,
		Version:   record.Version,
		Kty:       record.Key.Kty,
		Crv:       record.Key.Crv,
		Kid:       record.Key.Kid,
		KeyOps:    record.Key.KeyOps,
		N:         record.Key.N,
		E:         record.Key.E,
		X:         record.Key.X,
		Y:         record.Key.Y,
		Created:   record.Attributes.Created,
		Updated:   record.Attributes.Updated,
		NotBefore: record.Attributes.NotBefore,
		Expires:   record.Attributes.Expires,
	}
	if pemBytes := publicKeyToPEM(record.Key); len(pemBytes) > 0 {
		resp.PublicKeyPem = string(pemBytes)
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// publicKeyToPEM reconstructs the public key from a JWK and returns its
// PKIX-encoded PEM representation. Returns nil for symmetric (oct) keys.
func publicKeyToPEM(jwk model.JSONWebKey) []byte {
	var pub any
	switch jwk.Kty {
	case "RSA", "RSA-HSM":
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil || len(nBytes) == 0 {
			return nil
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil || len(eBytes) == 0 {
			return nil
		}
		pub = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	case "EC", "EC-HSM":
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil || len(xBytes) == 0 {
			return nil
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil || len(yBytes) == 0 {
			return nil
		}
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil
		}
		pub = &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
	default:
		return nil
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func (h *Handler) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := h.kvStore.DeleteKey(name); err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := h.kvStore.DeleteCertificate(name); err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type generateCertificateRequest struct {
	Name           string  `json:"name"`
	CommonName     string  `json:"commonName,omitempty"`
	Organization   string  `json:"organization,omitempty"`
	Country        string  `json:"country,omitempty"`
	State          string  `json:"state,omitempty"`
	Locality       string  `json:"locality,omitempty"`
	ValidityMonths float64 `json:"validityMonths,omitempty"`
	CertType       string  `json:"certType,omitempty"`   // "CA", "intermediate", or "leaf"
	IssuerName     string  `json:"issuerName,omitempty"` // name of signing cert already in vault
}

type importCertificateRequest struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Password string `json:"password,omitempty"`
}

func (h *Handler) handleGenerateCertificate(w http.ResponseWriter, r *http.Request) {
	var req generateCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	cn := req.CommonName
	if cn == "" {
		cn = req.Name
	}
	subjectParts := []string{"CN=" + cn}
	if req.Organization != "" {
		subjectParts = append(subjectParts, "O="+req.Organization)
	}
	if req.Country != "" {
		subjectParts = append(subjectParts, "C="+req.Country)
	}
	if req.State != "" {
		subjectParts = append(subjectParts, "ST="+req.State)
	}
	if req.Locality != "" {
		subjectParts = append(subjectParts, "L="+req.Locality)
	}
	x509Props := map[string]any{
		"subject": strings.Join(subjectParts, ", "),
	}
	if req.ValidityMonths > 0 {
		x509Props["validity_months"] = req.ValidityMonths
	}
	certType := req.CertType
	if certType == "" {
		certType = "CA"
	}
	x509Props["cert_type"] = certType
	if req.IssuerName != "" {
		x509Props["issuer_name"] = req.IssuerName
	}
	policy := &model.CertificatePolicy{X509Props: x509Props}
	record, err := h.kvStore.CreateCertificate(req.Name, model.CreateCertificateRequest{Policy: policy})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, certificateResponse{
		Name:    record.Name,
		Version: record.Version,
		Created: record.Attributes.Created,
		Updated: record.Attributes.Updated,
		Expires: record.Attributes.Expires,
	})
}

func (h *Handler) handleImportCertificate(w http.ResponseWriter, r *http.Request) {
	var req importCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Value == "" {
		h.writeError(w, http.StatusBadRequest, "certificate value is required")
		return
	}
	record, err := h.kvStore.ImportCertificate(req.Name, model.ImportCertificateRequest{
		Value:    req.Value,
		Password: req.Password,
	})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, certificateResponse{
		Name:    record.Name,
		Version: record.Version,
		Created: record.Attributes.Created,
		Updated: record.Attributes.Updated,
		Expires: record.Attributes.Expires,
	})
}

func (h *Handler) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	record, err := h.kvStore.GetCertificate(name, "")
	if err != nil {
		h.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	resp := certificateDetailResponse{
		Name:    record.Name,
		Version: record.Version,
		Created: record.Attributes.Created,
		Updated: record.Attributes.Updated,
		Expires: record.Attributes.Expires,
	}
	if len(record.Cer) > 0 {
		cert, parseErr := x509.ParseCertificate(record.Cer)
		if parseErr == nil {
			resp.Subject = cert.Subject.String()
			resp.Issuer = cert.Issuer.String()
			resp.Serial = cert.SerialNumber.String()
			sum := sha1.Sum(record.Cer)
			resp.Thumbprint = hex.EncodeToString(sum[:])
			resp.NotBefore = cert.NotBefore.Unix()
			resp.NotAfter = cert.NotAfter.Unix()
		}
		resp.Pem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: record.Cer}))
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			h.writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		session, ok := h.auth.ValidateSession(cookie.Value)
		if !ok {
			h.writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionContextKey, session)))
	}
}

func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return h.requireSession(func(w http.ResponseWriter, r *http.Request) {
		session := sessionFromContext(r.Context())
		if session == nil || session.Role != auth.RoleAdmin {
			h.writeError(w, http.StatusForbidden, "admin access required")
			return
		}
		next(w, r)
	})
}

func sessionFromContext(ctx context.Context) *auth.Session {
	session, _ := ctx.Value(sessionContextKey).(*auth.Session)
	return session
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
		}
		return err
	}
	return nil
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/ui",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, map[string]string{"error": message})
}
