package web

import (
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pacorreia/azure-keyvault-emulator/internal/auth"
	"github.com/pacorreia/azure-keyvault-emulator/internal/encryption"
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
	Name        string `json:"name"`
	Version     string `json:"version"`
	Enabled     bool   `json:"enabled"`
	ContentType string `json:"contentType"`
}

type keyResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kty     string `json:"kty"`
	Crv     string `json:"crv"`
	Kid     string `json:"kid"`
}

type certificateResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func New(a *auth.Service, s store.Storer) *Handler {
	h := &Handler{auth: a}
	h.kvStore = newEncryptedStore(s, h.getEncryptionKey)
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
	mux.HandleFunc("GET /ui/api/keys", h.requireSession(h.handleListKeys))
	mux.HandleFunc("GET /ui/api/certificates", h.requireSession(h.handleListCertificates))
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
	if _, ok := h.auth.GetConfig("enc_salt"); !ok {
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

	saltHex, ok := h.auth.GetConfig("enc_salt")
	if !ok {
		h.writeError(w, http.StatusBadRequest, "encryption not configured")
		return
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "invalid encryption salt")
		return
	}

	encVerify, ok := h.auth.GetConfig("enc_verify")
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
		Secure:   isSecureRequest(r),
		Expires:  time.Unix(session.ExpiresAt, 0),
		SameSite: http.SameSiteLaxMode,
	})
	h.writeJSON(w, http.StatusOK, authResponse{Username: session.Username, Role: session.Role})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		h.auth.Logout(cookie.Value)
	}
	h.clearSessionCookie(w, r)
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
			Name:    record.Name,
			Version: record.Version,
			Kty:     record.Key.Kty,
			Crv:     record.Key.Crv,
			Kid:     record.Key.Kid,
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
		response = append(response, certificateResponse{Name: record.Name, Version: record.Version})
	}
	h.writeJSON(w, http.StatusOK, response)
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

func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/ui",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}

func isSecureRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
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
