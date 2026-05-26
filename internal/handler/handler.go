package handler

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

type Handler struct {
	store store.Storer
}

func New(s store.Storer) *Handler {
	return &Handler{store: s}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.healthz)
	h.registerSecretRoutes(mux)
	h.registerKeyRoutes(mux)
	h.registerCertificateRoutes(mux)
	mux.HandleFunc("/", h.handleNotFound)
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) handleNotFound(w http.ResponseWriter, r *http.Request) {
	h.writeError(w, store.NewError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
}

func (h *Handler) parseBody(r *http.Request, dst any) error {
	if r.Body == nil {
		return fmt.Errorf("request body is required")
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return err
	}
	return nil
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	if kvErr, ok := err.(*store.Error); ok {
		h.writeJSON(w, kvErr.Status, model.NewKeyVaultError(kvErr.Code, kvErr.Message))
		return
	}
	h.writeJSON(w, http.StatusInternalServerError, model.NewKeyVaultError("InternalServerError", err.Error()))
}

func (h *Handler) vaultBaseURL(r *http.Request) string {
	host := r.Host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	if host == "" || !strings.Contains(host, ".vault.") {
		host = "emulator"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + host
}

func (h *Handler) parsePagination(r *http.Request) (int, string, error) {
	maxResults := 25
	query := r.URL.Query()
	if raw := query.Get("$maxresults"); raw == "" {
		raw = query.Get("maxresults")
		if raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				return 0, "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided maxresults value is invalid.")
			}
			maxResults = parsed
		}
	} else {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return 0, "", store.NewError(http.StatusBadRequest, "BadParameter", "The provided $maxresults value is invalid.")
		}
		maxResults = parsed
	}
	if maxResults > 100 {
		maxResults = 100
	}
	skip := query.Get("$skiptoken")
	if skip == "" {
		skip = query.Get("skiptoken")
	}
	return maxResults, skip, nil
}

func (h *Handler) buildNextLink(r *http.Request, next *string) *string {
	if next == nil {
		return nil
	}
	query := cloneValues(r.URL.Query())
	query.Set("$skiptoken", *next)
	if query.Get("api-version") == "" {
		query.Set("api-version", "7.4")
	}
	link := h.vaultBaseURL(r) + r.URL.Path + "?" + query.Encode()
	return &link
}

func cloneValues(values url.Values) url.Values {
	out := url.Values{}
	for key, current := range values {
		copied := append([]string(nil), current...)
		out[key] = copied
	}
	return out
}

func splitPath(path, prefix string) []string {
	trimmed := strings.TrimPrefix(path, prefix)
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func modelError(status int, code, message string) error {
	return store.NewError(status, code, message)
}

func recoveryID(baseURL, recoveryPath string) string {
	if strings.HasPrefix(recoveryPath, "http://") || strings.HasPrefix(recoveryPath, "https://") {
		return recoveryPath
	}
	if strings.HasPrefix(recoveryPath, "/") {
		return baseURL + recoveryPath
	}
	return baseURL + "/" + recoveryPath
}
