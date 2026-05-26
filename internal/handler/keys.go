package handler

import (
	"net/http"
	"strings"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

func (h *Handler) registerKeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /keys", h.listKeys)
	mux.HandleFunc("POST /keys/", h.handleKeyRoutes)
	mux.HandleFunc("GET /keys/", h.handleKeyRoutes)
	mux.HandleFunc("DELETE /keys/", h.handleKeyRoutes)
	mux.HandleFunc("PATCH /keys/", h.handleKeyRoutes)
	mux.HandleFunc("GET /deletedkeys", h.listDeletedKeys)
	mux.HandleFunc("GET /deletedkeys/", h.handleDeletedKeyRoutes)
	mux.HandleFunc("DELETE /deletedkeys/", h.handleDeletedKeyRoutes)
	mux.HandleFunc("POST /deletedkeys/", h.handleDeletedKeyRoutes)
}

func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListKeys(maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.KeyItem, 0, len(records))
	baseURL := h.vaultBaseURL(r)
	for _, record := range records {
		items = append(items, model.KeyItem{
			Kid:        keyID(baseURL, record.Name, record.Version),
			Attributes: record.Attributes,
			Tags:       record.Tags,
		})
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.KeyItem]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) handleKeyRoutes(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(r.URL.Path, "/keys/")
	if len(segments) < 1 {
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
		return
	}
	name := segments[0]
	switch r.Method {
	case http.MethodPost:
		h.handleKeyPost(w, r, name, segments)
	case http.MethodGet:
		h.handleKeyGet(w, r, name, segments)
	case http.MethodDelete:
		if len(segments) != 1 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		record, err := h.store.DeleteKey(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.deletedKeyBundle(r, record))
	case http.MethodPatch:
		if len(segments) != 2 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		var req model.UpdateKeyRequest
		if err := h.parseBody(r, &req); err != nil {
			h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
			return
		}
		record, err := h.store.UpdateKey(name, segments[1], req)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.keyBundle(r, record))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleKeyPost(w http.ResponseWriter, r *http.Request, name string, segments []string) {
	if len(segments) == 2 {
		switch segments[1] {
		case "create":
			var req model.CreateKeyRequest
			if err := h.parseBody(r, &req); err != nil {
				h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
				return
			}
			record, err := h.store.CreateKey(name, req)
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, h.keyBundle(r, record))
			return
		case "import":
			var req model.ImportKeyRequest
			if err := h.parseBody(r, &req); err != nil {
				h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
				return
			}
			record, err := h.store.ImportKey(name, req)
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, h.keyBundle(r, record))
			return
		}
	}
	if len(segments) != 3 {
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
		return
	}
	version, operation := segments[1], strings.ToLower(segments[2])
	switch operation {
	case "encrypt", "decrypt":
		var req model.EncryptRequest
		if err := h.parseBody(r, &req); err != nil {
			h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
			return
		}
		var value, iv string
		var err error
		if operation == "encrypt" {
			value, iv, err = h.store.Encrypt(name, version, req)
		} else {
			value, iv, err = h.store.Decrypt(name, version, req)
		}
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, model.CryptoResponse{Kid: keyID(h.vaultBaseURL(r), name, version), Value: value, Alg: req.Alg, IV: iv})
	case "sign":
		var req model.SignRequest
		if err := h.parseBody(r, &req); err != nil {
			h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
			return
		}
		value, err := h.store.Sign(name, version, req)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, model.CryptoResponse{Kid: keyID(h.vaultBaseURL(r), name, version), Value: value, Alg: req.Alg})
	case "verify":
		var req model.VerifyRequest
		if err := h.parseBody(r, &req); err != nil {
			h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
			return
		}
		ok, err := h.store.Verify(name, version, req)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, model.VerifyResponse{Value: ok})
	case "wrapkey", "unwrapkey":
		var req model.EncryptRequest
		if err := h.parseBody(r, &req); err != nil {
			h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
			return
		}
		var value string
		var err error
		if operation == "wrapkey" {
			value, err = h.store.WrapKey(name, version, req)
		} else {
			value, err = h.store.UnwrapKey(name, version, req)
		}
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, model.CryptoResponse{Kid: keyID(h.vaultBaseURL(r), name, version), Value: value, Alg: req.Alg})
	default:
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
	}
}

func (h *Handler) handleKeyGet(w http.ResponseWriter, r *http.Request, name string, segments []string) {
	switch len(segments) {
	case 1:
		record, err := h.store.GetKey(name, "")
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.keyBundle(r, record))
	case 2:
		if segments[1] == "versions" {
			h.listKeyVersions(w, r, name)
			return
		}
		record, err := h.store.GetKey(name, segments[1])
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.keyBundle(r, record))
	default:
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
	}
}

func (h *Handler) listKeyVersions(w http.ResponseWriter, r *http.Request, name string) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListKeyVersions(name, maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.KeyItem, 0, len(records))
	baseURL := h.vaultBaseURL(r)
	for _, record := range records {
		items = append(items, model.KeyItem{Kid: keyID(baseURL, record.Name, record.Version), Attributes: record.Attributes, Tags: record.Tags})
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.KeyItem]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) listDeletedKeys(w http.ResponseWriter, r *http.Request) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListDeletedKeys(maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.DeletedKeyBundle, 0, len(records))
	for _, record := range records {
		items = append(items, h.deletedKeyBundle(r, record))
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.DeletedKeyBundle]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) handleDeletedKeyRoutes(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(r.URL.Path, "/deletedkeys/")
	if len(segments) == 0 {
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
		return
	}
	name := segments[0]
	switch r.Method {
	case http.MethodGet:
		if len(segments) != 1 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		record, err := h.store.GetDeletedKey(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.deletedKeyBundle(r, record))
	case http.MethodDelete:
		if len(segments) != 1 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		if err := h.store.PurgeDeletedKey(name); err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusNoContent, nil)
	case http.MethodPost:
		if len(segments) != 2 || segments[1] != "recover" {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		record, err := h.store.RecoverDeletedKey(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.keyBundle(r, record))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) keyBundle(r *http.Request, record store.KeyRecord) model.KeyBundle {
	baseURL := h.vaultBaseURL(r)
	key := record.Key
	key.Kid = keyID(baseURL, record.Name, record.Version)
	return model.KeyBundle{Key: key, Attributes: record.Attributes, Tags: record.Tags}
}

func (h *Handler) deletedKeyBundle(r *http.Request, record store.DeletedKeyRecord) model.DeletedKeyBundle {
	bundle := h.keyBundle(r, record.KeyRecord)
	return model.DeletedKeyBundle{
		KeyBundle:          bundle,
		RecoveryID:         recoveryID(h.vaultBaseURL(r), record.RecoveryID),
		DeletedDate:        record.DeletedDate,
		ScheduledPurgeDate: record.ScheduledPurgeDate,
	}
}

func keyID(baseURL, name, version string) string {
	if version == "" {
		return baseURL + "/keys/" + name
	}
	return baseURL + "/keys/" + name + "/" + version
}
