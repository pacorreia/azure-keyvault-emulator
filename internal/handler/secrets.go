package handler

import (
	"net/http"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

type restoreRequest struct {
	Value string `json:"value"`
}

func (h *Handler) registerSecretRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /secrets", h.listSecrets)
	mux.HandleFunc("POST /secrets/restore", h.restoreSecret)
	mux.HandleFunc("PUT /secrets/", h.handleSecretRoutes)
	mux.HandleFunc("GET /secrets/", h.handleSecretRoutes)
	mux.HandleFunc("DELETE /secrets/", h.handleSecretRoutes)
	mux.HandleFunc("PATCH /secrets/", h.handleSecretRoutes)
	mux.HandleFunc("POST /secrets/", h.handleSecretRoutes)
	mux.HandleFunc("GET /deletedsecrets", h.listDeletedSecrets)
	mux.HandleFunc("GET /deletedsecrets/", h.handleDeletedSecretRoutes)
	mux.HandleFunc("DELETE /deletedsecrets/", h.handleDeletedSecretRoutes)
	mux.HandleFunc("POST /deletedsecrets/", h.handleDeletedSecretRoutes)
}

func (h *Handler) listSecrets(w http.ResponseWriter, r *http.Request) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListSecrets(maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.SecretItem, 0, len(records))
	baseURL := h.vaultBaseURL(r)
	for _, record := range records {
		items = append(items, model.SecretItem{
			ID:          secretID(baseURL, record.Name, record.Version),
			ContentType: record.ContentType,
			Attributes:  record.Attributes,
			Tags:        record.Tags,
		})
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.SecretItem]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) handleSecretRoutes(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(r.URL.Path, "/secrets/")
	if len(segments) == 0 {
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
		return
	}
	name := segments[0]
	switch r.Method {
	case http.MethodPut:
		if len(segments) != 1 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		var req model.SecretSetRequest
		if err := h.parseBody(r, &req); err != nil {
			h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
			return
		}
		record, err := h.store.SetSecret(name, req)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.secretBundle(r, record))
	case http.MethodGet:
		if len(segments) == 1 {
			record, err := h.store.GetSecret(name, "")
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, h.secretBundle(r, record))
			return
		}
		if len(segments) == 2 && segments[1] == "versions" {
			h.listSecretVersions(w, r, name)
			return
		}
		if len(segments) == 2 {
			record, err := h.store.GetSecret(name, segments[1])
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, h.secretBundle(r, record))
			return
		}
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
	case http.MethodDelete:
		if len(segments) != 1 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		record, err := h.store.DeleteSecret(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.deletedSecretBundle(r, record))
	case http.MethodPatch:
		if len(segments) != 2 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		var req model.SecretUpdateRequest
		if err := h.parseBody(r, &req); err != nil {
			h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
			return
		}
		record, err := h.store.UpdateSecret(name, segments[1], req)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.secretBundle(r, record))
	case http.MethodPost:
		if len(segments) == 2 && segments[1] == "backup" {
			backup, err := h.store.BackupSecret(name)
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, map[string]string{"value": backup})
			return
		}
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) listSecretVersions(w http.ResponseWriter, r *http.Request, name string) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListSecretVersions(name, maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.SecretItem, 0, len(records))
	baseURL := h.vaultBaseURL(r)
	for _, record := range records {
		items = append(items, model.SecretItem{
			ID:          secretID(baseURL, record.Name, record.Version),
			ContentType: record.ContentType,
			Attributes:  record.Attributes,
			Tags:        record.Tags,
		})
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.SecretItem]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) listDeletedSecrets(w http.ResponseWriter, r *http.Request) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListDeletedSecrets(maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.DeletedSecretBundle, 0, len(records))
	for _, record := range records {
		items = append(items, h.deletedSecretBundle(r, record))
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.DeletedSecretBundle]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) handleDeletedSecretRoutes(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(r.URL.Path, "/deletedsecrets/")
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
		record, err := h.store.GetDeletedSecret(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.deletedSecretBundle(r, record))
	case http.MethodDelete:
		if len(segments) != 1 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		if err := h.store.PurgeDeletedSecret(name); err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusNoContent, nil)
	case http.MethodPost:
		if len(segments) != 2 || segments[1] != "recover" {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		record, err := h.store.RecoverDeletedSecret(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.secretBundle(r, record))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) restoreSecret(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := h.parseBody(r, &req); err != nil {
		h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
		return
	}
	record, err := h.store.RestoreSecret(req.Value)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, h.secretBundle(r, record))
}

func (h *Handler) secretBundle(r *http.Request, record store.SecretRecord) model.SecretBundle {
	baseURL := h.vaultBaseURL(r)
	return model.SecretBundle{
		Value:       record.Value,
		ID:          secretID(baseURL, record.Name, record.Version),
		ContentType: record.ContentType,
		Attributes:  record.Attributes,
		Tags:        record.Tags,
	}
}

func (h *Handler) deletedSecretBundle(r *http.Request, record store.DeletedSecretRecord) model.DeletedSecretBundle {
	baseURL := h.vaultBaseURL(r)
	return model.DeletedSecretBundle{
		SecretBundle: model.SecretBundle{
			Value:       record.Value,
			ID:          secretID(baseURL, record.Name, record.Version),
			ContentType: record.ContentType,
			Attributes:  record.Attributes,
			Tags:        record.Tags,
		},
		RecoveryID:         recoveryID(baseURL, record.RecoveryID),
		DeletedDate:        record.DeletedDate,
		ScheduledPurgeDate: record.ScheduledPurgeDate,
	}
}

func secretID(baseURL, name, version string) string {
	if version == "" {
		return baseURL + "/secrets/" + name
	}
	return baseURL + "/secrets/" + name + "/" + version
}
