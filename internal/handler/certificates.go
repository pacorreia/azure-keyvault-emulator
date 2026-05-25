package handler

import (
	"crypto/sha1"
	"net/http"

	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

func (h *Handler) registerCertificateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /certificates", h.listCertificates)
	mux.HandleFunc("POST /certificates/", h.handleCertificateRoutes)
	mux.HandleFunc("GET /certificates/", h.handleCertificateRoutes)
	mux.HandleFunc("DELETE /certificates/", h.handleCertificateRoutes)
	mux.HandleFunc("PATCH /certificates/", h.handleCertificateRoutes)
	mux.HandleFunc("GET /deletedcertificates", h.listDeletedCertificates)
	mux.HandleFunc("GET /deletedcertificates/", h.handleDeletedCertificateRoutes)
	mux.HandleFunc("DELETE /deletedcertificates/", h.handleDeletedCertificateRoutes)
	mux.HandleFunc("POST /deletedcertificates/", h.handleDeletedCertificateRoutes)
}

func (h *Handler) listCertificates(w http.ResponseWriter, r *http.Request) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListCertificates(maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.CertificateItem, 0, len(records))
	for _, record := range records {
		items = append(items, h.certificateItem(r, record))
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.CertificateItem]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) handleCertificateRoutes(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(r.URL.Path, "/certificates/")
	if len(segments) == 0 {
		h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
		return
	}
	name := segments[0]
	switch r.Method {
	case http.MethodPost:
		if len(segments) != 2 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		switch segments[1] {
		case "create":
			var req model.CreateCertificateRequest
			if err := h.parseBody(r, &req); err != nil {
				h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
				return
			}
			record, err := h.store.CreateCertificate(name, req)
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, h.certificateBundle(r, record))
		case "import":
			var req model.ImportCertificateRequest
			if err := h.parseBody(r, &req); err != nil {
				h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
				return
			}
			record, err := h.store.ImportCertificate(name, req)
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, h.certificateBundle(r, record))
		default:
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
		}
	case http.MethodGet:
		switch len(segments) {
		case 1:
			record, err := h.store.GetCertificate(name, "")
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, h.certificateBundle(r, record))
		case 2:
			switch segments[1] {
			case "versions":
				h.listCertificateVersions(w, r, name)
			case "policy":
				policy, err := h.store.GetCertificatePolicy(name)
				if err != nil {
					h.writeError(w, err)
					return
				}
				h.writeJSON(w, http.StatusOK, policy)
			case "pending":
				op, err := h.store.GetPendingCertificateOperation(name)
				if err != nil {
					h.writeError(w, err)
					return
				}
				h.writeJSON(w, http.StatusOK, op)
			default:
				record, err := h.store.GetCertificate(name, segments[1])
				if err != nil {
					h.writeError(w, err)
					return
				}
				h.writeJSON(w, http.StatusOK, h.certificateBundle(r, record))
			}
		default:
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
		}
	case http.MethodPatch:
		if len(segments) == 2 && segments[1] == "policy" {
			var req model.CreateCertificateRequest
			if err := h.parseBody(r, &req); err != nil {
				h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
				return
			}
			policy, err := h.store.UpdateCertificatePolicy(name, req.Policy)
			if err != nil {
				h.writeError(w, err)
				return
			}
			h.writeJSON(w, http.StatusOK, policy)
			return
		}
		if len(segments) != 2 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		var req model.UpdateCertificateRequest
		if err := h.parseBody(r, &req); err != nil {
			h.writeError(w, modelError(http.StatusBadRequest, "BadParameter", err.Error()))
			return
		}
		record, err := h.store.UpdateCertificate(name, segments[1], req)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.certificateBundle(r, record))
	case http.MethodDelete:
		if len(segments) != 1 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		record, err := h.store.DeleteCertificate(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.deletedCertificateBundle(r, record))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) listCertificateVersions(w http.ResponseWriter, r *http.Request, name string) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListCertificateVersions(name, maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.CertificateItem, 0, len(records))
	for _, record := range records {
		items = append(items, h.certificateItem(r, record))
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.CertificateItem]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) listDeletedCertificates(w http.ResponseWriter, r *http.Request) {
	maxResults, skip, err := h.parsePagination(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	records, next, err := h.store.ListDeletedCertificates(maxResults, skip)
	if err != nil {
		h.writeError(w, err)
		return
	}
	items := make([]model.DeletedCertificateBundle, 0, len(records))
	for _, record := range records {
		items = append(items, h.deletedCertificateBundle(r, record))
	}
	h.writeJSON(w, http.StatusOK, model.ListResult[model.DeletedCertificateBundle]{Value: items, NextLink: h.buildNextLink(r, next)})
}

func (h *Handler) handleDeletedCertificateRoutes(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(r.URL.Path, "/deletedcertificates/")
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
		record, err := h.store.GetDeletedCertificate(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.deletedCertificateBundle(r, record))
	case http.MethodDelete:
		if len(segments) != 1 {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		if err := h.store.PurgeDeletedCertificate(name); err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusNoContent, nil)
	case http.MethodPost:
		if len(segments) != 2 || segments[1] != "recover" {
			h.writeError(w, modelError(http.StatusNotFound, "NotFound", "The requested resource was not found."))
			return
		}
		record, err := h.store.RecoverDeletedCertificate(name)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, h.certificateBundle(r, record))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *Handler) certificateBundle(r *http.Request, record store.CertificateRecord) model.CertificateBundle {
	baseURL := h.vaultBaseURL(r)
	return model.CertificateBundle{
		ID:         certificateID(baseURL, record.Name, record.Version),
		Kid:        keyID(baseURL, record.Name, record.Version),
		Sid:        secretID(baseURL, record.Name, record.Version),
		Cer:        kvcrypto.EncodeBase64URL(record.Cer),
		Attributes: record.Attributes,
		Tags:       record.Tags,
		Policy:     record.Policy,
	}
}

func (h *Handler) certificateItem(r *http.Request, record store.CertificateRecord) model.CertificateItem {
	sum := sha1.Sum(record.Cer)
	baseURL := h.vaultBaseURL(r)
	return model.CertificateItem{
		ID:         certificateID(baseURL, record.Name, record.Version),
		Kid:        keyID(baseURL, record.Name, record.Version),
		Sid:        secretID(baseURL, record.Name, record.Version),
		X5t:        kvcrypto.EncodeBase64URL(sum[:]),
		Attributes: record.Attributes,
		Tags:       record.Tags,
	}
}

func (h *Handler) deletedCertificateBundle(r *http.Request, record store.DeletedCertificateRecord) model.DeletedCertificateBundle {
	bundle := h.certificateBundle(r, record.CertificateRecord)
	return model.DeletedCertificateBundle{
		CertificateBundle:  bundle,
		RecoveryID:         recoveryID(h.vaultBaseURL(r), record.RecoveryID),
		DeletedDate:        record.DeletedDate,
		ScheduledPurgeDate: record.ScheduledPurgeDate,
	}
}

func certificateID(baseURL, name, version string) string {
	if version == "" {
		return baseURL + "/certificates/" + name
	}
	return baseURL + "/certificates/" + name + "/" + version
}
