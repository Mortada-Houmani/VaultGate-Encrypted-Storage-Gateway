package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/crypto"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/envelope"
	"github.com/Mortada-Houmani/VaultGate-Encrypted-Storage-Gateway/pkg/storage"
)

// JSONUploadRequest represents an optional JSON payload format for uploads.
type JSONUploadRequest struct {
	ObjectID string `json:"object_id,omitempty"`
	Data     string `json:"data"`
	Encoding string `json:"encoding,omitempty"` // "base64" (default) or "plain"
}

// ErrorResponse represents a structured JSON error format.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// ReWrapRequest represents the payload for rotating a key on an existing object.
type ReWrapRequest struct {
	NewKMSKeyID string `json:"new_kms_key_id"`
}

// DeleteResponse represents a successful deletion response.
type DeleteResponse struct {
	Status   string `json:"status"`
	ObjectID string `json:"object_id"`
}

// Handler contains HTTP handler methods for the VaultGate API.
type Handler struct {
	gateway *GatewayService
}

// NewHandler instantiates an API HTTP handler.
func NewHandler(gateway *GatewayService) *Handler {
	return &Handler{gateway: gateway}
}

// Upload handles POST /objects and POST /api/v1/objects.
// It supports binary payloads, JSON payloads, and multipart/form-data.
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, errors.New("method not allowed"), http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}

	var objectID string
	var plaintext []byte
	contentType := r.Header.Get("Content-Type")

	// Extract object ID from query param or header if provided
	if qID := r.URL.Query().Get("id"); qID != "" {
		objectID = qID
	} else if hID := r.Header.Get("X-Object-ID"); hID != "" {
		objectID = hID
	}

	switch {
	case strings.HasPrefix(contentType, "application/json"):
		var req JSONUploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, err, http.StatusBadRequest, "INVALID_JSON")
			return
		}
		if req.ObjectID != "" {
			objectID = req.ObjectID
		}
		if strings.EqualFold(req.Encoding, "plain") || strings.EqualFold(req.Encoding, "text") {
			plaintext = []byte(req.Data)
		} else {
			// Default to base64 decoding
			decoded, err := base64.StdEncoding.DecodeString(req.Data)
			if err != nil {
				// Fallback to raw string bytes if not valid base64
				plaintext = []byte(req.Data)
			} else {
				plaintext = decoded
			}
		}

	case strings.HasPrefix(contentType, "multipart/form-data"):
		// 32MB max memory
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			h.writeError(w, err, http.StatusBadRequest, "INVALID_MULTIPART")
			return
		}
		if formID := r.FormValue("object_id"); formID != "" {
			objectID = formID
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			h.writeError(w, errors.New("missing 'file' field in multipart form"), http.StatusBadRequest, "MISSING_FILE")
			return
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			h.writeError(w, err, http.StatusInternalServerError, "FILE_READ_FAILED")
			return
		}
		plaintext = data

	default:
		// Raw binary stream
		data, err := io.ReadAll(r.Body)
		if err != nil {
			h.writeError(w, err, http.StatusInternalServerError, "BODY_READ_FAILED")
			return
		}
		plaintext = data
	}

	result, err := h.gateway.Upload(r.Context(), objectID, plaintext)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

// Download handles GET /objects/{id} and GET /api/v1/objects/{id}.
// It returns the decrypted plaintext bytes along with cryptographic metadata headers.
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, errors.New("method not allowed"), http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}

	objectID := extractObjectID(r.URL.Path)
	if objectID == "" {
		h.writeError(w, errors.New("missing object ID in URL path"), http.StatusBadRequest, "MISSING_OBJECT_ID")
		return
	}

	plaintext, meta, err := h.gateway.Download(r.Context(), objectID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-VaultGate-Object-ID", meta.ObjectID)
	w.Header().Set("X-VaultGate-KMS-Key-ID", meta.KMSKeyID)
	w.Header().Set("X-VaultGate-Algorithm", meta.Algorithm)
	w.Header().Set("X-VaultGate-Created-At", meta.CreatedAt.Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(plaintext)
}

// Head handles HEAD /objects/{id} and HEAD /api/v1/objects/{id}.
func (h *Handler) Head(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodHead {
		h.writeError(w, errors.New("method not allowed"), http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}

	objectID := extractObjectID(r.URL.Path)
	if objectID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, err := h.gateway.Head(r.Context(), objectID)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
}

// Delete handles DELETE /objects/{id} and DELETE /api/v1/objects/{id}.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.writeError(w, errors.New("method not allowed"), http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}

	objectID := extractObjectID(r.URL.Path)
	if objectID == "" {
		h.writeError(w, errors.New("missing object ID in URL path"), http.StatusBadRequest, "MISSING_OBJECT_ID")
		return
	}

	err := h.gateway.Delete(r.Context(), objectID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(&DeleteResponse{
		Status:   "deleted",
		ObjectID: objectID,
	})
}

// ReWrap handles POST /objects/{id}/rewrap and POST /api/v1/objects/{id}/rewrap.
func (h *Handler) ReWrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, errors.New("method not allowed"), http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}

	objectID := extractObjectID(r.URL.Path)
	if objectID == "" {
		h.writeError(w, errors.New("missing object ID in URL path"), http.StatusBadRequest, "MISSING_OBJECT_ID")
		return
	}

	var req ReWrapRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	targetKey := req.NewKMSKeyID
	if targetKey == "" {
		targetKey = r.URL.Query().Get("key_id")
	}

	result, err := h.gateway.ReWrap(r.Context(), objectID, targetKey)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// Health handles GET /health and GET /api/v1/health.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	status := h.gateway.CheckHealth(r.Context())
	w.Header().Set("Content-Type", "application/json")
	if status.Status == "ok" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(status)
}

// handleServiceError inspects domain errors and translates them to exact HTTP responses.
func (h *Handler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, envelope.ErrAccessDenied), errors.Is(err, storage.ErrStorageAccessDenied):
		h.writeError(w, err, http.StatusForbidden, "ACCESS_DENIED")

	case errors.Is(err, storage.ErrObjectNotFound):
		h.writeError(w, err, http.StatusNotFound, "OBJECT_NOT_FOUND")

	case errors.Is(err, crypto.ErrAuthenticationFailed), errors.Is(err, envelope.ErrEncryptionContextMismatch):
		h.writeError(w, err, http.StatusBadRequest, "TAMPER_DETECTED")

	case errors.Is(err, ErrEmptyPayload):
		h.writeError(w, err, http.StatusBadRequest, "EMPTY_PAYLOAD")

	case errors.Is(err, envelope.ErrInvalidEnvelope), errors.Is(err, storage.ErrMissingMetadata), errors.Is(err, storage.ErrCorruptMetadata):
		h.writeError(w, err, http.StatusBadRequest, "INVALID_ENVELOPE")

	default:
		h.writeError(w, err, http.StatusInternalServerError, "INTERNAL_ERROR")
	}
}

// writeError outputs a structured JSON error response.
func (h *Handler) writeError(w http.ResponseWriter, err error, statusCode int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(&ErrorResponse{
		Error: err.Error(),
		Code:  code,
	})
}

// extractObjectID retrieves the ID portion from URLs like /objects/{id} or /api/v1/objects/{id}.
func extractObjectID(path string) string {
	clean := strings.Trim(path, "/")
	parts := strings.Split(clean, "/")
	if len(parts) > 0 {
		for i, part := range parts {
			if part == "objects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}
