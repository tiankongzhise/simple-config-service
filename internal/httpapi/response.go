package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"simple-config-service/internal/app"
)

type errorResponse struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	body := errorResponse{Error: "internal server error"}

	var fieldErr app.FieldError
	switch {
	case errors.As(err, &fieldErr):
		status = http.StatusBadRequest
		body = errorResponse{Error: fieldErr.Message, Field: fieldErr.Field}
	case errors.Is(err, app.ErrBadRequest):
		status = http.StatusBadRequest
		body = errorResponse{Error: "bad request"}
	case errors.Is(err, app.ErrUnauthorized):
		status = http.StatusUnauthorized
		body = errorResponse{Error: "unauthorized"}
	case errors.Is(err, app.ErrForbidden):
		status = http.StatusForbidden
		body = errorResponse{Error: "forbidden"}
	case errors.Is(err, app.ErrNotFound):
		status = http.StatusNotFound
		body = errorResponse{Error: "not found"}
	case errors.Is(err, app.ErrConflict):
		status = http.StatusConflict
		body = errorResponse{Error: "conflict"}
	}

	writeJSON(w, status, body)
}

func readJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return app.ErrBadRequest
	}
	return nil
}
