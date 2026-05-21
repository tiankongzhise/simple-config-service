package httpapi

import (
	"net/http"

	"simple-config-service/internal/app"
)

const userIDHeader = "X-Config-User-ID"

type InternalHandler struct {
	app *app.App
	mux *http.ServeMux
}

func NewInternalHandler(service *app.App) http.Handler {
	h := &InternalHandler{
		app: service,
		mux: http.NewServeMux(),
	}
	h.routes()
	return h
}

func (h *InternalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *InternalHandler) routes() {
	h.mux.HandleFunc("GET /healthz", h.health)
	h.mux.HandleFunc("GET /internal/configs", h.configs)
}

func (h *InternalHandler) health(w http.ResponseWriter, r *http.Request) {
	if err := h.app.Health(r.Context()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *InternalHandler) configs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	userID := r.Header.Get(userIDHeader)
	configs, err := h.app.InternalConfigs(r.Context(), userID, query.Get("application"), query.Get("environment"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"application": query.Get("application"),
		"environment": query.Get("environment"),
		"configs":     toInternalConfigResponses(configs),
	})
}
