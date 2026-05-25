package httpapi

import (
	"net/http"

	"simple-config-service/internal/app"
	"simple-config-service/internal/store"
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
	var responseConfigs []internalConfigResponse
	var err error
	if projectID := query.Get("project_id"); projectID != "" {
		var list []store.Config
		list, err = h.app.InternalProjectConfigs(r.Context(), userID, projectID, query.Get("environment"))
		responseConfigs = toInternalConfigResponses(list)
	} else {
		var list []store.Config
		list, err = h.app.InternalConfigs(r.Context(), userID, query.Get("application"), query.Get("environment"))
		responseConfigs = toInternalConfigResponses(list)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"project_id":  query.Get("project_id"),
		"application": query.Get("application"),
		"environment": query.Get("environment"),
		"configs":     responseConfigs,
	})
}
