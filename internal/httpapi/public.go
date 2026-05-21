package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"simple-config-service/internal/app"
)

type PublicHandler struct {
	app *app.App
	mux *http.ServeMux
}

func NewPublicHandler(service *app.App) http.Handler {
	h := &PublicHandler{
		app: service,
		mux: http.NewServeMux(),
	}
	h.routes()
	return h
}

func (h *PublicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *PublicHandler) routes() {
	h.mux.HandleFunc("GET /healthz", h.health)
	h.mux.HandleFunc("POST /api/register", h.register)
	h.mux.HandleFunc("POST /api/login", h.login)
	h.mux.HandleFunc("POST /api/refresh", h.refresh)
	h.mux.HandleFunc("POST /api/logout", h.auth(h.logout))
	h.mux.HandleFunc("POST /api/configs", h.auth(h.createConfig))
	h.mux.HandleFunc("GET /api/configs", h.auth(h.listConfigs))
	h.mux.HandleFunc("PUT /api/configs/{id}", h.auth(h.updateConfig))
	h.mux.HandleFunc("DELETE /api/configs/{id}", h.auth(h.deleteConfig))
	h.mux.HandleFunc("GET /api/configs/{id}/versions", h.auth(h.listVersions))
	h.mux.HandleFunc("POST /api/configs/{id}/rollback", h.auth(h.rollback))
}

type authenticatedHandler func(http.ResponseWriter, *http.Request, app.PublicUser)

func (h *PublicHandler) auth(next authenticatedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := h.app.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, err)
			return
		}
		next(w, r, user)
	}
}

func (h *PublicHandler) health(w http.ResponseWriter, r *http.Request) {
	if err := h.app.Health(r.Context()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *PublicHandler) register(w http.ResponseWriter, r *http.Request) {
	var input app.RegisterInput
	if err := readJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	response, err := h.app.Register(r.Context(), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

func (h *PublicHandler) login(w http.ResponseWriter, r *http.Request) {
	var input app.LoginInput
	if err := readJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	response, err := h.app.Login(r.Context(), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *PublicHandler) refresh(w http.ResponseWriter, r *http.Request) {
	token, err := tokenFromRequest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	response, err := h.app.Refresh(r.Context(), token)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *PublicHandler) logout(w http.ResponseWriter, r *http.Request, user app.PublicUser) {
	h.app.Logout(r.Context(), user.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *PublicHandler) createConfig(w http.ResponseWriter, r *http.Request, user app.PublicUser) {
	var input app.ConfigInput
	if err := readJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	config, err := h.app.CreateConfig(r.Context(), user.ID, input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toConfigResponse(config))
}

func (h *PublicHandler) updateConfig(w http.ResponseWriter, r *http.Request, user app.PublicUser) {
	var input app.ConfigInput
	if err := readJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	config, err := h.app.UpdateConfig(r.Context(), user.ID, r.PathValue("id"), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toConfigResponse(config))
}

func (h *PublicHandler) deleteConfig(w http.ResponseWriter, r *http.Request, user app.PublicUser) {
	if err := h.app.DeleteConfig(r.Context(), user.ID, r.PathValue("id")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PublicHandler) listConfigs(w http.ResponseWriter, r *http.Request, user app.PublicUser) {
	query := r.URL.Query()
	limit, err := parseQueryInt(query.Get("limit"), 50)
	if err != nil {
		writeError(w, err)
		return
	}
	offset, err := parseQueryInt(query.Get("offset"), 0)
	if err != nil {
		writeError(w, err)
		return
	}
	configs, err := h.app.ListConfigs(r.Context(), user.ID, query.Get("application"), query.Get("environment"), limit, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configs": toConfigResponses(configs)})
}

func (h *PublicHandler) listVersions(w http.ResponseWriter, r *http.Request, user app.PublicUser) {
	configs, err := h.app.ListVersions(r.Context(), user.ID, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": toConfigResponses(configs)})
}

type rollbackRequest struct {
	Version int `json:"version"`
}

func (h *PublicHandler) rollback(w http.ResponseWriter, r *http.Request, user app.PublicUser) {
	var input rollbackRequest
	if err := readJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	config, err := h.app.Rollback(r.Context(), user.ID, r.PathValue("id"), input.Version)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toConfigResponse(config))
}

func tokenFromRequest(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	typ, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(typ, "Bearer") || strings.TrimSpace(token) == "" {
		return "", app.ErrUnauthorized
	}
	return strings.TrimSpace(token), nil
}

func parseQueryInt(value string, fallback int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, app.BadField("query", "invalid integer")
	}
	return parsed, nil
}
