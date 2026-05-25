package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed ui
var uiFiles embed.FS

func (h *PublicHandler) ui(w http.ResponseWriter, r *http.Request) {
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
	if strings.HasPrefix(cleanPath, "/assets/") {
		serveUIAsset(w, r)
		return
	}

	switch cleanPath {
	case "/", "/login", "/register", "/home":
		serveUIIndex(w)
	default:
		http.NotFound(w, r)
	}
}

func serveUIAsset(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}

func serveUIIndex(w http.ResponseWriter) {
	body, err := uiFiles.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
