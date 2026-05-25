package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicHandlerServesUIRoutes(t *testing.T) {
	handler := NewPublicHandler(nil)

	for _, path := range []string{"/", "/login", "/register", "/home"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("%s returned status %d", path, recorder.Code)
		}
		if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
			t.Fatalf("%s returned content type %q", path, contentType)
		}
		if !strings.Contains(recorder.Body.String(), `id="app"`) {
			t.Fatalf("%s did not return the UI shell", path)
		}
	}
}

func TestPublicHandlerServesUIAssets(t *testing.T) {
	handler := NewPublicHandler(nil)
	request := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("asset returned status %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "simple-config-service.token") {
		t.Fatal("asset response did not include the UI script")
	}
}

func TestUISubmitDispatchUsesFormAttributeID(t *testing.T) {
	script, err := uiFiles.ReadFile("ui/assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	body := string(script)
	if !strings.Contains(body, `const formID = form.getAttribute("id") || "";`) {
		t.Fatal("submit handler should read the form id attribute")
	}
	if strings.Contains(body, `if (form.id === "config-form")`) {
		t.Fatal("submit handler should not use form.id for config form dispatch")
	}
}
