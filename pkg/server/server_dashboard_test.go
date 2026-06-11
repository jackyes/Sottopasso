package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The JSON feed must return the live tunnels in a stable order (oldest first)
// with the byte counters resolved to plain numbers.
func TestServeTunnelsJSON(t *testing.T) {
	s := New(&Config{})
	older := &Tunnel{ID: "b-old", Type: "http", PublicURL: "http://old.localhost", ClientAddr: "1.1.1.1:1", Status: "active", CreatedAt: time.Now().Add(-time.Hour)}
	older.TotalBytesIn.Store(123)
	older.TotalBytesOut.Store(456)
	newer := &Tunnel{ID: "a-new", Type: "tcp", PublicURL: "127.0.0.1:9000", ClientAddr: "2.2.2.2:2", Status: "active", CreatedAt: time.Now()}
	s.tunnels[older.ID] = older
	s.tunnels[newer.ID] = newer

	rec := httptest.NewRecorder()
	s.serveTunnelsJSON(rec, httptest.NewRequest("GET", "/api/tunnels", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}

	var payload struct {
		Tunnels []tunnelView `json:"tunnels"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(payload.Tunnels) != 2 {
		t.Fatalf("got %d tunnels, want 2", len(payload.Tunnels))
	}
	if payload.Tunnels[0].ID != "b-old" || payload.Tunnels[1].ID != "a-new" {
		t.Errorf("order=[%s %s], want oldest first [b-old a-new]", payload.Tunnels[0].ID, payload.Tunnels[1].ID)
	}
	first := payload.Tunnels[0]
	if first.BytesIn != 123 || first.BytesOut != 456 {
		t.Errorf("bytes=(%d,%d), want (123,456)", first.BytesIn, first.BytesOut)
	}
	if first.UptimeSeconds < 3500 {
		t.Errorf("uptime_seconds=%d, want roughly an hour", first.UptimeSeconds)
	}
}

// Only GET makes sense on the feed; the close action goes through POST /.
func TestServeTunnelsJSON_RejectsNonGET(t *testing.T) {
	s := New(&Config{})
	rec := httptest.NewRecorder()
	s.serveTunnelsJSON(rec, httptest.NewRequest("POST", "/api/tunnels", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("code=%d, want 405", rec.Code)
	}
}

// The dashboard must be fully self-contained: no external origins anywhere in
// the page (fonts, scripts, styles), so it works air-gapped and the CSP stays
// same-origin only.
func TestServeDashboard_NoExternalResources(t *testing.T) {
	s := New(&Config{})
	tn := &Tunnel{ID: "x", Type: "http", PublicURL: "http://x.localhost", ClientAddr: "1.2.3.4:5", Status: "active", CreatedAt: time.Now()}
	s.tunnels["x"] = tn

	rec := httptest.NewRecorder()
	s.serveDashboard(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()

	for _, banned := range []string{"fonts.googleapis.com", "fonts.gstatic.com", "https://cdn", "integrity="} {
		if strings.Contains(body, banned) {
			t.Errorf("dashboard references an external resource: %q", banned)
		}
	}
	// The HTTP tunnel URL must render as a clickable link, with its copy button.
	if !strings.Contains(body, `href="http://x.localhost"`) {
		t.Error("expected the HTTP tunnel URL to render as a link")
	}
	if !strings.Contains(body, `data-copy="http://x.localhost"`) {
		t.Error("expected a copy button for the tunnel URL")
	}
}
