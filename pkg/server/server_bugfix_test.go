package server

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// runHandleHTTPRequest invokes handleHTTPRequest with a watchdog so a hung
// handler fails the test instead of blocking the suite.
func runHandleHTTPRequest(t *testing.T, s *Server, rec *httptest.ResponseRecorder, req *http.Request, tun *Tunnel) {
	t.Helper()
	done := make(chan struct{})
	go func() { s.handleHTTPRequest(rec, req, tun); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleHTTPRequest did not return")
	}
}

// A request body exceeding MaxHTTPRequestBytes must yield 413, not an implicit 200.
func TestHandleHTTPRequest_RequestBodyTooLargeIs413(t *testing.T) {
	s := New(&Config{Domain: "localhost", MaxHTTPRequestBytes: 8})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(io.Discard, stream) // swallow whatever part of the request arrives
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://abc.localhost/", strings.NewReader(strings.Repeat("A", 1024)))
	runHandleHTTPRequest(t, s, rec, req, tun)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("code=%d, want 413 when the request body exceeds the limit", rec.Code)
	}
}

// Interim 1xx responses from the backend must be skipped, not relayed as final.
func TestHandleHTTPRequest_SkipsInterim1xx(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(stream)); err != nil {
			return
		}
		io.WriteString(stream, "HTTP/1.1 100 Continue\r\n\r\n")
		io.WriteString(stream, "HTTP/1.1 204 No Content\r\n\r\n")
		stream.Close()
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://abc.localhost/", nil)
	runHandleHTTPRequest(t, s, rec, req, tun)

	if rec.Code != http.StatusNoContent {
		t.Errorf("code=%d, want 204 (the interim 100 must be skipped)", rec.Code)
	}
}

// The visitor's "Expect: 100-continue" is answered by net/http itself; relaying
// it would make the backend emit a 100 that gets mistaken for the final response.
func TestHandleHTTPRequest_StripsExpectHeader(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	backendErr := make(chan error, 1)
	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			backendErr <- err
			return
		}
		relayed, err := http.ReadRequest(bufio.NewReader(stream))
		if err != nil {
			backendErr <- err
			return
		}
		if v := relayed.Header.Get("Expect"); v != "" {
			backendErr <- fmt.Errorf("Expect header was relayed to the backend: %q", v)
		} else {
			backendErr <- nil
		}
		io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		stream.Close()
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://abc.localhost/", strings.NewReader("hi"))
	req.Header.Set("Expect", "100-continue")
	runHandleHTTPRequest(t, s, rec, req, tun)

	if err := <-backendErr; err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d, want 200", rec.Code)
	}
}

// Response trailers declared by the backend must reach the visitor.
func TestHandleHTTPRequest_ForwardsTrailers(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(stream)); err != nil {
			return
		}
		io.WriteString(stream, "HTTP/1.1 200 OK\r\n"+
			"Trailer: X-Sum\r\n"+
			"Transfer-Encoding: chunked\r\n\r\n"+
			"3\r\nabc\r\n"+
			"0\r\nX-Sum: 99\r\n\r\n")
		stream.Close()
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://abc.localhost/", nil)
	runHandleHTTPRequest(t, s, rec, req, tun)

	if rec.Body.String() != "abc" {
		t.Errorf("body=%q, want abc", rec.Body.String())
	}
	if got := rec.Result().Trailer.Get("X-Sum"); got != "99" {
		t.Errorf("trailer X-Sum=%q, want 99", got)
	}
}

// A backend that accepts the request but never produces response headers must
// not pin the handler goroutine forever when HTTPResponseHeaderTimeout is set.
func TestHandleHTTPRequest_StalledBackendTimesOut(t *testing.T) {
	s := New(&Config{Domain: "localhost", HTTPResponseHeaderTimeout: 200 * time.Millisecond})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(io.Discard, stream) // read the request, never respond
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://abc.localhost/", nil)
	runHandleHTTPRequest(t, s, rec, req, tun)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("code=%d, want 502 when the backend stalls past the header timeout", rec.Code)
	}
}

// The hijack path has no body limits or deadlines, so only genuine WebSocket
// handshakes (GET, per RFC 6455) may reach it.
func TestIsWebSocketRequest_RequiresGET(t *testing.T) {
	mk := func(method string) *http.Request {
		r := httptest.NewRequest(method, "http://x/", nil)
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "Upgrade")
		return r
	}
	if !isWebSocketRequest(mk("GET")) {
		t.Error("a GET upgrade request must be detected as WebSocket")
	}
	if isWebSocketRequest(mk("POST")) {
		t.Error("a POST with Upgrade headers must not reach the unlimited hijack path")
	}
}

// Shutdown must close client sessions: per-tunnel TCP listeners and their accept
// goroutines only exit when their session dies.
func TestShutdown_ClosesClientSessions(t *testing.T) {
	s := New(&Config{})
	sess, _ := newYamuxPair(t)
	s.tunnels["t1"] = &Tunnel{ID: "t1", Type: "tcp", Session: sess}

	s.Shutdown()

	if !sess.IsClosed() {
		t.Error("Shutdown must close active client sessions")
	}
}
