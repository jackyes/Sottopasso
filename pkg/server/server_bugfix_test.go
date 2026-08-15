package server

import (
	"Sottopasso/pkg/protocol"
	"bufio"
	"fmt"
	"io"
	"net"
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

// A backend that answers before consuming the (large) request body must have its
// response relayed, not lost behind a request upload that blocks on flow control.
func TestHandleHTTPRequest_BackendEarlyResponseIsRelayed(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		// Respond immediately, without reading the request body.
		io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://abc.localhost/", strings.NewReader(strings.Repeat("A", 1<<20)))
	runHandleHTTPRequest(t, s, rec, req, tun)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body=%q, want ok", rec.Body.String())
	}
}

// Hop-by-hop request headers must be stripped before the request is relayed, just
// like the response side.
func TestHandleHTTPRequest_StripsRequestHopByHopHeaders(t *testing.T) {
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
		defer stream.Close()
		relayed, err := http.ReadRequest(bufio.NewReader(stream))
		if err != nil {
			backendErr <- err
			return
		}
		for _, h := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "TE", "Upgrade", "X-Custom"} {
			if v := relayed.Header.Get(h); v != "" {
				backendErr <- fmt.Errorf("hop-by-hop header %s was relayed: %q", h, v)
				return
			}
		}
		backendErr <- nil
		io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://abc.localhost/", strings.NewReader("hi"))
	req.Header.Set("Connection", "keep-alive, X-Custom")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("X-Custom", "secret")
	runHandleHTTPRequest(t, s, rec, req, tun)

	if err := <-backendErr; err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d, want 200", rec.Code)
	}
}

// A backend that floods interim 1xx responses past the cap must not have one of
// them relayed as the final response.
func TestHandleHTTPRequest_TooManyInterimResponsesIs502(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		if _, err := http.ReadRequest(bufio.NewReader(stream)); err != nil {
			return
		}
		for i := 0; i < 6; i++ {
			io.WriteString(stream, "HTTP/1.1 100 Continue\r\n\r\n")
		}
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://abc.localhost/", nil)
	runHandleHTTPRequest(t, s, rec, req, tun)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("code=%d, want 502 when interim responses exceed the cap", rec.Code)
	}
}

// setupHTTPTunnel must deregister the tunnel when it cannot send the response,
// mirroring setupTCPTunnel, so no ghost entry survives a broken control stream.
func TestSetupHTTPTunnel_DeregistersOnResponseSendFailure(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	sess, _ := newYamuxPair(t)

	ctrl1, ctrl2 := net.Pipe()
	ctrl2.Close() // force the response write to fail
	defer ctrl1.Close()

	err := s.setupHTTPTunnel(protocol.RequestTunnel{Type: "http", Subdomain: "myapp"}, sess, ctrl1)
	if err == nil {
		t.Fatal("setupHTTPTunnel should fail when the control stream is closed")
	}
	if len(s.tunnels) != 0 {
		t.Errorf("tunnels map not empty after send failure: %d entries", len(s.tunnels))
	}
	s.httpTunnelsMu.RLock()
	_, ok := s.httpTunnels["myapp.localhost"]
	s.httpTunnelsMu.RUnlock()
	if ok {
		t.Error("httpTunnels still contains the tunnel after send failure")
	}
}

func TestHTTPRoutingHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://abc.localhost", "abc.localhost"},
		{"http://abc.localhost:8001", "abc.localhost"},
		{"https://abc.example.com:443", "abc.example.com"},
		{"https://ABC.Example.com", "abc.example.com"},
	}
	for _, c := range cases {
		if got := httpRoutingHost(c.in); got != c.want {
			t.Errorf("httpRoutingHost(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

// tcpPublicAddr must advertise a dialable host (the configured Domain host) rather
// than the listener's wildcard bind address.
func TestTCPPublicAddr(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("domain host", func(t *testing.T) {
		s := New(&Config{Domain: "tunnel.example.com"})
		want := net.JoinHostPort("tunnel.example.com", port)
		if got := s.tcpPublicAddr(ln); got != want {
			t.Errorf("tcpPublicAddr=%q, want %q", got, want)
		}
	})
	t.Run("domain with port", func(t *testing.T) {
		s := New(&Config{Domain: "localhost:8001"})
		want := net.JoinHostPort("localhost", port)
		if got := s.tcpPublicAddr(ln); got != want {
			t.Errorf("tcpPublicAddr=%q, want %q", got, want)
		}
	})
	t.Run("no domain falls back to listener addr", func(t *testing.T) {
		s := New(&Config{})
		if got := s.tcpPublicAddr(ln); got != ln.Addr().String() {
			t.Errorf("tcpPublicAddr=%q, want %q", got, ln.Addr().String())
		}
	})
}
