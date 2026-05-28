package server

import (
	"Sottopasso/pkg/protocol"
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// --- helpers ---

func quietYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.LogOutput = io.Discard
	return cfg
}

// newYamuxPair returns a connected (server, client) yamux session pair over an
// in-memory pipe so tunnel logic can be exercised without TLS or real sockets.
func newYamuxPair(t *testing.T) (server *yamux.Session, client *yamux.Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	cfg := quietYamuxConfig()

	var wg sync.WaitGroup
	var serr, cerr error
	wg.Add(2)
	go func() { defer wg.Done(); server, serr = yamux.Server(c1, cfg) }()
	go func() { defer wg.Done(); client, cerr = yamux.Client(c2, cfg) }()
	wg.Wait()
	if serr != nil || cerr != nil {
		t.Fatalf("yamux setup failed: server=%v client=%v", serr, cerr)
	}
	t.Cleanup(func() {
		server.Close()
		client.Close()
		c1.Close()
		c2.Close()
	})
	return server, client
}

// --- New ---

func TestNew(t *testing.T) {
	s := New(&Config{})
	if s.tunnels == nil || s.httpTunnels == nil {
		t.Fatal("tunnel maps must be initialized")
	}
	if s.dashboardTemplate == nil {
		t.Fatal("dashboard template must be parsed")
	}
	if len(s.csrfToken) != 64 {
		t.Errorf("csrfToken length=%d, want 64 hex chars (32 bytes)", len(s.csrfToken))
	}
	// Two servers must not share the same CSRF token.
	s2 := New(&Config{})
	if s.csrfToken == s2.csrfToken {
		t.Error("CSRF tokens for two servers should differ")
	}
}

// --- request classification ---

func TestIsWebSocketRequest(t *testing.T) {
	cases := []struct {
		name     string
		upgrade  string
		conn     string
		expected bool
	}{
		{"plain websocket", "websocket", "Upgrade", true},
		{"mixed case", "WebSocket", "keep-alive, Upgrade", true},
		{"no upgrade header", "", "", false},
		{"upgrade but not websocket", "h2c", "Upgrade", false},
		{"websocket but no connection upgrade", "websocket", "keep-alive", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if c.upgrade != "" {
				r.Header.Set("Upgrade", c.upgrade)
			}
			if c.conn != "" {
				r.Header.Set("Connection", c.conn)
			}
			if got := isWebSocketRequest(r); got != c.expected {
				t.Errorf("isWebSocketRequest=%v, want %v", got, c.expected)
			}
		})
	}
}

func TestIsSSERequest(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		accept   string
		expected bool
	}{
		{"sse get", "GET", "text/event-stream", true},
		{"sse among others", "GET", "text/html, text/event-stream", true},
		{"post is not sse", "POST", "text/event-stream", false},
		{"get without sse accept", "GET", "text/html", false},
		{"get no accept", "GET", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, "/", nil)
			if c.accept != "" {
				r.Header.Set("Accept", c.accept)
			}
			if got := isSSERequest(r); got != c.expected {
				t.Errorf("isSSERequest=%v, want %v", got, c.expected)
			}
		})
	}
}

// --- middleware ---

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

func TestBasicAuth_NoCredentialsConfiguredPassesThrough(t *testing.T) {
	s := New(&Config{}) // empty user/pass
	rec := httptest.NewRecorder()
	s.basicAuth(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d, want 200 (auth disabled when creds empty)", rec.Code)
	}
}

func TestBasicAuth_RejectsMissingAndWrongCredentials(t *testing.T) {
	s := New(&Config{DashboardUsername: "admin", DashboardPassword: "pw"})

	// missing
	rec := httptest.NewRecorder()
	s.basicAuth(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing creds: code=%d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate challenge header")
	}

	// wrong
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "wrong")
	s.basicAuth(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong creds: code=%d, want 401", rec.Code)
	}
}

func TestBasicAuth_AcceptsCorrectCredentials(t *testing.T) {
	s := New(&Config{DashboardUsername: "admin", DashboardPassword: "pw"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "pw")
	s.basicAuth(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body=%q, want ok", rec.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := New(&Config{})
	rec := httptest.NewRecorder()
	s.securityHeaders(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("header %s=%q, want %q", k, got, v)
		}
	}
}

// --- ServeHTTP routing ---

func TestServeHTTP_UnknownHost404(t *testing.T) {
	s := New(&Config{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://nope.localhost:8001/", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code=%d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("body=%q, want a not-found message", rec.Body.String())
	}
}

// Full HTTP proxy path: validates host:port stripping, routing, request/response
// relay, header copying, and (critically) the direction of byte accounting.
func TestServeHTTP_ProxiesRequestAndCountsBytes(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)

	tun := &Tunnel{
		ID:        "id1",
		Type:      "http",
		PublicURL: "http://abc.localhost",
		Status:    "active",
		CreatedAt: time.Now(),
		Session:   serverSess,
	}
	s.tunnels["id1"] = tun
	s.httpTunnels["abc.localhost"] = tun

	const respBody = "hello world"
	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		br := bufio.NewReader(stream)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(respBody)),
			ContentLength: int64(len(respBody)),
		}
		resp.Header.Set("X-Test", "yes")
		resp.Write(stream)
	}()

	// Host carries a port; routing must strip it to match the "abc.localhost" key.
	req := httptest.NewRequest("GET", "http://abc.localhost:8001/path", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("X-Test"); got != "yes" {
		t.Errorf("missing relayed response header, got %q", got)
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != respBody {
		t.Fatalf("body=%q, want %q", body, respBody)
	}
	if tun.TotalBytesIn.Load() == 0 {
		t.Error("expected TotalBytesIn>0 (request written toward client)")
	}
	if tun.TotalBytesOut.Load() < uint64(len(respBody)) {
		t.Errorf("TotalBytesOut=%d, want >= response body size %d", tun.TotalBytesOut.Load(), len(respBody))
	}
}

// Exercises the hijack proxy path (WebSocket/SSE). Uses a real httptest.Server
// so the ResponseWriter supports http.Hijacker, then verifies the raw
// bidirectional proxy relays the upgrade response and subsequent frames.
func TestHandleHijackedRequest_WebSocketProxy(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{
		ID:        "ws",
		Type:      "http",
		PublicURL: "http://127.0.0.1",
		Status:    "active",
		CreatedAt: time.Now(),
		Session:   serverSess,
	}
	s.tunnels["ws"] = tun
	s.httpTunnels["127.0.0.1"] = tun // ServeHTTP strips the port from 127.0.0.1:PORT

	ts := httptest.NewServer(s)
	defer ts.Close()

	// Tunnel-client side: accept the stream, read the forwarded request, reply
	// with a 101 upgrade, then echo one frame back.
	clientErr := make(chan error, 1)
	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			clientErr <- err
			return
		}
		defer stream.Close()
		br := bufio.NewReader(stream)
		req, err := http.ReadRequest(br)
		if err != nil {
			clientErr <- fmt.Errorf("tunnel client ReadRequest: %w", err)
			return
		}
		if req.URL.Path != "/ws" {
			clientErr <- fmt.Errorf("forwarded path=%q, want /ws", req.URL.Path)
			return
		}
		if _, err := io.WriteString(stream,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			clientErr <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(br, buf); err != nil {
			clientErr <- fmt.Errorf("tunnel client read frame: %w", err)
			return
		}
		if _, err := stream.Write(append([]byte("echo:"), buf...)); err != nil {
			clientErr <- err
			return
		}
		clientErr <- nil
	}()

	// Public client: a raw TCP connection that performs a WebSocket-style upgrade.
	addr := strings.TrimPrefix(ts.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading status line: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("status line=%q, want 101 Switching Protocols", statusLine)
	}
	for { // drain response headers
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len("echo:hello"))
	if _, err := io.ReadFull(br, out); err != nil {
		t.Fatalf("reading echoed frame: %v", err)
	}
	if string(out) != "echo:hello" {
		t.Errorf("echoed frame=%q, want echo:hello", out)
	}

	if err := <-clientErr; err != nil {
		t.Errorf("tunnel client side error: %v", err)
	}
	// Both directions should have moved bytes through the measured conns.
	if tun.TotalBytesIn.Load() == 0 || tun.TotalBytesOut.Load() == 0 {
		t.Errorf("expected non-zero traffic both ways, in=%d out=%d",
			tun.TotalBytesIn.Load(), tun.TotalBytesOut.Load())
	}
}

// A transparent proxy must forward ALL bytes the client sent, including any data
// pipelined immediately after the upgrade request (which the HTTP server buffers
// while parsing headers). This guards against discarding the hijacked buffer.
func TestHandleHijackedRequest_ForwardsBufferedClientData(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "ws2", Type: "http", PublicURL: "http://127.0.0.1", Status: "active", CreatedAt: time.Now(), Session: serverSess}
	s.tunnels["ws2"] = tun
	s.httpTunnels["127.0.0.1"] = tun

	ts := httptest.NewServer(s)
	defer ts.Close()

	clientErr := make(chan error, 1)
	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			clientErr <- err
			return
		}
		defer stream.Close()
		br := bufio.NewReader(stream)
		if _, err := http.ReadRequest(br); err != nil {
			clientErr <- fmt.Errorf("ReadRequest: %w", err)
			return
		}
		// Acknowledge the upgrade first, then read the pipelined frame.
		if _, err := io.WriteString(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			clientErr <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(br, buf); err != nil {
			clientErr <- fmt.Errorf("reading pipelined frame: %w", err)
			return
		}
		stream.Write(append([]byte("echo:"), buf...))
		clientErr <- nil
	}()

	addr := strings.TrimPrefix(ts.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Request AND the first frame in a single write -> the server buffers "hello"
	// while parsing the request headers.
	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello")

	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil { // status line
		t.Fatalf("reading status line: %v", err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	out := make([]byte, len("echo:hello"))
	if _, err := io.ReadFull(br, out); err != nil {
		t.Fatalf("did not receive echo of pipelined data (buffered bytes likely dropped): %v", err)
	}
	if string(out) != "echo:hello" {
		t.Errorf("echoed=%q, want echo:hello", out)
	}
	if err := <-clientErr; err != nil {
		t.Errorf("tunnel client side error: %v", err)
	}
}

// --- authenticate (server side) ---

func sendControl(t *testing.T, conn net.Conn, mtype protocol.MessageType, inner interface{}) {
	t.Helper()
	payload, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(protocol.ControlMessage{Type: mtype, RawPayload: payload}); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

func TestAuthenticate_ValidToken(t *testing.T) {
	s := New(&Config{ValidTokens: []string{"good-token"}})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	res := make(chan bool, 1)
	go func() { res <- s.authenticate(c1) }()

	sendControl(t, c2, protocol.AuthRequestType, protocol.AuthRequest{AuthToken: "good-token"})

	var resp protocol.ControlMessage
	if err := json.NewDecoder(c2).Decode(&resp); err != nil {
		t.Fatalf("decode auth response: %v", err)
	}
	if resp.Type != protocol.AuthResponseType {
		t.Errorf("response type=%q, want %q", resp.Type, protocol.AuthResponseType)
	}
	var ar protocol.AuthResponse
	json.Unmarshal(resp.RawPayload, &ar)
	if !ar.Success {
		t.Error("AuthResponse.Success=false, want true")
	}
	if got := <-res; !got {
		t.Error("authenticate returned false for a valid token")
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	s := New(&Config{ValidTokens: []string{"good-token"}})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	res := make(chan bool, 1)
	go func() { res <- s.authenticate(c1) }()

	sendControl(t, c2, protocol.AuthRequestType, protocol.AuthRequest{AuthToken: "bad-token"})

	var resp protocol.ControlMessage
	if err := json.NewDecoder(c2).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var ar protocol.AuthResponse
	json.Unmarshal(resp.RawPayload, &ar)
	if ar.Success {
		t.Error("AuthResponse.Success=true for invalid token")
	}
	if ar.Error == "" {
		t.Error("expected an error message for invalid token")
	}
	if got := <-res; got {
		t.Error("authenticate returned true for an invalid token")
	}
}

func TestAuthenticate_WrongFirstMessageType(t *testing.T) {
	s := New(&Config{ValidTokens: []string{"good-token"}})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	res := make(chan bool, 1)
	go func() { res <- s.authenticate(c1) }()

	// First message is a tunnel request rather than auth -> must be rejected,
	// and (since no response is sent) authenticate returns immediately.
	sendControl(t, c2, protocol.RequestTunnelType, protocol.RequestTunnel{Type: "http"})

	if got := <-res; got {
		t.Error("authenticate returned true for a non-auth first message")
	}
}

// --- handleRequestTunnel / setup* ---

func readControl(t *testing.T, conn net.Conn) protocol.ControlMessage {
	t.Helper()
	var msg protocol.ControlMessage
	if err := json.NewDecoder(conn).Decode(&msg); err != nil {
		t.Fatalf("decode control: %v", err)
	}
	return msg
}

func TestHandleRequestTunnel_UnsupportedType(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	sess, _ := newYamuxPair(t)
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	payload, _ := json.Marshal(protocol.RequestTunnel{Type: "ftp"})
	msg := &protocol.ControlMessage{Type: protocol.RequestTunnelType, RawPayload: payload}

	errCh := make(chan error, 1)
	go func() { errCh <- s.handleRequestTunnel(msg, sess, ctrl1) }()

	resp := readControl(t, ctrl2)
	var tr protocol.TunnelResponse
	json.Unmarshal(resp.RawPayload, &tr)
	if !strings.Contains(tr.Error, "unsupported tunnel type: ftp") {
		t.Errorf("response error=%q, want it to mention unsupported type", tr.Error)
	}
	if err := <-errCh; err == nil {
		t.Error("handleRequestTunnel should return an error for unsupported type")
	}
}

func TestSetupHTTPTunnel_RequestedSubdomain(t *testing.T) {
	s := New(&Config{Domain: "localhost:8001"}) // port must be stripped
	sess, _ := newYamuxPair(t)
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.setupHTTPTunnel(protocol.RequestTunnel{Type: "http", Subdomain: "myapp"}, sess, ctrl1)
	}()

	resp := readControl(t, ctrl2)
	if err := <-errCh; err != nil {
		t.Fatalf("setupHTTPTunnel: %v", err)
	}
	var tr protocol.TunnelResponse
	json.Unmarshal(resp.RawPayload, &tr)
	if tr.PublicURL != "http://myapp.localhost" {
		t.Errorf("PublicURL=%q, want http://myapp.localhost", tr.PublicURL)
	}
	if _, ok := s.httpTunnels["myapp.localhost"]; !ok {
		t.Error("expected httpTunnels to contain myapp.localhost")
	}
	if len(s.tunnels) != 1 {
		t.Errorf("len(tunnels)=%d, want 1", len(s.tunnels))
	}
}

func TestSetupHTTPTunnel_SubdomainCollisionFallsBackToRandom(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	sess, _ := newYamuxPair(t)
	// Pre-occupy the requested subdomain.
	s.httpTunnels["taken.localhost"] = &Tunnel{ID: "pre"}

	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.setupHTTPTunnel(protocol.RequestTunnel{Type: "http", Subdomain: "taken"}, sess, ctrl1)
	}()

	resp := readControl(t, ctrl2)
	if err := <-errCh; err != nil {
		t.Fatalf("setupHTTPTunnel: %v", err)
	}
	var tr protocol.TunnelResponse
	json.Unmarshal(resp.RawPayload, &tr)
	if tr.PublicURL == "http://taken.localhost" {
		t.Error("collision should have produced a different (random) subdomain")
	}
	if !strings.HasPrefix(tr.PublicURL, "http://") || !strings.HasSuffix(tr.PublicURL, ".localhost") {
		t.Errorf("PublicURL=%q has unexpected shape", tr.PublicURL)
	}
	if len(s.httpTunnels) != 2 {
		t.Errorf("len(httpTunnels)=%d, want 2 (pre-existing + new)", len(s.httpTunnels))
	}
}

func TestSetupTCPTunnel(t *testing.T) {
	s := New(&Config{})
	sess, _ := newYamuxPair(t)
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- s.setupTCPTunnel(protocol.RequestTunnel{Type: "tcp"}, sess, ctrl1) }()

	resp := readControl(t, ctrl2)
	if err := <-errCh; err != nil {
		t.Fatalf("setupTCPTunnel: %v", err)
	}
	var tr protocol.TunnelResponse
	json.Unmarshal(resp.RawPayload, &tr)
	if _, _, err := net.SplitHostPort(tr.PublicURL); err != nil {
		t.Errorf("PublicURL=%q is not host:port: %v", tr.PublicURL, err)
	}
	if len(s.tunnels) != 1 {
		t.Fatalf("len(tunnels)=%d, want 1", len(s.tunnels))
	}
	for _, tn := range s.tunnels {
		if tn.Type != "tcp" {
			t.Errorf("tunnel type=%q, want tcp", tn.Type)
		}
	}
}

// --- cleanup ---

func TestCleanupTunnelsForSession(t *testing.T) {
	s := New(&Config{})
	sess, _ := newYamuxPair(t)
	otherSess, _ := newYamuxPair(t)

	httpTun := &Tunnel{ID: "h", Type: "http", PublicURL: "http://a.localhost", Session: sess}
	httpsTun := &Tunnel{ID: "s", Type: "http", PublicURL: "https://b.localhost", Session: sess}
	keep := &Tunnel{ID: "k", Type: "http", PublicURL: "http://c.localhost", Session: otherSess}

	s.tunnels["h"] = httpTun
	s.tunnels["s"] = httpsTun
	s.tunnels["k"] = keep
	s.httpTunnels["a.localhost"] = httpTun
	s.httpTunnels["b.localhost"] = httpsTun
	s.httpTunnels["c.localhost"] = keep

	s.cleanupTunnelsForSession(sess)

	if _, ok := s.tunnels["h"]; ok {
		t.Error("http tunnel for closed session not cleaned up")
	}
	if _, ok := s.tunnels["s"]; ok {
		t.Error("https tunnel for closed session not cleaned up")
	}
	if _, ok := s.tunnels["k"]; !ok {
		t.Error("tunnel for a different session was wrongly removed")
	}
	if _, ok := s.httpTunnels["a.localhost"]; ok {
		t.Error("httpTunnels[a.localhost] should be removed")
	}
	if _, ok := s.httpTunnels["b.localhost"]; ok {
		t.Error("httpTunnels[b.localhost] (https URL) should be removed")
	}
	if _, ok := s.httpTunnels["c.localhost"]; !ok {
		t.Error("httpTunnels[c.localhost] should remain")
	}
}

// --- handleCloseTunnel (CSRF) ---

func postForm(values url.Values) *http.Request {
	req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestHandleCloseTunnel_CSRFAndValidation(t *testing.T) {
	s := New(&Config{})

	// missing/invalid CSRF -> 403
	rec := httptest.NewRecorder()
	s.handleCloseTunnel(rec, postForm(url.Values{"tunnelId": {"x"}}))
	if rec.Code != http.StatusForbidden {
		t.Errorf("no csrf: code=%d, want 403", rec.Code)
	}

	// valid CSRF but missing tunnelId -> 400
	rec = httptest.NewRecorder()
	s.handleCloseTunnel(rec, postForm(url.Values{"csrf_token": {s.csrfToken}}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing tunnelId: code=%d, want 400", rec.Code)
	}

	// valid CSRF, unknown tunnelId -> 404
	rec = httptest.NewRecorder()
	s.handleCloseTunnel(rec, postForm(url.Values{"csrf_token": {s.csrfToken}, "tunnelId": {"nope"}}))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown tunnel: code=%d, want 404", rec.Code)
	}
}

func TestHandleCloseTunnel_Success(t *testing.T) {
	s := New(&Config{})
	sess, _ := newYamuxPair(t)
	tun := &Tunnel{ID: "abc", Type: "tcp", Session: sess}
	s.tunnels["abc"] = tun

	rec := httptest.NewRecorder()
	s.handleCloseTunnel(rec, postForm(url.Values{"csrf_token": {s.csrfToken}, "tunnelId": {"abc"}}))
	if rec.Code != http.StatusFound {
		t.Fatalf("code=%d, want 302 redirect", rec.Code)
	}
	// Session should have been closed.
	if !sess.IsClosed() {
		t.Error("expected the tunnel session to be closed")
	}
}

// --- dashboard rendering + formatBytes boundaries ---

func TestServeDashboard_RendersAndFormatsBytes(t *testing.T) {
	s := New(&Config{})

	add := func(id string, in uint64) {
		tn := &Tunnel{ID: id, Type: "http", PublicURL: "http://" + id, ClientAddr: "1.2.3.4:1", Status: "active", CreatedAt: time.Now()}
		tn.TotalBytesIn.Store(in)
		s.tunnels[id] = tn
	}
	add("z", 0)             // 0 B
	add("a", 1023)          // 1023 B
	add("b", 1024)          // 1.00 KB
	add("c", 1048576)       // 1.00 MB
	add("d", 1073741824)    // 1.00 GB
	add("e", 1099511627776) // 1.00 TB

	rec := httptest.NewRecorder()
	s.serveDashboard(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", rec.Code)
	}
	body := rec.Body.String()

	for _, want := range []string{"0 B", "1023 B", "1.00 KB", "1.00 MB", "1.00 GB", "1.00 TB"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard body missing formatted value %q", want)
		}
	}
	// Active tunnel count is rendered.
	if !strings.Contains(body, "<span>6</span>") {
		t.Error("expected active tunnel count of 6 in dashboard")
	}
	// CSRF token should be embedded in the close forms.
	if !strings.Contains(body, s.csrfToken) {
		t.Error("expected CSRF token embedded in dashboard")
	}
}

// --- TLS config / cert generation ---

func TestGenerateSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	if err := generateSelfSignedCert(certFile, keyFile, "localhost"); err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("generated cert/key not loadable: %v", err)
	}
}

func TestGetTLSConfig_GeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "c.pem")
	keyFile := filepath.Join(dir, "k.pem")

	s := New(&Config{})
	cfg, err := s.getTLSConfig(certFile, keyFile, "localhost")
	if err != nil {
		t.Fatalf("getTLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("got %d certificates, want 1", len(cfg.Certificates))
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion=%x, want TLS1.2 (%x)", cfg.MinVersion, tls.VersionTLS12)
	}

	// Second call should load the now-existing files without error.
	if _, err := s.getTLSConfig(certFile, keyFile, "localhost"); err != nil {
		t.Errorf("getTLSConfig on existing files: %v", err)
	}
}
