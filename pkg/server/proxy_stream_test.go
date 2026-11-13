package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"Sottopasso/pkg/protocol"

	"github.com/hashicorp/yamux"
)

// newPublicProxyTest registers an HTTP tunnel routed by Host 127.0.0.1 and
// serves s on a real listener, so the ResponseWriter can be hijacked and a
// visitor can drive the connection byte by byte.
func newPublicProxyTest(t *testing.T) (*Server, *yamux.Session, string) {
	t.Helper()
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "pub", Type: "http", PublicURL: "http://127.0.0.1", Status: "active", CreatedAt: time.Now(), Session: serverSess}
	s.tunnels[tun.ID] = tun
	s.httpTunnels["127.0.0.1"] = tun
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return s, clientSess, strings.TrimPrefix(ts.URL, "http://")
}

// keepAliveBackend plays a backend that keeps its connection open: on every
// stream it answers each request it reads with response, and reports the
// requests it saw.
func keepAliveBackend(sess *yamux.Session, response string) <-chan *http.Request {
	seen := make(chan *http.Request, 16)
	go func() {
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer stream.Close()
				br := bufio.NewReader(stream)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					seen <- req
					if _, err := io.WriteString(stream, response); err != nil {
						return
					}
				}
			}(stream)
		}
	}()
	return seen
}

func dialVisitor(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, bufio.NewReader(conn)
}

func readVisitorResponse(t *testing.T, br *bufio.Reader) (*http.Response, string) {
	t.Helper()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("visitor ReadResponse: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("visitor reading body: %v", err)
	}
	return resp, string(body)
}

// assertProxiedRequests checks that the backend saw exactly n requests, each
// with forwarding headers set by the server rather than by the visitor.
func assertProxiedRequests(t *testing.T, seen <-chan *http.Request, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		select {
		case req := <-seen:
			if got := req.Header.Get("X-Forwarded-For"); got != "127.0.0.1" {
				t.Errorf("request %d (%s): backend saw X-Forwarded-For=%q, want 127.0.0.1 set by the server", i, req.URL.Path, got)
			}
			if got := req.Header.Get("X-Real-IP"); got != "127.0.0.1" {
				t.Errorf("request %d (%s): backend saw X-Real-IP=%q, want 127.0.0.1 set by the server", i, req.URL.Path, got)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("backend saw %d requests, want %d", i-1, n)
		}
	}
}

// A request that merely claims to be SSE (anyone can send that Accept header)
// used to turn the visitor's connection into a raw tunnel to the backend, so
// every later request on it skipped the proxy: spoofed X-Forwarded-For and
// X-Real-IP reached the backend untouched.
func TestServeHTTP_SSEFollowUpRequestGoesThroughProxy(t *testing.T) {
	_, backend, addr := newPublicProxyTest(t)
	seen := keepAliveBackend(backend, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 10\r\n\r\ndata: hi\n\n")
	conn, br := dialVisitor(t, addr)

	fmt.Fprint(conn, "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n")
	if _, body := readVisitorResponse(t, br); body != "data: hi\n\n" {
		t.Fatalf("SSE body=%q", body)
	}
	fmt.Fprint(conn, "GET /second HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\n\r\n")
	readVisitorResponse(t, br)

	assertProxiedRequests(t, seen, 2)
}

// Same bypass through a WebSocket upgrade the backend never accepted: only a
// 101 Switching Protocols may turn the connection into a raw stream.
func TestServeHTTP_RefusedUpgradeFollowUpRequestGoesThroughProxy(t *testing.T) {
	_, backend, addr := newPublicProxyTest(t)
	seen := keepAliveBackend(backend, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	conn, br := dialVisitor(t, addr)

	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if resp, _ := readVisitorResponse(t, br); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("refused upgrade: status=%d, want the backend's 404", resp.StatusCode)
	}
	fmt.Fprint(conn, "GET /second HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\n\r\n")
	readVisitorResponse(t, br)

	assertProxiedRequests(t, seen, 2)
}

// SSE events must reach the visitor as the backend produces them, not when
// the response ends.
func TestServeHTTP_SSEEventsAreFlushedAsTheyArrive(t *testing.T) {
	_, backend, addr := newPublicProxyTest(t)
	release := make(chan struct{})
	go func() {
		stream, err := backend.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		if _, err := http.ReadRequest(bufio.NewReader(stream)); err != nil {
			return
		}
		io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: one\n\n")
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		io.WriteString(stream, "data: two\n\n")
	}()
	conn, br := dialVisitor(t, addr)
	defer close(release)

	fmt.Fprint(conn, "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	// No resp.Body.Close: on a client response it drains the body, which only
	// ends once the deferred close(release) has run. The connection is closed
	// by dialVisitor's cleanup instead.
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type=%q, want text/event-stream", ct)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("first event not delivered while the stream is still open: %v", err)
	}
	if line != "data: one\n" {
		t.Errorf("first line=%q, want %q", line, "data: one\n")
	}
}

// The tunnel client controls the response bytes: headers without a size limit
// let it make the server buffer as much memory as it likes.
func TestHandleHTTPRequest_OversizedResponseHeadersAre502(t *testing.T) {
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
		io.WriteString(stream, "HTTP/1.1 200 OK\r\nX-Big: "+strings.Repeat("a", 2*maxResponseHeaderBytes)+"\r\nContent-Length: 0\r\n\r\n")
	}()

	rec := httptest.NewRecorder()
	runHandleHTTPRequest(t, s, rec, httptest.NewRequest("GET", "http://abc.localhost/", nil), tun)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("code=%d, want 502 for response headers over %d bytes", rec.Code, maxResponseHeaderBytes)
	}
	if rec.Header().Get("X-Big") != "" {
		t.Error("oversized header was relayed to the visitor")
	}
}

// The backend must see the tunnel's own host name, not whatever the visitor
// put in Host (other case, another port).
func TestHandleHTTPRequest_ForwardsCanonicalHost(t *testing.T) {
	s := New(&Config{Domain: "localhost:8001"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost:8001", Status: "active", CreatedAt: time.Now(), Session: serverSess}
	s.tunnels[tun.ID] = tun
	s.httpTunnels["abc.localhost"] = tun
	seen := keepAliveBackend(clientSess, "HTTP/1.1 204 No Content\r\n\r\n")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "http://ABC.Localhost:9999/x", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code=%d, want 204", rec.Code)
	}
	select {
	case req := <-seen:
		if req.Host != "abc.localhost:8001" {
			t.Errorf("backend saw Host=%q, want abc.localhost:8001", req.Host)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "abc.localhost:8001" {
			t.Errorf("backend saw X-Forwarded-Host=%q, want abc.localhost:8001", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend saw no request")
	}
}

// A 101 the visitor did not ask for would hand a plain HTTP connection over
// to the backend as a raw stream.
func TestHandleHTTPRequest_UnrequestedSwitchingProtocolsIs502(t *testing.T) {
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
		io.WriteString(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		io.Copy(io.Discard, stream)
	}()

	rec := httptest.NewRecorder()
	runHandleHTTPRequest(t, s, rec, httptest.NewRequest("GET", "http://abc.localhost/", nil), tun)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("code=%d, want 502 for a 101 to a request without Upgrade", rec.Code)
	}
}

// The backend may only switch to the protocol the visitor asked for.
func TestServeHTTP_UpgradeToOtherProtocolIs502(t *testing.T) {
	_, backend, addr := newPublicProxyTest(t)
	go func() {
		stream, err := backend.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		if _, err := http.ReadRequest(bufio.NewReader(stream)); err != nil {
			return
		}
		io.WriteString(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n")
		io.Copy(io.Discard, stream)
	}()
	conn, br := dialVisitor(t, addr)

	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if resp, _ := readVisitorResponse(t, br); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status=%d, want 502 when the backend switches to another protocol", resp.StatusCode)
	}
}

// The server never accepts streams from a client after the control stream:
// unaccepted streams would sit in yamux's backlog with their receive buffers
// filling up, so a client that opens one is cut off.
func TestHandleClientConnection_ClosesSessionOnUnexpectedStream(t *testing.T) {
	s := New(&Config{ValidTokens: []string{"good"}, KeepaliveInterval: time.Minute, ConnectionWriteTimeout: 5 * time.Second})
	c1, c2 := net.Pipe()
	defer c2.Close()
	done := make(chan struct{})
	go func() { s.handleClientConnection(c1); close(done) }()

	payload, _ := json.Marshal(protocol.AuthRequest{AuthToken: "good"})
	if err := json.NewEncoder(c2).Encode(protocol.ControlMessage{Type: protocol.AuthRequestType, RawPayload: payload}); err != nil {
		t.Fatalf("send auth: %v", err)
	}
	// Read the auth response byte by byte up to its newline, so no yamux bytes
	// are consumed by a decoder's read-ahead.
	if line, err := readLine(c2); err != nil || !strings.Contains(line, `"success":true`) {
		t.Fatalf("auth response %q, err %v", line, err)
	}

	sess, err := yamux.Client(c2, quietYamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctrl, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("open control stream: %v", err)
	}
	defer ctrl.Close()
	extra, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("open extra stream: %v", err)
	}
	defer extra.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server kept the session open after the client opened an unexpected stream")
	}
}

func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	b := make([]byte, 1)
	for {
		if _, err := r.Read(b); err != nil {
			return sb.String(), err
		}
		if b[0] == '\n' {
			return sb.String(), nil
		}
		sb.WriteByte(b[0])
	}
}

// newTimedProxyTest is newPublicProxyTest with the public server's read and
// write timeouts set, as tunnel-server sets them, and a given idle timeout.
func newTimedProxyTest(t *testing.T, serverTimeout, idle time.Duration) (*yamux.Session, string) {
	t.Helper()
	s := New(&Config{Domain: "localhost", HijackedIdleTimeout: idle})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "pub", Type: "http", PublicURL: "http://127.0.0.1", Status: "active", CreatedAt: time.Now(), Session: serverSess}
	s.tunnels[tun.ID] = tun
	s.httpTunnels["127.0.0.1"] = tun
	ts := httptest.NewUnstartedServer(s)
	ts.Config.ReadTimeout = serverTimeout
	ts.Config.WriteTimeout = serverTimeout
	ts.Start()
	t.Cleanup(ts.Close)
	return clientSess, strings.TrimPrefix(ts.URL, "http://")
}

// SSE is no longer hijacked, so the public server's read/write timeouts would
// cut every stream short; they are lifted for event-stream responses.
func TestServeHTTP_SSEOutlivesServerTimeouts(t *testing.T) {
	const serverTimeout = 300 * time.Millisecond
	backend, addr := newTimedProxyTest(t, serverTimeout, 0)
	go func() {
		stream, err := backend.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		if _, err := http.ReadRequest(bufio.NewReader(stream)); err != nil {
			return
		}
		io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
		for i := 0; i < 8; i++ { // 800ms in all, well past serverTimeout
			time.Sleep(100 * time.Millisecond)
			if _, err := fmt.Fprintf(stream, "data: %d\n\n", i); err != nil {
				return
			}
		}
	}()
	conn, br := dialVisitor(t, addr)

	fmt.Fprint(conn, "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n")
	resp, body := readVisitorResponse(t, br)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "data: 7\n\n") {
		t.Errorf("stream ended early: got %q, want all 8 events", body)
	}
}

// A backend that stops sending must not hold the stream forever.
func TestServeHTTP_SilentSSEBackendIsClosedAfterIdleTimeout(t *testing.T) {
	backend, addr := newTimedProxyTest(t, 0, 200*time.Millisecond)
	go func() {
		stream, err := backend.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		if _, err := http.ReadRequest(bufio.NewReader(stream)); err != nil {
			return
		}
		io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: only\n\n")
		io.Copy(io.Discard, stream) // then silence until the server closes the stream
	}()
	conn, br := dialVisitor(t, addr)

	start := time.Now()
	fmt.Fprint(conn, "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n")
	_, body := readVisitorResponse(t, br) // returns once the stream is closed
	if body != "data: only\n\n" {
		t.Errorf("body=%q", body)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("silent stream closed after %s, want about the 200ms idle timeout", elapsed)
	}
}
