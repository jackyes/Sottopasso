package server

import (
	"Sottopasso/pkg/protocol"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- ServeHTTP: SSE dispatch ---

// An SSE request (GET with Accept: text/event-stream) must be routed through the
// hijack proxy path so the streamed response reaches the public client.
func TestServeHTTP_SSEDispatch(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "sse", Type: "http", PublicURL: "http://127.0.0.1", Status: "active", CreatedAt: time.Now(), Session: serverSess}
	s.tunnels["sse"] = tun
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
		req, err := http.ReadRequest(br)
		if err != nil {
			clientErr <- fmt.Errorf("tunnel client ReadRequest: %w", err)
			return
		}
		if req.Header.Get("Accept") != "text/event-stream" {
			clientErr <- fmt.Errorf("forwarded Accept=%q, want text/event-stream", req.Header.Get("Accept"))
			return
		}
		_, err = io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: hello\n\n")
		clientErr <- err
	}()

	addr := strings.TrimPrefix(ts.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	fmt.Fprint(conn, "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n")

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading status line: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status line=%q, want 200", status)
	}
	for { // drain headers
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	data, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading SSE data: %v", err)
	}
	if !strings.Contains(data, "data: hello") {
		t.Errorf("SSE payload=%q, want it to contain 'data: hello'", data)
	}
	if err := <-clientErr; err != nil {
		t.Errorf("tunnel client side error: %v", err)
	}
}

// --- handleHTTPRequest: error paths ---

// If the tunnel session is dead, OpenStream fails and the proxy must answer the
// public caller with 502/500 rather than hanging or panicking.
func TestHandleHTTPRequest_OpenStreamFailureReturns5xx(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, _ := newYamuxPair(t)
	serverSess.Close() // OpenStream now fails immediately

	tun := &Tunnel{ID: "dead", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://abc.localhost/", nil)

	done := make(chan struct{})
	go func() { s.handleHTTPRequest(rec, req, tun); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHTTPRequest hung when OpenStream failed")
	}
	if rec.Code < 500 {
		t.Errorf("code=%d, want a 5xx error when the tunnel is unavailable", rec.Code)
	}
}

// If the tunnel client closes its stream without producing a response, the proxy
// must give up without panicking or writing a bogus body.
func TestHandleHTTPRequest_ClientClosesWithoutResponding(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://abc.localhost", Status: "active", CreatedAt: time.Now(), Session: serverSess}

	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		stream.Close() // close immediately, no response
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://abc.localhost/", nil)
	done := make(chan struct{})
	go func() { s.handleHTTPRequest(rec, req, tun); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHTTPRequest hung when the client closed without responding")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected no body to be written, got %q", rec.Body.String())
	}
}

// --- setupTCPTunnel: live data path ---

// Drive a full TCP tunnel: a public client connects to the assigned public port,
// the server opens a stream to the tunnel client, and bytes must flow correctly in
// both directions (this exercises the accept loop + Proxy wiring and the byte
// direction of the measured connections).
func TestSetupTCPTunnel_DataPathBothDirections(t *testing.T) {
	s := New(&Config{})
	serverSess, clientSess := newYamuxPair(t)
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- s.setupTCPTunnel(protocol.RequestTunnel{Type: "tcp"}, serverSess, ctrl1) }()
	resp := readControl(t, ctrl2)
	if err := <-errCh; err != nil {
		t.Fatalf("setupTCPTunnel: %v", err)
	}
	var tr protocol.TunnelResponse
	if err := json.Unmarshal(resp.RawPayload, &tr); err != nil {
		t.Fatal(err)
	}

	// Tunnel-client side: accept the server-opened stream and echo with a prefix.
	clientErr := make(chan error, 1)
	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			clientErr <- err
			return
		}
		defer stream.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(stream, buf); err != nil {
			clientErr <- fmt.Errorf("client read: %w", err)
			return
		}
		if string(buf) != "hello" {
			clientErr <- fmt.Errorf("client got %q, want hello", buf)
			return
		}
		_, err = stream.Write(append([]byte("re:"), buf...))
		clientErr <- err
	}()

	// Public client dials the assigned public port (use loopback, not the wildcard host).
	_, port, err := net.SplitHostPort(tr.PublicURL)
	if err != nil {
		t.Fatalf("public URL %q not host:port: %v", tr.PublicURL, err)
	}
	pc, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial public addr: %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := pc.Write([]byte("hello")); err != nil {
		t.Fatalf("public write: %v", err)
	}
	out := make([]byte, len("re:hello"))
	if _, err := io.ReadFull(pc, out); err != nil {
		t.Fatalf("public read echo: %v", err)
	}
	if string(out) != "re:hello" {
		t.Errorf("public got %q, want re:hello", out)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("tunnel client side: %v", err)
	}

	// Traffic must have been accounted in both directions. The counters are bumped
	// by the proxy goroutines slightly after the reads above return, so poll.
	tun := singleTunnel(t, s)
	waitForTunnelTraffic(t, tun)
}

// singleTunnel returns the one tunnel registered on s (fails otherwise).
func singleTunnel(t *testing.T, s *Server) *Tunnel {
	t.Helper()
	s.tunnelsMu.RLock()
	defer s.tunnelsMu.RUnlock()
	if len(s.tunnels) != 1 {
		t.Fatalf("len(tunnels)=%d, want exactly 1", len(s.tunnels))
	}
	for _, tn := range s.tunnels {
		return tn
	}
	return nil
}

// waitForTunnelTraffic polls until both byte counters are non-zero or times out.
func waitForTunnelTraffic(t *testing.T, tun *Tunnel) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if tun.TotalBytesIn.Load() > 0 && tun.TotalBytesOut.Load() > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Errorf("expected non-zero traffic both ways, in=%d out=%d",
		tun.TotalBytesIn.Load(), tun.TotalBytesOut.Load())
}

// A tunnel's traffic counters must reflect the bytes that actually crossed the
// public boundary exactly once: 5 bytes in, 8 bytes out for this round trip. The
// proxy wires both legs of the connection, so a naive implementation that measures
// both legs into the same counters double-counts every byte.
func TestSetupTCPTunnel_CountsEachByteOnce(t *testing.T) {
	s := New(&Config{})
	serverSess, clientSess := newYamuxPair(t)
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- s.setupTCPTunnel(protocol.RequestTunnel{Type: "tcp"}, serverSess, ctrl1) }()
	resp := readControl(t, ctrl2)
	if err := <-errCh; err != nil {
		t.Fatalf("setupTCPTunnel: %v", err)
	}
	var tr protocol.TunnelResponse
	json.Unmarshal(resp.RawPayload, &tr)
	_, port, _ := net.SplitHostPort(tr.PublicURL)

	go func() {
		stream, err := clientSess.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(stream, buf); err != nil {
			return
		}
		stream.Write(append([]byte("re:"), buf...)) // 8 bytes back
	}()

	pc, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := pc.Write([]byte("hello")); err != nil { // 5 bytes in
		t.Fatalf("write: %v", err)
	}
	out := make([]byte, len("re:hello"))
	if _, err := io.ReadFull(pc, out); err != nil { // 8 bytes out
		t.Fatalf("read echo: %v", err)
	}

	tun := singleTunnel(t, s)
	// By the time the echo has been fully read, both counters have settled. Poll
	// briefly to absorb the small async gap, then require the exact public byte counts.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if tun.TotalBytesIn.Load() == 5 && tun.TotalBytesOut.Load() == 8 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Errorf("traffic counters = (in=%d, out=%d), want (5, 8): each byte should be counted once across the public boundary, not once per proxied leg",
		tun.TotalBytesIn.Load(), tun.TotalBytesOut.Load())
}

// Two public connections through the same TCP tunnel must each be proxied,
// exercising more than one iteration of the accept loop.
func TestSetupTCPTunnel_HandlesMultipleConnections(t *testing.T) {
	s := New(&Config{})
	serverSess, clientSess := newYamuxPair(t)
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- s.setupTCPTunnel(protocol.RequestTunnel{Type: "tcp"}, serverSess, ctrl1) }()
	resp := readControl(t, ctrl2)
	if err := <-errCh; err != nil {
		t.Fatalf("setupTCPTunnel: %v", err)
	}
	var tr protocol.TunnelResponse
	json.Unmarshal(resp.RawPayload, &tr)
	_, port, _ := net.SplitHostPort(tr.PublicURL)

	// Client side: keep accepting streams and echo each one's first 4 bytes.
	go func() {
		for {
			stream, err := clientSess.AcceptStream()
			if err != nil {
				return
			}
			go func(st net.Conn) {
				defer st.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(st, buf); err != nil {
					return
				}
				st.Write(buf)
			}(stream)
		}
	}()

	for i := 0; i < 2; i++ {
		pc, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			t.Fatalf("conn %d dial: %v", i, err)
		}
		pc.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := pc.Write([]byte("ping")); err != nil {
			t.Fatalf("conn %d write: %v", i, err)
		}
		out := make([]byte, 4)
		if _, err := io.ReadFull(pc, out); err != nil {
			t.Fatalf("conn %d read: %v", i, err)
		}
		if string(out) != "ping" {
			t.Errorf("conn %d got %q, want ping", i, out)
		}
		pc.Close()
	}
}

// --- handleClientConnection: auth rejection ---

// A client that presents an invalid token must be rejected, the connection
// returned (closed), and no tunnel/session state left behind.
func TestHandleClientConnection_RejectsBadAuth(t *testing.T) {
	s := New(&Config{ValidTokens: []string{"good"}})
	c1, c2 := net.Pipe()
	defer c2.Close()

	done := make(chan struct{})
	go func() { s.handleClientConnection(c1); close(done) }()

	payload, _ := json.Marshal(protocol.AuthRequest{AuthToken: "bad"})
	if err := json.NewEncoder(c2).Encode(protocol.ControlMessage{Type: protocol.AuthRequestType, RawPayload: payload}); err != nil {
		t.Fatalf("send auth: %v", err)
	}

	var resp protocol.ControlMessage
	if err := json.NewDecoder(c2).Decode(&resp); err != nil {
		t.Fatalf("decode auth response: %v", err)
	}
	var ar protocol.AuthResponse
	json.Unmarshal(resp.RawPayload, &ar)
	if ar.Success {
		t.Error("server accepted an invalid token")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleClientConnection did not return after auth failure")
	}
	if len(s.tunnels) != 0 {
		t.Errorf("len(tunnels)=%d, want 0 after rejected auth", len(s.tunnels))
	}
}

// --- getTLSConfig: invalid existing files ---

func TestGetTLSConfig_InvalidCertFileErrors(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "c.pem")
	key := filepath.Join(dir, "k.pem")
	// Files exist but contain garbage -> generation is skipped and load must fail.
	if err := os.WriteFile(cert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(&Config{})
	if _, err := s.getTLSConfig(cert, key, "localhost"); err == nil {
		t.Error("expected an error loading an invalid cert/key pair")
	}
}

// --- serveDashboard: POST dispatch ---

func TestServeDashboard_POSTDispatchesToCloseTunnel(t *testing.T) {
	s := New(&Config{})
	sess, _ := newYamuxPair(t)
	s.tunnels["abc"] = &Tunnel{ID: "abc", Type: "tcp", Session: sess}

	rec := httptest.NewRecorder()
	req := postForm(url.Values{"csrf_token": {s.csrfToken}, "tunnelId": {"abc"}})
	s.serveDashboard(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("code=%d, want 302 (POST should dispatch to handleCloseTunnel)", rec.Code)
	}
	if !sess.IsClosed() {
		t.Error("expected the tunnel session to be closed via the POST path")
	}
}

// --- defensive / malformed-input branches ---

// A WebSocket/SSE upgrade can only be served if the ResponseWriter supports
// hijacking. httptest.NewRecorder() does not, so the server must fail with 500
// instead of panicking.
func TestHandleHijackedRequest_NonHijackerReturns500(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	sess, _ := newYamuxPair(t)
	tun := &Tunnel{ID: "x", Type: "http", PublicURL: "http://h", Session: sess, Status: "active", CreatedAt: time.Now()}
	s.tunnels["x"] = tun
	s.httpTunnels["h"] = tun

	rec := httptest.NewRecorder() // not an http.Hijacker
	req := httptest.NewRequest("GET", "http://h/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("code=%d, want 500 when the ResponseWriter cannot be hijacked", rec.Code)
	}
}

// An unknown control message type must be ignored (logged) without tearing down
// the stream, so subsequent valid messages are still processed.
func TestServeControlStream_IgnoresUnknownTypeThenServes(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)
	cs, err := clientSess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := serverSess.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	go s.serveControlStream(serverSess, ss)

	enc := json.NewEncoder(cs)
	if err := enc.Encode(protocol.ControlMessage{Type: protocol.MessageType("bogus"), RawPayload: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(protocol.RequestTunnel{Type: "http", Subdomain: "ok"})
	if err := enc.Encode(protocol.ControlMessage{Type: protocol.RequestTunnelType, RawPayload: payload}); err != nil {
		t.Fatal(err)
	}

	cs.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp protocol.ControlMessage
	if err := json.NewDecoder(cs).Decode(&resp); err != nil {
		t.Fatalf("decoding response after an unknown message: %v", err)
	}
	if resp.Type != protocol.TunnelResponseType {
		t.Fatalf("response type=%q, want %q", resp.Type, protocol.TunnelResponseType)
	}
	var tr protocol.TunnelResponse
	json.Unmarshal(resp.RawPayload, &tr)
	if tr.PublicURL != "http://ok.localhost" {
		t.Errorf("PublicURL=%q, want http://ok.localhost", tr.PublicURL)
	}
}

// A malformed auth payload (valid envelope, junk inner JSON) must be rejected.
func TestAuthenticate_MalformedPayloadRejected(t *testing.T) {
	s := New(&Config{ValidTokens: []string{"good"}})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	res := make(chan bool, 1)
	go func() { res <- s.authenticate(c1) }()

	// RawPayload is a JSON string, not an AuthRequest object -> inner unmarshal fails.
	if err := json.NewEncoder(c2).Encode(protocol.ControlMessage{Type: protocol.AuthRequestType, RawPayload: []byte(`"not-an-object"`)}); err != nil {
		t.Fatal(err)
	}
	if <-res {
		t.Error("authenticate accepted a malformed auth payload")
	}
}

// A malformed RequestTunnel payload must surface an error rather than creating a tunnel.
func TestHandleRequestTunnel_MalformedPayload(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	sess, _ := newYamuxPair(t)
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	msg := &protocol.ControlMessage{Type: protocol.RequestTunnelType, RawPayload: []byte(`"bad"`)}
	if err := s.handleRequestTunnel(msg, sess, ctrl1); err == nil {
		t.Error("expected an error for a malformed RequestTunnel payload")
	}
	if len(s.tunnels) != 0 {
		t.Errorf("len(tunnels)=%d, want 0", len(s.tunnels))
	}
}

// --- serveControlStream: oversized message ---

// A single control message larger than the 1 MiB cap must cause the server to
// disconnect the stream (rather than buffer unbounded memory) and must not create
// a tunnel.
func TestServeControlStream_RejectsOversizedMessage(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	serverSess, clientSess := newYamuxPair(t)

	clientStream, err := clientSess.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	serverStream, err := serverSess.AcceptStream()
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	done := make(chan struct{})
	go func() { s.serveControlStream(serverSess, serverStream); close(done) }()

	huge := strings.Repeat("a", (1<<20)+1024) // > maxControlMessageSize
	payload, _ := json.Marshal(protocol.RequestTunnel{Type: "http", Subdomain: huge})
	msg := protocol.ControlMessage{Type: protocol.RequestTunnelType, RawPayload: payload}
	// Write in the background: once the server hits the cap it stops reading, so the
	// write may block on flow control.
	go func() { json.NewEncoder(clientStream).Encode(msg) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveControlStream did not disconnect on an oversized message")
	}
	if len(s.tunnels) != 0 {
		t.Errorf("len(tunnels)=%d, want 0 (oversized message must not create a tunnel)", len(s.tunnels))
	}
}
