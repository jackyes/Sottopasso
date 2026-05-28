package client

import (
	"Sottopasso/pkg/protocol"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func decode(t *testing.T, conn net.Conn) protocol.ControlMessage {
	t.Helper()
	var msg protocol.ControlMessage
	if err := json.NewDecoder(conn).Decode(&msg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return msg
}

func reply(t *testing.T, conn net.Conn, mtype protocol.MessageType, inner interface{}) {
	t.Helper()
	payload, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(protocol.ControlMessage{Type: mtype, RawPayload: payload}); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

func TestAuthenticate_Success(t *testing.T) {
	c := New(&Config{AuthToken: "tok"})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- c.authenticate(c1) }()

	// Server side reads the auth request and verifies it.
	req := decode(t, c2)
	if req.Type != protocol.AuthRequestType {
		t.Errorf("request type=%q, want %q", req.Type, protocol.AuthRequestType)
	}
	var ar protocol.AuthRequest
	json.Unmarshal(req.RawPayload, &ar)
	if ar.AuthToken != "tok" {
		t.Errorf("token=%q, want tok", ar.AuthToken)
	}
	reply(t, c2, protocol.AuthResponseType, protocol.AuthResponse{Success: true})

	if err := <-errCh; err != nil {
		t.Fatalf("authenticate returned error on success: %v", err)
	}
}

func TestAuthenticate_ServerRejects(t *testing.T) {
	c := New(&Config{AuthToken: "tok"})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- c.authenticate(c1) }()

	decode(t, c2)
	reply(t, c2, protocol.AuthResponseType, protocol.AuthResponse{Success: false, Error: "bad creds"})

	err := <-errCh
	if err == nil {
		t.Fatal("expected error when server rejects authentication")
	}
	if !strings.Contains(err.Error(), "bad creds") {
		t.Errorf("error=%q, want it to mention server reason", err)
	}
}

func TestAuthenticate_UnexpectedResponseType(t *testing.T) {
	c := New(&Config{AuthToken: "tok"})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- c.authenticate(c1) }()

	decode(t, c2)
	reply(t, c2, protocol.TunnelResponseType, protocol.TunnelResponse{PublicURL: "x"})

	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "unexpected message type") {
		t.Fatalf("error=%v, want 'unexpected message type'", err)
	}
}

func TestRequestTunnel_Success(t *testing.T) {
	c := New(&Config{TunnelType: "http", LocalPort: 3000, Subdomain: "myapp"})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	resCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		url, err := c.requestTunnel(c1)
		resCh <- url
		errCh <- err
	}()

	req := decode(t, c2)
	if req.Type != protocol.RequestTunnelType {
		t.Errorf("request type=%q, want %q", req.Type, protocol.RequestTunnelType)
	}
	var rt protocol.RequestTunnel
	json.Unmarshal(req.RawPayload, &rt)
	if rt.Type != "http" || rt.LocalPort != 3000 || rt.Subdomain != "myapp" {
		t.Errorf("decoded request %+v, unexpected", rt)
	}
	reply(t, c2, protocol.TunnelResponseType, protocol.TunnelResponse{PublicURL: "http://myapp.localhost"})

	if err := <-errCh; err != nil {
		t.Fatalf("requestTunnel error: %v", err)
	}
	if url := <-resCh; url != "http://myapp.localhost" {
		t.Errorf("public URL=%q, want http://myapp.localhost", url)
	}
}

func TestRequestTunnel_ServerError(t *testing.T) {
	c := New(&Config{TunnelType: "tcp", LocalPort: 22})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := c.requestTunnel(c1)
		errCh <- err
	}()

	decode(t, c2)
	reply(t, c2, protocol.TunnelResponseType, protocol.TunnelResponse{Error: "no ports available"})

	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "no ports available") {
		t.Fatalf("error=%v, want it to surface the server error", err)
	}
}

func TestRequestTunnel_UnexpectedType(t *testing.T) {
	c := New(&Config{TunnelType: "http", LocalPort: 80})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := c.requestTunnel(c1)
		errCh <- err
	}()

	decode(t, c2)
	reply(t, c2, protocol.AuthResponseType, protocol.AuthResponse{Success: true})

	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "unexpected message type") {
		t.Fatalf("error=%v, want 'unexpected message type'", err)
	}
}

// handleServerStream should fail fast (and not hang) when the local service is
// unreachable. We point it at a port that nothing is listening on.
func TestHandleServerStream_LocalServiceUnreachable(t *testing.T) {
	// Find a port that is closed by opening then immediately closing a listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	c := New(&Config{LocalPort: port})
	server, client := net.Pipe()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		c.handleServerStream(client) // closes client when done
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleServerStream hung when local service was unreachable")
	}
}
