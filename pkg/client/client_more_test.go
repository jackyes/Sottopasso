package client

import (
	"Sottopasso/pkg/protocol"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Start must fail fast with a connection error when the control server is down,
// rather than blocking or panicking.
func TestStart_DialFailure(t *testing.T) {
	// Reserve then release a port so nothing is listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := New(&Config{
		ServerAddr:             addr,
		AuthToken:              "x",
		InsecureSkipVerify:     true,
		KeepaliveInterval:      time.Second,
		ConnectionWriteTimeout: time.Second,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start() }()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Start returned nil, want a connection error")
		}
		if !strings.Contains(err.Error(), "unable to connect") {
			t.Errorf("error=%v, want it to mention the connection failure", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return on dial failure")
	}
}

// handleServerStream must dial the local service and proxy bytes both ways.
func TestHandleServerStream_ProxiesToLocalService(t *testing.T) {
	// Local echo service: reads 4 bytes, replies with "ok:"+those bytes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		conn.Write(append([]byte("ok:"), buf...))
	}()

	c := New(&Config{LocalPort: port})
	streamSide, publicSide := net.Pipe()

	done := make(chan struct{})
	go func() { c.handleServerStream(streamSide); close(done) }()

	publicSide.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := publicSide.Write([]byte("ping")); err != nil {
		t.Fatalf("write to stream: %v", err)
	}
	out := make([]byte, len("ok:ping"))
	if _, err := io.ReadFull(publicSide, out); err != nil {
		t.Fatalf("read relayed response: %v", err)
	}
	if string(out) != "ok:ping" {
		t.Errorf("relayed response=%q, want ok:ping", out)
	}

	publicSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleServerStream did not return after the stream closed")
	}
}

// authenticate must surface a write error when the control connection is already
// closed (the request cannot be sent).
func TestAuthenticate_WriteError(t *testing.T) {
	c := New(&Config{AuthToken: "x"})
	c1, c2 := net.Pipe()
	c1.Close()
	c2.Close()

	if err := c.authenticate(c1); err == nil {
		t.Fatal("expected an error sending auth on a closed connection")
	}
}

// authenticate must surface a decode error when the server closes without replying.
func TestAuthenticate_DecodeError(t *testing.T) {
	c := New(&Config{AuthToken: "x"})
	c1, c2 := net.Pipe()
	defer c1.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- c.authenticate(c1) }()

	decode(t, c2) // consume the auth request
	c2.Close()    // close without sending a response

	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "decoding auth response") {
		t.Fatalf("error=%v, want a decode error", err)
	}
}

// authenticate must surface an error when the server replies with the right
// message type but a payload that is not a valid AuthResponse.
func TestAuthenticate_MalformedResponsePayload(t *testing.T) {
	c := New(&Config{AuthToken: "x"})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- c.authenticate(c1) }()

	decode(t, c2) // consume the auth request
	// Right type, junk inner payload (a JSON string, not an AuthResponse object).
	if err := json.NewEncoder(c2).Encode(protocol.ControlMessage{Type: protocol.AuthResponseType, RawPayload: []byte(`"junk"`)}); err != nil {
		t.Fatal(err)
	}

	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "unmarshaling AuthResponse") {
		t.Fatalf("error=%v, want an AuthResponse unmarshal error", err)
	}
}

// requestTunnel must surface a write error when the control connection is closed.
func TestRequestTunnel_WriteError(t *testing.T) {
	c := New(&Config{TunnelType: "http", LocalPort: 80})
	c1, c2 := net.Pipe()
	c1.Close()
	c2.Close()

	if _, err := c.requestTunnel(c1); err == nil {
		t.Fatal("expected an error sending the tunnel request on a closed connection")
	}
}
