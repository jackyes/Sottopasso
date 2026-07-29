package client

import (
	"Sottopasso/pkg/protocol"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestNextBackoff(t *testing.T) {
	tests := []struct {
		name     string
		cur, max time.Duration
		want     time.Duration
	}{
		{"doubles", time.Second, time.Minute, 2 * time.Second},
		{"clamps to max", 40 * time.Second, time.Minute, time.Minute},
		{"already at max", time.Minute, time.Minute, time.Minute},
		{"max below cur", 2 * time.Minute, time.Minute, time.Minute},
		{"zero starts at max", 0, time.Minute, time.Minute},
		{"overflow clamps", time.Duration(1)<<62 + 1, time.Minute, time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextBackoff(tt.cur, tt.max); got != tt.want {
				t.Errorf("nextBackoff(%v, %v)=%v, want %v", tt.cur, tt.max, got, tt.want)
			}
		})
	}
}

// jitter must stay within [d/2, d] so the reconnect delay never collapses to
// zero (a busy loop) nor exceeds the configured ceiling.
func TestJitterStaysWithinHalfRange(t *testing.T) {
	const d = time.Second
	for i := 0; i < 200; i++ {
		got := jitter(d)
		if got < d/2 || got > d {
			t.Fatalf("jitter(%v)=%v, want within [%v, %v]", d, got, d/2, d)
		}
	}
	if got := jitter(0); got != 0 {
		t.Errorf("jitter(0)=%v, want 0", got)
	}
}

func TestSubdomainOf(t *testing.T) {
	tests := []struct {
		publicURL string
		want      string
	}{
		{"http://itest.localhost", "itest"},
		{"https://myapp.example.com", "myapp"},
		{"http://MyApp.example.com", "myapp"},
		{"http://itest.localhost:8080", "itest"},
		{"http://localhost", "localhost"},
		{"tcp://1.2.3.4:9000", "1"},
		{"myapp.localhost", ""}, // no scheme, so no host to read
		{"", ""},
		{"://bad", ""},
	}
	for _, tt := range tests {
		t.Run(tt.publicURL, func(t *testing.T) {
			if got := subdomainOf(tt.publicURL); got != tt.want {
				t.Errorf("subdomainOf(%q)=%q, want %q", tt.publicURL, got, tt.want)
			}
		})
	}
}

// testServerTLSConfig returns a self-signed certificate for 127.0.0.1. Clients
// in these tests set InsecureSkipVerify, so only the handshake has to succeed.
func testServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sottopasso-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// testControlServer is a minimal stand-in for pkg/server: it answers the auth
// handshake, then speaks yamux and replies to the tunnel request with whatever
// the test script dictates. It exists so client-side retry behaviour can be
// driven without standing up the real server.
type testControlServer struct {
	ln    net.Listener
	addr  string
	conns atomic.Int32 // connections accepted so far

	authOK bool
	// tunnelReply is called with the 1-based sequence number of the tunnel
	// request across the server's lifetime.
	tunnelReply func(n int) protocol.TunnelResponse

	mu       sync.Mutex
	requests int
}

func newTestControlServer(t *testing.T, authOK bool, tunnelReply func(n int) protocol.TunnelResponse) *testControlServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", testServerTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s := &testControlServer{ln: ln, addr: ln.Addr().String(), authOK: authOK, tunnelReply: tunnelReply}

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				break
			}
			s.conns.Add(1)
			wg.Add(1)
			go func() { defer wg.Done(); s.handle(conn) }()
		}
	}()
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return s
}

func (s *testControlServer) handle(conn net.Conn) {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	var msg protocol.ControlMessage
	if err := dec.Decode(&msg); err != nil {
		return
	}
	payload, _ := json.Marshal(protocol.AuthResponse{Success: s.authOK, Error: "nope"})
	if err := json.NewEncoder(conn).Encode(protocol.ControlMessage{
		Type: protocol.AuthResponseType, RawPayload: payload,
	}); err != nil || !s.authOK {
		return
	}

	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false // keeps test output free of keepalive noise
	cfg.LogOutput = io.Discard  // yamux rejects setting both LogOutput and Logger
	session, err := yamux.Server(conn, cfg)
	if err != nil {
		return
	}
	defer session.Close()

	ctrlStream, err := session.AcceptStream()
	if err != nil {
		return
	}
	defer ctrlStream.Close()

	ctrlDec := json.NewDecoder(ctrlStream)
	for {
		var req protocol.ControlMessage
		if err := ctrlDec.Decode(&req); err != nil {
			return
		}
		if req.Type != protocol.RequestTunnelType {
			continue
		}
		s.mu.Lock()
		s.requests++
		n := s.requests
		s.mu.Unlock()

		respPayload, _ := json.Marshal(s.tunnelReply(n))
		if err := json.NewEncoder(ctrlStream).Encode(protocol.ControlMessage{
			Type: protocol.TunnelResponseType, RawPayload: respPayload,
		}); err != nil {
			return
		}
	}
}

func (s *testControlServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// testClientConfig returns a Config pointed at addr with backoffs short enough
// that a test does not spend seconds waiting between attempts.
func testClientConfig(addr string) *Config {
	return &Config{
		ServerAddr:             addr,
		AuthToken:              "tok",
		TunnelType:             "http",
		LocalPort:              1,
		InsecureSkipVerify:     true,
		KeepaliveInterval:      30 * time.Second,
		ConnectionWriteTimeout: 5 * time.Second,
		ConnectTimeout:         2 * time.Second,
		ReconnectMinBackoff:    10 * time.Millisecond,
		ReconnectMaxBackoff:    30 * time.Millisecond,
	}
}

// Start must keep retrying while the control server is unreachable, and return
// nil (a clean shutdown, not a failure) once its context is cancelled.
func TestStart_RetriesOnDialFailure(t *testing.T) {
	// A listener that accepts and immediately closes fails the TLS handshake,
	// which is the transient case Start has to ride out. It also lets us count
	// attempts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var accepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()

	c := New(testClientConfig(ln.Addr().String()))
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(ctx) }()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned %v, want nil on context cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after its context was cancelled")
	}

	if n := accepted.Load(); n < 2 {
		t.Errorf("server saw %d connection attempts, want at least 2 (Start did not retry)", n)
	}
}

// A rejected token cannot be fixed by reconnecting, so Start must give up at
// once instead of hammering the server.
func TestStart_FatalAuthErrorStopsImmediately(t *testing.T) {
	srv := newTestControlServer(t, false, nil)

	c := New(testClientConfig(srv.addr))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(ctx) }()

	var err error
	select {
	case err = <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Start kept retrying after the server rejected authentication")
	}

	var fatal *FatalError
	if !errors.As(err, &fatal) {
		t.Fatalf("error=%v (%T), want a *FatalError", err, err)
	}
	if !strings.Contains(err.Error(), "rejected authentication") {
		t.Errorf("error=%q, want it to mention the rejection", err)
	}
	if n := srv.conns.Load(); n != 1 {
		t.Errorf("server saw %d connections, want exactly 1", n)
	}
}

// The server silently hands out a random subdomain while the previous session
// still holds the requested one. runSession must reject that session instead of
// reporting it as established, so Start retries and eventually reclaims the URL.
func TestRunSession_RetriesUntilSubdomainReclaimed(t *testing.T) {
	srv := newTestControlServer(t, true, func(n int) protocol.TunnelResponse {
		if n == 1 {
			return protocol.TunnelResponse{PublicURL: "http://random123.localhost"}
		}
		return protocol.TunnelResponse{PublicURL: "http://myapp.localhost"}
	})

	cfg := testClientConfig(srv.addr)
	cfg.Subdomain = "myapp"
	c := New(cfg)

	// First attempt: the server grants a different subdomain, so the session is
	// discarded without ever being reported up.
	established := false
	err := c.runSession(context.Background(), func() { established = true })
	if err == nil {
		t.Fatal("runSession returned nil, want an error when the subdomain was not granted")
	}
	if !strings.Contains(err.Error(), "not granted") {
		t.Errorf("error=%q, want it to mention the subdomain was not granted", err)
	}
	if established {
		t.Error("onEstablished fired for a session served from the wrong subdomain")
	}

	// Second attempt: the subdomain is free again and the session comes up.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upCh := make(chan struct{})
	go func() {
		// Cancel once the tunnel is up; runSession would otherwise block in
		// AcceptStream for the life of the session.
		<-upCh
		cancel()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runSession(ctx, func() { close(upCh) })
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runSession did not return after its context was cancelled")
	}

	select {
	case <-upCh:
	default:
		t.Fatal("onEstablished never fired even though the requested subdomain was granted")
	}

	if n := srv.requestCount(); n != 2 {
		t.Errorf("server handled %d tunnel requests, want 2", n)
	}
}

// A cancelled context must interrupt the backoff wait rather than let it run to
// completion, so Ctrl-C is responsive during a long reconnect delay.
func TestStart_CancelDuringBackoffReturnsPromptly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listening: the first attempt fails and Start backs off

	cfg := testClientConfig(addr)
	cfg.ReconnectMinBackoff = 30 * time.Second
	cfg.ReconnectMaxBackoff = 30 * time.Second
	c := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Start(ctx) }()

	time.Sleep(200 * time.Millisecond) // let the first attempt fail and enter the wait
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned %v, want nil on cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start waited out the backoff instead of returning when cancelled")
	}
}
