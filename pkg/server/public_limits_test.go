package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"Sottopasso/pkg/protocol"

	"github.com/hashicorp/yamux"
)

// openTunnel asks s for a tunnel of the given type on serverSess and returns
// its public URL or address.
func openTunnel(t *testing.T, s *Server, serverSess *yamux.Session, req protocol.RequestTunnel) string {
	t.Helper()
	ctrl1, ctrl2 := net.Pipe()
	t.Cleanup(func() { ctrl1.Close(); ctrl2.Close() })
	errCh := make(chan error, 1)
	go func() { errCh <- s.handleRequestTunnel(controlMessage(t, req), serverSess, ctrl1) }()
	resp := readControl(t, ctrl2)
	if err := <-errCh; err != nil {
		t.Fatalf("tunnel setup: %v", err)
	}
	var tr protocol.TunnelResponse
	if err := json.Unmarshal(resp.RawPayload, &tr); err != nil || tr.Error != "" {
		t.Fatalf("tunnel setup: %q, %v", tr.Error, err)
	}
	return tr.PublicURL
}

func controlMessage(t *testing.T, req protocol.RequestTunnel) *protocol.ControlMessage {
	t.Helper()
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.ControlMessage{Type: protocol.RequestTunnelType, RawPayload: payload}
}

// holdingBackend accepts streams on sess, reads one request from each and
// answers 204 only once release is closed. Every accepted stream is reported
// on the returned channel.
func holdingBackend(sess *yamux.Session, release <-chan struct{}) <-chan struct{} {
	accepted := make(chan struct{}, 64)
	go func() {
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer stream.Close()
				if _, err := http.ReadRequest(bufio.NewReader(stream)); err != nil {
					return
				}
				accepted <- struct{}{}
				<-release
				io.WriteString(stream, "HTTP/1.1 204 No Content\r\n\r\n")
			}(stream)
		}
	}()
	return accepted
}

func waitFor(t *testing.T, ch <-chan struct{}, n int, what string) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: got %d, want %d", what, i, n)
		}
	}
}

// One source must not be able to take every request slot of a tunnel.
func TestHTTPTunnel_LimitsConcurrentRequestsPerSource(t *testing.T) {
	s := New(&Config{Domain: "localhost", MaxConnsPerIPPerTunnel: 2})
	serverSess, clientSess := newYamuxPair(t)
	url := openTunnel(t, s, serverSess, protocol.RequestTunnel{Type: "http", Subdomain: "limited"})
	if url != "http://limited.localhost" {
		t.Fatalf("PublicURL=%q", url)
	}
	release := make(chan struct{})
	accepted := holdingBackend(clientSess, release)

	request := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://limited.localhost/", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}

	var wg sync.WaitGroup
	codes := make(chan int, 3)
	for _, remote := range []string{"203.0.113.1:1001", "203.0.113.1:1002"} {
		wg.Add(1)
		go func(remote string) { defer wg.Done(); codes <- request(remote).Code }(remote)
	}
	waitFor(t, accepted, 2, "requests in flight from 203.0.113.1")

	// A third request from the same source is refused at once...
	third := make(chan int, 1)
	go func() { third <- request("203.0.113.1:1003").Code }()
	select {
	case code := <-third:
		if code != http.StatusTooManyRequests {
			t.Errorf("third concurrent request from one source: code=%d, want 429", code)
		}
	case <-time.After(2 * time.Second):
		close(release) // unblock everything before failing
		t.Fatal("third concurrent request from one source was forwarded to the backend instead of refused")
	}
	// ...while another source still gets through.
	wg.Add(1)
	go func() { defer wg.Done(); codes <- request("198.51.100.9:2000").Code }()
	waitFor(t, accepted, 1, "request from another source")

	close(release)
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusNoContent {
			t.Errorf("admitted request: code=%d, want 204", code)
		}
	}
	// Slots are given back: the first source may send again.
	release2 := make(chan struct{})
	close(release2)
	holdingBackend(clientSess, release2)
	if rec := request("203.0.113.1:1004"); rec.Code == http.StatusTooManyRequests {
		t.Error("per-source slots were not released after the requests finished")
	}
}

// dialTCPTunnel connects to a TCP tunnel's public port on loopback.
func dialTCPTunnel(t *testing.T, publicAddr string) net.Conn {
	t.Helper()
	_, port, err := net.SplitHostPort(publicAddr)
	if err != nil {
		t.Fatalf("bad public address %q: %v", publicAddr, err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// echoBackend echoes everything on every stream it accepts, reporting each
// accepted stream.
func echoBackend(sess *yamux.Session) <-chan struct{} {
	accepted := make(chan struct{}, 64)
	go func() {
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func(stream net.Conn) {
				defer stream.Close()
				io.Copy(stream, stream)
			}(stream)
		}
	}()
	return accepted
}

// expectClosed reports whether the server closed conn without forwarding it.
func expectClosed(t *testing.T, conn net.Conn, within time.Duration, what string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("%s: read %d bytes, want the connection closed", what, n)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s: connection still open after %s", what, within)
	}
}

func TestTCPTunnel_LimitsConcurrentConnectionsPerSource(t *testing.T) {
	s := New(&Config{MaxConnsPerIPPerTunnel: 2})
	serverSess, clientSess := newYamuxPair(t)
	addr := openTunnel(t, s, serverSess, protocol.RequestTunnel{Type: "tcp"})
	accepted := echoBackend(clientSess)

	for i := 0; i < 2; i++ {
		c := dialTCPTunnel(t, addr)
		c.Write([]byte("x"))
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			t.Fatalf("connection %d not forwarded: %v", i+1, err)
		}
	}
	waitFor(t, accepted, 2, "forwarded connections")

	third := dialTCPTunnel(t, addr)
	expectClosed(t, third, 2*time.Second, "third concurrent connection from one source")
	select {
	case <-accepted:
		t.Error("the refused connection was forwarded to the client")
	default:
	}
}

// An idle public TCP connection used to hold its slot forever.
func TestTCPTunnel_ClosesIdleConnections(t *testing.T) {
	s := New(&Config{TCPIdleTimeout: 200 * time.Millisecond})
	serverSess, clientSess := newYamuxPair(t)
	addr := openTunnel(t, s, serverSess, protocol.RequestTunnel{Type: "tcp"})
	echoBackend(clientSess)

	// An active connection survives well past the idle timeout...
	active := dialTCPTunnel(t, addr)
	for i := 0; i < 6; i++ {
		if _, err := active.Write([]byte("x")); err != nil {
			t.Fatalf("active connection write %d: %v", i, err)
		}
		if _, err := io.ReadFull(active, make([]byte, 1)); err != nil {
			t.Fatalf("active connection closed while in use (after %d round trips): %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// ...a silent one does not.
	idle := dialTCPTunnel(t, addr)
	expectClosed(t, idle, 2*time.Second, "idle TCP connection")
}

// --- public listener caps ---

func newLoopbackListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// acceptAll accepts on ln and reports every connection it is handed.
func acceptAll(ln net.Listener) <-chan net.Conn {
	conns := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(conns)
				return
			}
			conns <- c
		}
	}()
	return conns
}

func receiveConn(t *testing.T, conns <-chan net.Conn, what string) net.Conn {
	t.Helper()
	select {
	case c := <-conns:
		return c
	case <-time.After(3 * time.Second):
		t.Fatalf("%s was not accepted", what)
		return nil
	}
}

func TestLimitListener_PerSourceCap(t *testing.T) {
	base := newLoopbackListener(t)
	ln := newLimitListener(base, 0, 2)
	conns := acceptAll(ln)

	c1, _ := net.Dial("tcp", base.Addr().String())
	c2, _ := net.Dial("tcp", base.Addr().String())
	defer c1.Close()
	defer c2.Close()
	s1 := receiveConn(t, conns, "first connection")
	receiveConn(t, conns, "second connection")

	c3, _ := net.Dial("tcp", base.Addr().String())
	defer c3.Close()
	expectClosed(t, c3, 2*time.Second, "third connection from one source")

	// Closing an accepted connection gives its slot back.
	s1.Close()
	c4, _ := net.Dial("tcp", base.Addr().String())
	defer c4.Close()
	receiveConn(t, conns, "connection after a slot was freed")
}

func TestLimitListener_GlobalCap(t *testing.T) {
	base := newLoopbackListener(t)
	ln := newLimitListener(base, 2, 0)
	conns := acceptAll(ln)

	c1, _ := net.Dial("tcp", base.Addr().String())
	c2, _ := net.Dial("tcp", base.Addr().String())
	defer c1.Close()
	defer c2.Close()
	receiveConn(t, conns, "first connection")
	s2 := receiveConn(t, conns, "second connection")

	c3, _ := net.Dial("tcp", base.Addr().String())
	defer c3.Close()
	expectClosed(t, c3, 2*time.Second, "connection over the global cap")

	s2.Close()
	s2.Close() // a second Close must not free a second slot
	c4, _ := net.Dial("tcp", base.Addr().String())
	c5, _ := net.Dial("tcp", base.Addr().String())
	defer c4.Close()
	defer c5.Close()
	receiveConn(t, conns, "connection after a slot was freed")
	expectClosed(t, c5, 2*time.Second, "connection over the cap after a double Close")
}

func TestLimitListener_DisabledReturnsBase(t *testing.T) {
	base := newLoopbackListener(t)
	if ln := newLimitListener(base, 0, 0); ln != base {
		t.Error("with both caps disabled the listener must be returned unwrapped")
	}
}

// The public HTTP listener must actually be wrapped by the caps.
func TestStartHTTPListener_AppliesPerSourceCap(t *testing.T) {
	addr := freeAddrs(t, 1)[0]
	s := New(&Config{HTTPAddr: addr, Domain: "localhost", MaxPublicConnsPerIP: 1})
	go s.startHTTPListener()
	defer s.Shutdown()
	waitDial(t, addr, 5*time.Second)

	// The probe connection's slot is released asynchronously: retry until a
	// connection is served, then keep it open.
	var first net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for first == nil {
		if time.Now().After(deadline) {
			t.Fatal("no connection was ever served")
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		io.WriteString(c, "GET / HTTP/1.1\r\nHost: nothing.localhost\r\n\r\n")
		if line, err := bufio.NewReader(c).ReadString('\n'); err == nil && strings.Contains(line, "404") {
			first = c
		} else {
			c.Close()
			time.Sleep(20 * time.Millisecond)
		}
	}
	defer first.Close()

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	expectClosed(t, second, 2*time.Second, "second connection from one source")
}
