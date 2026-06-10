package tunnel

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// tcpPair returns the two ends of a real TCP connection on the loopback
// interface (net.Pipe cannot express half-close).
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn, err}
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	accepted := <-ch
	if accepted.err != nil {
		t.Fatal(accepted.err)
	}
	return dialed, accepted.conn
}

// A peer that half-closes its write side after sending the request must still
// receive the full response flowing in the other direction: Proxy must
// propagate the EOF as a half-close instead of tearing down both connections.
func TestProxy_HalfCloseAllowsResponseAfterClientEOF(t *testing.T) {
	pubClient, pubServer := tcpPair(t)
	backProxySide, backServer := tcpPair(t)
	defer pubClient.Close()
	defer backServer.Close()

	var x atomic.Uint64
	proxyDone := make(chan struct{})
	go func() {
		Proxy(NewMeasuredConn(pubServer, &x, &x), NewMeasuredConn(backProxySide, &x, &x))
		close(proxyDone)
	}()

	// Backend: read the request until EOF, then send a response and close.
	const response = "response-after-eof"
	backendErr := make(chan error, 1)
	go func() {
		request, err := io.ReadAll(backServer)
		if err != nil {
			backendErr <- fmt.Errorf("backend read: %w", err)
			return
		}
		if string(request) != "request" {
			backendErr <- fmt.Errorf("backend got %q, want request", request)
			return
		}
		_, err = backServer.Write([]byte(response))
		backServer.Close()
		backendErr <- err
	}()

	// Public client: send the request, shut down the write side, read the response.
	if _, err := pubClient.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := pubClient.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(pubClient)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if string(got) != response {
		t.Fatalf("got %q, want %q (response truncated: half-close not propagated)", got, response)
	}
	if err := <-backendErr; err != nil {
		t.Fatal(err)
	}

	select {
	case <-proxyDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Proxy did not return after both directions finished")
	}
}
