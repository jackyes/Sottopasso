package server

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// dialControl opens one TLS control connection and reports whether the server
// kept it. A rejected connection is closed before the handshake, which surfaces
// here as a handshake error.
func dialControl(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// startLimitedControlServer brings up only the control listener, with the given
// per-source limits.
func startLimitedControlServer(t *testing.T, maxPerIP, burst int, interval time.Duration) (*Server, string) {
	t.Helper()
	addr := freeAddrs(t, 1)[0]
	dir := t.TempDir()
	srv := New(&Config{
		ControlAddr:            addr,
		Domain:                 "localhost",
		ValidTokens:            []string{"secret-tok"},
		TLSCertFile:            filepath.Join(dir, "cert.pem"),
		TLSKeyFile:             filepath.Join(dir, "key.pem"),
		KeepaliveInterval:      30 * time.Second,
		ConnectionWriteTimeout: 10 * time.Second,
		MaxControlConnsPerIP:   maxPerIP,
		ControlAttemptBurst:    burst,
		ControlAttemptInterval: interval,
	})
	go func() { _ = srv.startControlListener() }()
	t.Cleanup(srv.Shutdown)
	waitDial(t, addr, 5*time.Second)
	return srv, addr
}

// A single source must not be able to hold more than MaxControlConnsPerIP slots
// of the global budget, and must get them back as its connections close.
func TestControlListener_PerIPConcurrencyLimit(t *testing.T) {
	// waitDial's own probe connection counts as an attempt, so leave the rate
	// limit off here and let the concurrency cap be the only thing under test.
	_, addr := startLimitedControlServer(t, 2, 0, 0)

	var kept []net.Conn
	defer func() {
		for _, c := range kept {
			c.Close()
		}
	}()

	for i := 0; i < 2; i++ {
		conn, err := dialControl(t, addr)
		if err != nil {
			t.Fatalf("connection %d within the cap was rejected: %v", i+1, err)
		}
		kept = append(kept, conn)
	}

	if conn, err := dialControl(t, addr); err == nil {
		conn.Close()
		t.Fatal("a third concurrent connection from the same source must be rejected")
	}

	// Close one and the freed slot must be reusable.
	kept[0].Close()
	kept = kept[1:]
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := dialControl(t, addr)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the freed slot never became reusable: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Connection churn from one source must be throttled once the burst is spent,
// even though every connection is closed immediately (so the concurrency cap
// alone would never trigger).
func TestControlListener_PerIPAttemptRateLimit(t *testing.T) {
	// A long interval keeps the refill from masking the throttle mid-test.
	_, addr := startLimitedControlServer(t, 0, 3, time.Hour)

	// waitDial has already spent one token, so at most two of the next attempts
	// can succeed; the loop only needs to prove that the source is cut off well
	// before it can churn indefinitely.
	rejected := false
	for i := 0; i < 6; i++ {
		conn, err := dialControl(t, addr)
		if err != nil {
			rejected = true
			break
		}
		conn.Close()
	}
	if !rejected {
		t.Fatal("connection churn past the burst must be rejected")
	}
}

// With both per-source limits disabled the listener must behave exactly as it
// did before: no limiter is built at all.
func TestControlListener_PerIPLimitsDisabled(t *testing.T) {
	srv, addr := startLimitedControlServer(t, 0, 0, 0)
	if srv.controlLimiter != nil {
		t.Error("no per-IP limiter should be built when both limits are zero")
	}

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < 5; i++ {
		conn, err := dialControl(t, addr)
		if err != nil {
			t.Fatalf("connection %d must be admitted with limits disabled: %v", i+1, err)
		}
		conns = append(conns, conn)
	}
}
