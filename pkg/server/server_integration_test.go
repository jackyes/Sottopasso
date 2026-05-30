package server

import (
	"Sottopasso/pkg/client"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// freeAddrs returns n distinct, currently-free loopback addresses. All probe
// listeners are held open until every port is reserved so the returned ports do
// not collide with one another.
func freeAddrs(t *testing.T, n int) []string {
	t.Helper()
	var lns []net.Listener
	var addrs []string
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		addrs = append(addrs, ln.Addr().String())
	}
	for _, ln := range lns {
		ln.Close()
	}
	return addrs
}

// waitDial blocks until addr accepts a TCP connection or the deadline passes.
func waitDial(t *testing.T, addr string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("address %s never became reachable", addr)
}

// TestEndToEnd_HTTPTunnel wires a real server (TLS control listener + public HTTP
// listener) to the real client and proves a public HTTP request is tunneled to a
// local backend and the response relayed back. This covers Start, the listener
// goroutines, handleClientConnection, serveControlStream, setupHTTPTunnel,
// ServeHTTP/handleHTTPRequest, Shutdown, and the whole client side.
func TestEndToEnd_HTTPTunnel(t *testing.T) {
	// Local backend the tunnel client forwards to.
	const backendBody = "BACKEND-OK-12345"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "yes")
		io.WriteString(w, backendBody)
	}))
	defer backend.Close()
	_, backendPort, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	addrs := freeAddrs(t, 2)
	controlAddr, httpAddr := addrs[0], addrs[1]

	dir := t.TempDir()
	cfg := &Config{
		ControlAddr:            controlAddr,
		HTTPAddr:               httpAddr,
		Domain:                 "localhost",
		ValidTokens:            []string{"secret-tok"},
		TLSCertFile:            filepath.Join(dir, "cert.pem"),
		TLSKeyFile:             filepath.Join(dir, "key.pem"),
		KeepaliveInterval:      30 * time.Second,
		ConnectionWriteTimeout: 10 * time.Second,
		// Dashboard intentionally disabled.
	}
	srv := New(cfg)
	go func() { _ = srv.Start() }()
	defer srv.Shutdown()

	waitDial(t, controlAddr, 5*time.Second)
	waitDial(t, httpAddr, 5*time.Second)

	// Backend port -> int for the client config.
	bport, err := strconv.Atoi(backendPort)
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}

	cli := client.New(&client.Config{
		ServerAddr:             controlAddr,
		AuthToken:              "secret-tok",
		TunnelType:             "http",
		LocalPort:              bport,
		Subdomain:              "itest",
		InsecureSkipVerify:     true,
		KeepaliveInterval:      30 * time.Second,
		ConnectionWriteTimeout: 10 * time.Second,
	})
	clientErr := make(chan error, 1)
	go func() { clientErr <- cli.Start() }()

	// The tunnel registers asynchronously after the client authenticates and
	// requests it; poll the public endpoint until it resolves to the backend.
	httpClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	var got string
	var lastCode int
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", "http://"+httpAddr+"/path", nil)
		req.Host = "itest.localhost" // route to the tunnel
		resp, err := httpClient.Do(req)
		if err != nil {
			select {
			case e := <-clientErr:
				t.Fatalf("client terminated early: %v", e)
			default:
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		lastCode = resp.StatusCode
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && string(body) == backendBody {
			got = string(body)
			if resp.Header.Get("X-Backend") != "yes" {
				t.Errorf("relayed response missing X-Backend header")
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got != backendBody {
		t.Fatalf("tunneled request never returned backend body (last status=%d, got=%q)", lastCode, got)
	}

	// The tunnel must be visible in server state with the expected public URL.
	s := srv
	s.httpTunnelsMu.RLock()
	_, ok := s.httpTunnels["itest.localhost"]
	s.httpTunnelsMu.RUnlock()
	if !ok {
		t.Error("server has no httpTunnels entry for itest.localhost")
	}

	// Shutdown must stop the control listener (a fresh TLS dial should fail soon).
	srv.Shutdown()
	stopped := false
	for i := 0; i < 50; i++ {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}, "tcp", controlAddr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			stopped = true
			break
		}
		c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	if !stopped {
		t.Error("control listener still accepting connections after Shutdown")
	}
}
