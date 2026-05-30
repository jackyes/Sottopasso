package server

import (
	"Sottopasso/pkg/protocol"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConcurrentTunnelAccessNoRace hammers every lock-protected map path
// (ServeHTTP read, serveDashboard read, setupHTTPTunnel write, cleanup delete)
// from many goroutines at once. Go's runtime aborts on concurrent map
// access, so a missing lock would crash this test even without -race.
//
// Iteration counts are bounded (rather than spinning on a timer) so the test is
// fast and deterministic while still interleaving readers and writers heavily.
func TestConcurrentTunnelAccessNoRace(t *testing.T) {
	s := New(&Config{Domain: "localhost"})

	// Stable tunnels for the readers to find.
	seedSess, _ := newYamuxPair(t)
	for i := 0; i < 5; i++ {
		host := fmt.Sprintf("seed%d.localhost", i)
		tn := &Tunnel{ID: fmt.Sprintf("seed%d", i), Type: "http", PublicURL: "http://" + host, Session: seedSess, Status: "active", CreatedAt: time.Now()}
		s.tunnels[tn.ID] = tn
		s.httpTunnels[host] = tn
	}

	var wg sync.WaitGroup
	run := func(iters int, f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				f()
			}
		}()
	}

	// Readers: public reverse-proxy lookups. Use an unknown host so we exercise the
	// httpTunnels read lock + 404 path without triggering real (blocking) proxying
	// to a yamux peer that has no client answering.
	for i := 0; i < 6; i++ {
		run(1000, func() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://nope.localhost/", nil)
			s.ServeHTTP(rec, req)
		})
	}
	// Readers: dashboard rendering (pure tunnels read lock; template render is heavier).
	for i := 0; i < 3; i++ {
		run(200, func() {
			rec := httptest.NewRecorder()
			s.serveDashboard(rec, httptest.NewRequest("GET", "/", nil))
		})
	}
	// Writers: create then clean up tunnels through the real locked paths. Each
	// writer owns a session + drained control pipe.
	for i := 0; i < 4; i++ {
		sess, _ := newYamuxPair(t)
		ctrlR, ctrlW := net.Pipe()
		go io.Copy(io.Discard, ctrlR) // drain encoded responses so setup never blocks
		wg.Add(1)
		go func(ctrlW net.Conn) {
			defer wg.Done()
			defer ctrlW.Close()
			for j := 0; j < 100; j++ {
				_ = s.setupHTTPTunnel(protocol.RequestTunnel{Type: "http"}, sess, ctrlW)
				s.cleanupTunnelsForSession(sess)
			}
		}(ctrlW)
	}

	wg.Wait()
}

// --- listener enable/disable + dashboard serving ---

func TestStartDashboardListener_DisabledReturns(t *testing.T) {
	s := New(&Config{DashboardAddr: ""})
	done := make(chan struct{})
	go func() { s.startDashboardListener(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("startDashboardListener must return immediately when DashboardAddr is empty")
	}
}

func TestStartHTTPListener_DisabledReturns(t *testing.T) {
	s := New(&Config{HTTPAddr: ""})
	done := make(chan struct{})
	go func() { s.startHTTPListener(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("startHTTPListener must return immediately when HTTPAddr is empty")
	}
}

func TestStartDashboardListener_HTTPServesWithBasicAuth(t *testing.T) {
	addr := freeAddrs(t, 1)[0]
	s := New(&Config{DashboardAddr: addr, DashboardUsername: "admin", DashboardPassword: "pw"})
	go s.startDashboardListener()
	defer func() {
		if s.dashboardServer != nil {
			s.dashboardServer.Close()
		}
	}()
	waitDial(t, addr, 3*time.Second)

	// No credentials -> 401.
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth: code=%d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Correct credentials -> 200 + dashboard + security headers.
	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.SetBasicAuth("admin", "pw")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("with auth: code=%d, want 200", resp2.StatusCode)
	}
	if resp2.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("expected security headers on the dashboard response")
	}
	body, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body), "Sottopasso") {
		t.Error("dashboard HTML was not served")
	}
}

func TestStartDashboardListener_TLSServesDashboard(t *testing.T) {
	addr := freeAddrs(t, 1)[0]
	dir := t.TempDir()
	s := New(&Config{
		DashboardAddr:        addr,
		DashboardTLSCertFile: filepath.Join(dir, "d.cert.pem"),
		DashboardTLSKeyFile:  filepath.Join(dir, "d.key.pem"),
	})
	go s.startDashboardListener()
	defer func() {
		if s.dashboardServer != nil {
			s.dashboardServer.Close()
		}
	}()
	waitDial(t, addr, 3*time.Second)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTTPS GET on dashboard: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("code=%d, want 200 (no basic auth configured)", resp.StatusCode)
	}
}
