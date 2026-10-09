package server

import (
	"Sottopasso/pkg/protocol"
	tunnel_pkg "Sottopasso/pkg/tunnel"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"
)

// Tunnel represents a single active tunnel managed by the server.
type Tunnel struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	PublicURL     string         `json:"public_url"`
	ClientAddr    string         `json:"client_addr"`
	Status        string         `json:"status"`
	CreatedAt     time.Time      `json:"created_at"`
	TotalBytesIn  atomic.Uint64  `json:"total_bytes_in"`
	TotalBytesOut atomic.Uint64  `json:"total_bytes_out"`
	Session       *yamux.Session `json:"-"`

	// listener is the public listener of a TCP tunnel (nil for HTTP tunnels).
	// Set before the tunnel is published in the maps, never mutated afterwards.
	listener net.Listener

	// sem bounds concurrent public requests for an HTTP tunnel (nil = unlimited,
	// or the tunnel is a TCP tunnel, whose limit lives in its accept loop).
	sem chan struct{}
}

// Config contains the server configuration.
type Config struct {
	ControlAddr            string
	HTTPAddr               string
	HTTPUseTLS             bool
	DashboardAddr          string
	Domain                 string
	ValidTokens            []string
	TLSCertFile            string
	TLSKeyFile             string
	DashboardUsername      string
	DashboardPassword      string
	DashboardTLSCertFile   string
	DashboardTLSKeyFile    string
	KeepaliveInterval      time.Duration
	ConnectionWriteTimeout time.Duration

	// Resource limits (0 = unlimited / disabled).
	MaxTunnelsPerSession  int           // max concurrent tunnels a single client session may create
	MaxConnsPerTunnel     int           // max concurrent public connections per TCP tunnel
	MaxControlConnections int           // max concurrent control-channel connections
	HTTPReadTimeout       time.Duration // public HTTP server ReadTimeout (0 = unlimited)
	HTTPWriteTimeout      time.Duration // public HTTP server WriteTimeout (0 = unlimited)
	MaxHTTPRequestBytes   int64         // max public HTTP request body size in bytes

	// Per-source-address control-channel limits. MaxControlConnections alone is a
	// global budget, so without these a single peer can hold every slot — a
	// control connection keeps its slot for the whole session, and an
	// unauthenticated one keeps it for the full authentication deadline.
	// IPv6 addresses are grouped by /64.
	MaxControlConnsPerIP   int           // max concurrent control connections per source (0 = unlimited)
	ControlAttemptBurst    int           // control connection attempts a source may make back-to-back (0 = no rate limit)
	ControlAttemptInterval time.Duration // one attempt is restored every interval (0 = no rate limit)

	// HTTPResponseHeaderTimeout bounds the round-trip with the tunnel client for a
	// proxied HTTP request: relaying the request plus reading the response headers.
	// It does not apply to the response body, which may stream indefinitely.
	// (0 = unlimited)
	HTTPResponseHeaderTimeout time.Duration

	// MaxHTTPConnsPerTunnel bounds concurrent public requests/hijacked connections
	// per HTTP tunnel (0 = unlimited).
	MaxHTTPConnsPerTunnel int

	// HijackedIdleTimeout reaps hijacked (WebSocket/SSE) connections with no
	// traffic in either direction for this long (0 = unlimited). Keepalive
	// frames count as traffic.
	HijackedIdleTimeout time.Duration

	// Dashboard Basic Auth throttling: after DashboardAuthMaxFailures failed
	// attempts from one source, it is locked out for DashboardAuthLockout
	// (0 = disabled).
	DashboardAuthMaxFailures int
	DashboardAuthLockout     time.Duration

	// ReservedSubdomains are additional subdomains clients may not claim,
	// on top of the built-in reservedSubdomains list.
	ReservedSubdomains []string
}

// Server is the main structure of our tunnel server.
type Server struct {
	config        *Config
	tunnels       map[string]*Tunnel
	tunnelsMu     sync.RWMutex
	httpTunnels   map[string]*Tunnel
	httpTunnelsMu sync.RWMutex
	// serversMu guards httpServer, dashboardServer and controlListener: they are
	// assigned by listener goroutines while Shutdown may read them concurrently.
	serversMu         sync.Mutex
	httpServer        *http.Server
	dashboardServer   *http.Server
	controlListener   net.Listener
	dashboardTemplate *template.Template
	csrfToken         string
	// controlLimiter bounds control connections per source address; nil when both
	// per-IP limits are disabled.
	controlLimiter *ipLimiter
	// dashAuth throttles repeated dashboard authentication failures per source
	// address; nil when disabled.
	dashAuth *authFailLimiter
}

// New creates a new server instance.
func New(config *Config) *Server {
	// Generate a random CSRF token for dashboard form protection.
	// A crypto/rand failure would leave the token all-zero (predictable), which
	// would silently defeat CSRF protection — so fail hard instead of ignoring it.
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		panic(fmt.Sprintf("crypto/rand failed while generating CSRF token: %v", err))
	}
	csrfToken := fmt.Sprintf("%x", csrfBytes)

	tmpl := template.Must(template.New("dashboard").Funcs(template.FuncMap{
		"formatBytes": func(b uint64) string {
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			kb := float64(b) / unit
			if kb < unit {
				return fmt.Sprintf("%.2f KB", kb)
			}
			mb := kb / unit
			if mb < unit {
				return fmt.Sprintf("%.2f MB", mb)
			}
			gb := mb / unit
			if gb < unit {
				return fmt.Sprintf("%.2f GB", gb)
			}
			tb := gb / unit
			return fmt.Sprintf("%.2f TB", tb)
		},
		"duration": func(d time.Time) string {
			return time.Since(d).Round(time.Second).String()
		},
		"uptimeSeconds": func(d time.Time) int64 {
			return int64(time.Since(d) / time.Second)
		},
		"csrfToken": func() string {
			return csrfToken
		},
		"countType": func(ts []*Tunnel, typ string) int {
			n := 0
			for _, t := range ts {
				if t.Type == typ {
					n++
				}
			}
			return n
		},
		"totalIn": func(ts []*Tunnel) uint64 {
			var n uint64
			for _, t := range ts {
				n += t.TotalBytesIn.Load()
			}
			return n
		},
		"totalOut": func(ts []*Tunnel) uint64 {
			var n uint64
			for _, t := range ts {
				n += t.TotalBytesOut.Load()
			}
			return n
		},
		"isHTTPURL": func(u string) bool {
			return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
		},
	}).Parse(dashboardTemplate))

	return &Server{
		config:            config,
		tunnels:           make(map[string]*Tunnel),
		httpTunnels:       make(map[string]*Tunnel),
		dashboardTemplate: tmpl,
		csrfToken:         csrfToken,
		controlLimiter: newIPLimiter(
			config.MaxControlConnsPerIP,
			config.ControlAttemptBurst,
			config.ControlAttemptInterval,
		),
		dashAuth: newAuthFailLimiter(config.DashboardAuthMaxFailures, config.DashboardAuthLockout),
	}
}

// Start starts all the server listeners.
func (s *Server) Start() error {
	go s.startHTTPListener()
	go s.startDashboardListener()
	return s.startControlListener()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() {
	log.Println("Shutting down servers...")
	s.serversMu.Lock()
	controlListener := s.controlListener
	httpServer := s.httpServer
	dashboardServer := s.dashboardServer
	s.serversMu.Unlock()
	if controlListener != nil {
		controlListener.Close()
	}
	if httpServer != nil {
		httpServer.Close()
	}
	if dashboardServer != nil {
		dashboardServer.Close()
	}

	// Close every client session: per-tunnel TCP listeners and their accept
	// goroutines only exit when their session dies, so without this a library
	// caller would leak them all.
	s.tunnelsMu.RLock()
	sessions := make(map[*yamux.Session]struct{})
	for _, t := range s.tunnels {
		if t.Session != nil {
			sessions[t.Session] = struct{}{}
		}
	}
	s.tunnelsMu.RUnlock()
	for session := range sessions {
		session.Close()
	}
}

// startControlListener starts the listener for client connections.
func (s *Server) startControlListener() error {
	lsConfig, err := s.getTLSConfig(s.config.TLSCertFile, s.config.TLSKeyFile, "localhost")
	if err != nil {
		return fmt.Errorf("unable to get control TLS configuration: %w", err)
	}

	log.Printf("TLS control server listening on %s", s.config.ControlAddr)
	ln, err := tls.Listen("tcp", s.config.ControlAddr, lsConfig)
	if err != nil {
		return fmt.Errorf("unable to start control TLS listener: %w", err)
	}
	s.serversMu.Lock()
	s.controlListener = ln
	s.serversMu.Unlock()
	defer ln.Close()

	// Bound the number of concurrent control connections so an unauthenticated flood
	// cannot exhaust goroutines/FDs while connections sit in the auth window.
	var sem chan struct{}
	if s.config.MaxControlConnections > 0 {
		sem = make(chan struct{}, s.config.MaxControlConnections)
	}
	// A flood is rejected as fast as it can connect, so logging every rejection
	// would put a stderr write (serialized on log's own mutex) in the accept path
	// and bury everything else in the log. Report the first one immediately, then
	// at most one line per second with a count of what it stands for.
	var lastRejectLog time.Time
	var suppressedRejects int
	logReject := func(addr net.Addr, reason string) {
		suppressedRejects++
		now := time.Now()
		if !lastRejectLog.IsZero() && now.Sub(lastRejectLog) < time.Second {
			return
		}
		if suppressedRejects > 1 {
			log.Printf("Rejecting control connection from %s: %s (and %d more since the previous line)", addr, reason, suppressedRejects-1)
		} else {
			log.Printf("Rejecting control connection from %s: %s", addr, reason)
		}
		lastRejectLog = now
		suppressedRejects = 0
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			log.Printf("Error accepting new TLS connection: %v", err)
			// Back off briefly: persistent accept errors (e.g. FD exhaustion)
			// would otherwise spin this loop at full speed.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// Per-source limits first: they are what keeps one peer from consuming the
		// global budget checked right after.
		admitted, releaseIP, reason := s.controlLimiter.admit(limiterKey(conn.RemoteAddr()))
		if !admitted {
			logReject(conn.RemoteAddr(), reason)
			conn.Close()
			continue
		}
		if sem != nil {
			select {
			case sem <- struct{}{}:
			default:
				logReject(conn.RemoteAddr(), fmt.Sprintf("global control connection limit (%d) reached", s.config.MaxControlConnections))
				releaseIP()
				conn.Close()
				continue
			}
		}
		go func(conn net.Conn) {
			defer releaseIP()
			if sem != nil {
				defer func() { <-sem }()
			}
			s.handleClientConnection(conn)
		}(conn)
	}
	return nil
}

// startDashboardListener starts the web server for the status page.
func (s *Server) startDashboardListener() {
	if s.config.DashboardAddr == "" {
		return
	}

	// Fail closed: never expose the dashboard without authentication. The dashboard
	// reveals the full tunnel inventory (including client IPs) and offers a tunnel-close
	// action, so requiring both credentials prevents the silent fail-open where a missing
	// username or password served everything to anyone who could reach the address.
	if s.config.DashboardUsername == "" || s.config.DashboardPassword == "" {
		log.Printf("Dashboard NOT started: dashboard_addr is set but dashboard_username and/or dashboard_password are missing. Configure both to enable the dashboard.")
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/tunnels", s.serveTunnelsJSON)
	mux.HandleFunc("/", s.serveDashboard)
	authHandler := s.securityHeaders(s.basicAuth(mux))
	srv := &http.Server{
		Addr:         s.config.DashboardAddr,
		Handler:      authHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	s.serversMu.Lock()
	s.dashboardServer = srv
	s.serversMu.Unlock()

	useTLS := s.config.DashboardTLSCertFile != "" && s.config.DashboardTLSKeyFile != ""
	if useTLS {
		cfg, err := s.getTLSConfig(s.config.DashboardTLSCertFile, s.config.DashboardTLSKeyFile, "localhost")
		if err != nil {
			log.Printf("Unable to get TLS configuration for dashboard: %v", err)
			return
		}
		srv.TLSConfig = cfg
		log.Printf("Secure status dashboard available at https://%s", s.config.DashboardAddr)
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("Dashboard TLS server error: %v", err)
		}
	} else {
		log.Printf("Status dashboard available at http://%s", s.config.DashboardAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("Dashboard server error: %v", err)
		}
	}
}

// startHTTPListener starts the public reverse proxy.
func (s *Server) startHTTPListener() {
	if s.config.HTTPAddr == "" {
		return
	}

	srv := &http.Server{
		Addr:              s.config.HTTPAddr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       s.config.HTTPReadTimeout,
		WriteTimeout:      s.config.HTTPWriteTimeout,
		IdleTimeout:       120 * time.Second,
		// Disable HTTP/2: the WebSocket/SSE paths rely on http.Hijacker, which
		// the h2 ResponseWriter does not implement — h2 clients would get 500s
		// on every SSE request. A non-nil empty map suppresses the automatic
		// h2 configuration of ListenAndServeTLS.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	s.serversMu.Lock()
	s.httpServer = srv
	s.serversMu.Unlock()

	if s.config.HTTPUseTLS {
		cfg, err := s.getTLSConfig(s.config.TLSCertFile, s.config.TLSKeyFile, "localhost")
		if err != nil {
			log.Printf("Unable to get TLS configuration for HTTPS listener: %v", err)
			return
		}
		srv.TLSConfig = cfg
		log.Printf("HTTPS listener listening on %s", s.config.HTTPAddr)
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("Fatal HTTPS listener error: %v", err)
		}
	} else {
		log.Printf("HTTP listener listening on %s", s.config.HTTPAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("Fatal HTTP listener error: %v", err)
		}
	}
}

// basicAuth is an HTTP Basic authentication middleware.
func (s *Server) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail closed. startDashboardListener refuses to bind when credentials are
		// empty, so reaching here without them means misconfiguration — deny rather
		// than serve the dashboard unauthenticated.
		if s.config.DashboardUsername == "" || s.config.DashboardPassword == "" {
			http.Error(w, "Dashboard authentication is not configured.", http.StatusServiceUnavailable)
			return
		}
		// Throttle repeated failures per source address: without this the
		// endpoint is an unlimited online brute-force target.
		key := limiterKeyFromString(r.RemoteAddr)
		if !s.dashAuth.allow(key) {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(s.config.DashboardAuthLockout.Seconds()), 10))
			http.Error(w, "Too many failed login attempts. Try again later.", http.StatusTooManyRequests)
			return
		}
		user, pass, ok := r.BasicAuth()
		userMatch := constantTimeEqual(user, s.config.DashboardUsername)
		passMatch := constantTimeEqual(pass, s.config.DashboardPassword)
		if !ok || !userMatch || !passMatch {
			s.dashAuth.recordFail(key)
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Access"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Authentication required.\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// constantTimeEqual compares two secrets in constant time without leaking their
// length: both are hashed first, so the comparison always runs over 32
// fixed-size bytes (subtle.ConstantTimeCompare returns immediately when the
// lengths differ).
func constantTimeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// securityHeaders adds security headers to HTTP responses.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Constrain what the dashboard page may load. 'unsafe-inline' is required by the
		// page's inline <style>/<script>; everything else is same-origin (the page is
		// fully self-contained — system fonts, inline SVG favicon, fetch to /api/tunnels).
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'; "+
				"img-src 'self' data:; "+
				"frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// serveDashboard is the handler for the status page.
func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleCloseTunnel(w, r)
		return
	}

	// Snapshot under the lock, render after releasing it: the template writes to
	// the client's socket and can block on a slow reader, and holding tunnelsMu
	// here would stall tunnel cleanup — and through it (httpTunnelsMu) the whole
	// public routing path. Tunnel fields are immutable after publication except
	// the atomic counters, so rendering without the lock is safe.
	tunnels := s.snapshotTunnels()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page embeds the CSRF token: never let a shared cache store it.
	w.Header().Set("Cache-Control", "no-store")
	if err := s.dashboardTemplate.Execute(w, tunnels); err != nil {
		log.Printf("Error executing dashboard template: %v", err)
	}
}

// snapshotTunnels returns the current tunnels in a stable order (oldest first,
// ID as tie-break) so the dashboard and the JSON feed do not reshuffle rows on
// every refresh the way map iteration would.
func (s *Server) snapshotTunnels() []*Tunnel {
	s.tunnelsMu.RLock()
	tunnels := make([]*Tunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		tunnels = append(tunnels, t)
	}
	s.tunnelsMu.RUnlock()

	sort.Slice(tunnels, func(i, j int) bool {
		if !tunnels[i].CreatedAt.Equal(tunnels[j].CreatedAt) {
			return tunnels[i].CreatedAt.Before(tunnels[j].CreatedAt)
		}
		return tunnels[i].ID < tunnels[j].ID
	})
	return tunnels
}

// tunnelView is the JSON shape served to the dashboard's polling script.
// Tunnel itself cannot be marshaled usefully (atomic counters have no exported
// fields), and a dedicated DTO keeps the wire format independent of internals.
type tunnelView struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	PublicURL     string    `json:"public_url"`
	ClientAddr    string    `json:"client_addr"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	BytesIn       uint64    `json:"bytes_in"`
	BytesOut      uint64    `json:"bytes_out"`
}

// serveTunnelsJSON feeds the dashboard's auto-refresh with the live tunnel list.
// It sits behind the same Basic Auth and security headers as the HTML page.
func (s *Server) serveTunnelsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}

	tunnels := s.snapshotTunnels()
	now := time.Now()
	views := make([]tunnelView, 0, len(tunnels))
	for _, t := range tunnels {
		views = append(views, tunnelView{
			ID:            t.ID,
			Type:          t.Type,
			PublicURL:     t.PublicURL,
			ClientAddr:    t.ClientAddr,
			Status:        t.Status,
			CreatedAt:     t.CreatedAt,
			UptimeSeconds: int64(now.Sub(t.CreatedAt) / time.Second),
			BytesIn:       t.TotalBytesIn.Load(),
			BytesOut:      t.TotalBytesOut.Load(),
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(map[string]any{"tunnels": views}); err != nil {
		log.Printf("Error encoding tunnels JSON: %v", err)
	}
}

// handleCloseTunnel handles tunnel close requests.
func (s *Server) handleCloseTunnel(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("csrf_token")
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.csrfToken)) != 1 {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	tunnelID := r.FormValue("tunnelId")
	if tunnelID == "" {
		http.Error(w, "Tunnel ID not provided", http.StatusBadRequest)
		return
	}

	s.tunnelsMu.RLock()
	tunnel, ok := s.tunnels[tunnelID]
	s.tunnelsMu.RUnlock()

	if !ok {
		http.Error(w, "Tunnel not found", http.StatusNotFound)
		return
	}

	log.Printf("Closing tunnel %q on dashboard request", tunnelID)
	s.closeTunnel(tunnel)

	http.Redirect(w, r, "/", http.StatusFound)
}

// closeTunnel tears down a single tunnel without killing the owning client's
// session: other tunnels multiplexed on the same session keep working. HTTP
// tunnels are deregistered from the host map; TCP tunnels also close their
// public listener (in-flight connections are left to drain on their own).
func (s *Server) closeTunnel(t *Tunnel) {
	// Lock order: httpTunnelsMu -> tunnelsMu (same as setupHTTPTunnel/cleanup)
	s.httpTunnelsMu.Lock()
	s.tunnelsMu.Lock()
	if t.Type == "http" {
		delete(s.httpTunnels, httpRoutingHost(t.PublicURL))
	}
	delete(s.tunnels, t.ID)
	s.tunnelsMu.Unlock()
	s.httpTunnelsMu.Unlock()

	if t.listener != nil {
		t.listener.Close()
	}
}

// getTLSConfig loads or generates a TLS configuration.
func (s *Server) getTLSConfig(certFile, keyFile, host string) (*tls.Config, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("TLS certificate not found (%s), generating a new one.", certFile)
		if err := generateSelfSignedCert(certFile, keyFile, host); err != nil {
			return nil, fmt.Errorf("unable to generate self-signed certificate: %w", err)
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to load TLS key/certificate pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// generateSelfSignedCert creates a self-signed certificate and key.
func generateSelfSignedCert(certFile, keyFile, host string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Sottopasso Self-Signed"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", host},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	crtOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer crtOut.Close()
	pem.Encode(crtOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// The private key must be owner-only: os.Create would use 0666 (world-readable
	// after umask). Open it explicitly with 0600 so other local users cannot read it.
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
}

// ServeHTTP implements the http.Handler interface for the reverse proxy.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	// Strip port from Host header so lookup matches the stored key (subdomain.domain)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Host names are case-insensitive; tunnel keys are stored lowercase, so fold the
	// lookup to match and avoid case-based routing confusion.
	host = strings.ToLower(host)
	s.httpTunnelsMu.RLock()
	t, ok := s.httpTunnels[host]
	s.httpTunnelsMu.RUnlock()

	if !ok {
		// Do not reflect the attacker-controlled Host into the body; keep it static
		// and non-sniffable.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "Tunnel not found.\n")
		return
	}

	if isWebSocketRequest(r) {
		s.handleHijackedRequest("WebSocket", w, r, t)
		return
	}

	if isSSERequest(r) {
		s.handleHijackedRequest("SSE", w, r, t)
		return
	}

	// Handle normal HTTP requests
	s.handleHTTPRequest(w, r, t)
}

func isWebSocketRequest(r *http.Request) bool {
	// The method check matters beyond RFC 6455 pedantry: the hijack path has no
	// body-size limit or deadlines, so without it any POST carrying Upgrade
	// headers would bypass MaxHTTPRequestBytes and the HTTP timeouts entirely.
	return r.Method == http.MethodGet &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func isSSERequest(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

// prefixConn is a net.Conn that returns a prefix of already-buffered bytes
// before delegating further reads to the underlying connection.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite forwards a half-close to the underlying connection when supported
// (the embedded net.Conn interface would otherwise hide it from the proxy).
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// activityConn records the time of the last bytes read or written, feeding the
// idle watchdog of hijacked connections.
type activityConn struct {
	net.Conn
	last *atomic.Int64
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

// handleHijackedRequest manages protocols (WebSocket, SSE) that require
// connection hijacking instead of a standard request/response cycle.
// After hijacking, the raw TCP connection is proxied bidirectionally to the
// tunnel client. The tunnel client is responsible for producing the full HTTP
// response (status line + headers + body), including protocol-specific headers
// such as Upgrade/Connection for WebSocket or Content-Type: text/event-stream
// for SSE.
func (s *Server) handleHijackedRequest(protocol string, w http.ResponseWriter, r *http.Request, t *Tunnel) {
	host := r.Host
	log.Printf("%s request for host %q", protocol, host)

	if t.sem != nil {
		select {
		case t.sem <- struct{}{}:
			defer func() { <-t.sem }()
		default:
			http.Error(w, "Too many concurrent requests for this tunnel.", http.StatusServiceUnavailable)
			return
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Unable to hijack connection for %s", protocol)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Hijack failed for %s: %v", protocol, err)
		return
	}
	defer clientConn.Close()
	// Detach from the http.Server's Read/WriteTimeout: hijacked WebSocket/SSE
	// connections are long-lived and must not be reaped by those deadlines.
	clientConn.SetDeadline(time.Time{})

	stream, err := t.Session.OpenStream()
	if err != nil {
		log.Printf("Unable to open stream for %s request to %s: %v", protocol, host, err)
		return
	}
	defer stream.Close()

	// An idle timeout reaps hijacked connections whose peer goes silent in both
	// directions; a dead peer would otherwise pin the connection and its stream
	// forever. Keepalive frames (WebSocket ping/pong, SSE comments) count as
	// traffic, so healthy connections are unaffected.
	idleTimeout := s.config.HijackedIdleTimeout
	var idleLast *atomic.Int64
	streamConn := net.Conn(stream)
	if idleTimeout > 0 {
		idleLast = &atomic.Int64{}
		idleLast.Store(time.Now().UnixNano())
		streamConn = &activityConn{Conn: streamConn, last: idleLast}
	}

	// The visitor may carry spoofed X-Forwarded-* headers; the tunnel is the
	// only hop in front of the backend, so overwrite them with the real values.
	setForwardedHeaders(r)

	// Write the request before starting the proxy to avoid a deadlock:
	// the tunnel client needs the HTTP request before it can produce a response,
	// and the proxy goroutines will start reading from both sides immediately.
	if err := r.Write(streamConn); err != nil {
		log.Printf("Error writing %s request to stream: %v", protocol, err)
		return
	}

	// The HTTP server may have buffered bytes the client sent immediately after
	// the request (e.g. an early WebSocket frame) while parsing the headers.
	// Recover them from the hijacked reader so they are forwarded rather than lost.
	if bufrw != nil {
		if n := bufrw.Reader.Buffered(); n > 0 {
			buffered := make([]byte, n)
			if _, err := io.ReadFull(bufrw.Reader, buffered); err == nil {
				clientConn = &prefixConn{Conn: clientConn, prefix: buffered}
			}
		}
	}

	if idleLast != nil {
		clientConn = &activityConn{Conn: clientConn, last: idleLast}
		done := make(chan struct{})
		defer close(done)
		go func() {
			tick := idleTimeout / 2
			if tick < time.Second {
				tick = time.Second
			}
			ticker := time.NewTicker(tick)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if idle := time.Since(time.Unix(0, idleLast.Load())); idle > idleTimeout {
						log.Printf("%s connection for %s idle for %s, closing", protocol, host, idle.Round(time.Second))
						clientConn.Close()
						streamConn.Close()
						return
					}
				}
			}
		}()
	}

	// Account traffic once, at the public boundary (clientConn). The stream relays
	// the same bytes, so measuring it too would double every reported figure.
	var ignoreIn, ignoreOut atomic.Uint64
	mClientConn := tunnel_pkg.NewMeasuredConn(clientConn, &t.TotalBytesIn, &t.TotalBytesOut)
	mStream := tunnel_pkg.NewMeasuredConn(streamConn, &ignoreIn, &ignoreOut)

	log.Printf("Starting %s proxy for %s", protocol, host)
	tunnel_pkg.Proxy(mClientConn, mStream)
	log.Printf("%s proxy for %s terminated", protocol, host)
}

// hopByHopHeaders are connection-specific and must not be forwarded to the public
// client (RFC 7230 6.1). Forwarding them lets a backend desync framing or poison
// downstream caches.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Transfer-Encoding", "TE", "Trailer", "Upgrade",
}

// removeHopByHopHeaders deletes the fixed hop-by-hop set plus any header named in a
// Connection token from h.
func removeHopByHopHeaders(h http.Header) {
	for _, connVal := range h.Values("Connection") {
		for _, name := range strings.Split(connVal, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// setForwardedHeaders overwrites the forwarding headers with the values of the
// public hop in front of the backend. The tunnel adds exactly one hop between
// the visitor and the backend, so any X-Forwarded-* the visitor sent is spoofed
// input and must not reach the backend.
func setForwardedHeaders(r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	r.Header.Set("X-Forwarded-For", ip)
	r.Header.Set("X-Real-IP", ip)
	r.Header.Set("X-Forwarded-Proto", proto)
	r.Header.Set("X-Forwarded-Host", r.Host)
}

// httpRoutingHost returns the key under which an HTTP tunnel is registered in
// httpTunnels: the Host-header form (subdomain + domain host, lowercase, with any
// port removed). ServeHTTP, setupHTTPTunnel, closeTunnel and cleanupTunnelsForSession
// must all derive this key the same way or lookups and teardown will miss entries.
func httpRoutingHost(publicURL string) string {
	host := strings.TrimPrefix(publicURL, "http://")
	host = strings.TrimPrefix(host, "https://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

func (s *Server) handleHTTPRequest(w http.ResponseWriter, r *http.Request, t *Tunnel) {
	host := r.Host
	if t.sem != nil {
		select {
		case t.sem <- struct{}{}:
			defer func() { <-t.sem }()
		default:
			http.Error(w, "Too many concurrent requests for this tunnel.", http.StatusServiceUnavailable)
			return
		}
	}
	if s.config.MaxHTTPRequestBytes > 0 && r.Body != nil {
		// Fast-path reject a request whose declared size already exceeds the
		// limit; MaxBytesReader below still guards chunked or under-declared
		// bodies that are only discovered while the request is relayed.
		if r.ContentLength > s.config.MaxHTTPRequestBytes {
			http.Error(w, "Request body too large.", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxHTTPRequestBytes)
	}
	stream, err := t.Session.OpenStream()
	if err != nil {
		log.Printf("Unable to open stream for host %q: %v", host, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer stream.Close()

	mStream := tunnel_pkg.NewMeasuredConn(stream, &t.TotalBytesOut, &t.TotalBytesIn)

	// net/http answers the visitor's "Expect: 100-continue" itself (it sends the
	// interim 100 when the body is first read), so the header must not be relayed:
	// the backend's own "100 Continue" would be mistaken for the final response.
	r.Header.Del("Expect")
	// Hop-by-hop headers describe the tunnel connection, not the request the
	// backend should see (RFC 7230 6.1). Forwarding them lets a backend desync
	// framing or poison downstream caches; mirror the response-side filtering.
	removeHopByHopHeaders(r.Header)
	// The visitor may carry spoofed X-Forwarded-* headers; the tunnel is the
	// only hop in front of the backend, so overwrite them with the real values.
	setForwardedHeaders(r)

	// Relay the request in the background so the backend's response can be read
	// and forwarded as soon as it is produced. A backend that answers early
	// (401/413/redirect) without consuming the request body must not deadlock the
	// relay on the body upload.
	reqErr := make(chan error, 1)
	go func() {
		err := r.Write(mStream)
		reqErr <- err
		if err != nil {
			// The request could not be relayed (e.g. body too large); abort the
			// pending response read so the handler can report it.
			stream.Close()
		}
	}()

	// Bound the round-trip with the tunnel client for the response headers only:
	// response bodies may stream indefinitely, and the request upload is governed
	// by the public server's read timeout, not this deadline.
	if d := s.config.HTTPResponseHeaderTimeout; d > 0 {
		stream.SetReadDeadline(time.Now().Add(d))
	}

	// Read the HTTP response from the tunnel stream. Interim 1xx responses
	// (e.g. 103 Early Hints) are skipped: unlike http.Transport, ReadResponse
	// returns them as if they were final. 101 is excluded — after "Switching
	// Protocols" the stream no longer carries HTTP. The iteration cap keeps a
	// misbehaving backend from spinning this loop.
	br := bufio.NewReader(mStream)
	resp, err := http.ReadResponse(br, r)
	for i := 0; err == nil && resp.StatusCode >= 100 && resp.StatusCode < 200 &&
		resp.StatusCode != http.StatusSwitchingProtocols && i < 5; i++ {
		resp.Body.Close()
		resp, err = http.ReadResponse(br, r)
	}
	if err != nil {
		// If the background relay failed (for example a body over the limit), its
		// stream close is what unblocked this read. Report that failure rather
		// than a generic gateway error.
		var reqWriteErr error
		select {
		case reqWriteErr = <-reqErr:
		default:
		}
		if reqWriteErr != nil {
			// Request.Write wraps body-read errors in an unexported type with no
			// Unwrap method, so errors.As alone cannot see the MaxBytesError from
			// MaxBytesReader — fall back to its (stable) message.
			var maxBytesErr *http.MaxBytesError
			if errors.As(reqWriteErr, &maxBytesErr) || strings.Contains(reqWriteErr.Error(), "http: request body too large") {
				http.Error(w, "Request body too large.", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "Bad gateway.", http.StatusBadGateway)
			}
			return
		}
		// Nothing has been written to w yet, so a clean 502 is safe. Returning
		// without a status would make net/http send an implicit empty 200, and a
		// dead backend would look healthy to the visitor.
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			log.Printf("Error reading response from stream: %v", err)
		}
		http.Error(w, "Bad gateway: the tunnel client did not return a response.", http.StatusBadGateway)
		return
	}

	// The iteration cap above keeps a misbehaving backend from spinning the loop;
	// a response that is still interim here means the cap was hit. Fail rather
	// than relaying a 1xx as the final response.
	if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		http.Error(w, "Bad gateway: the tunnel client sent too many interim responses.", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	stream.SetReadDeadline(time.Time{})

	// The backend (the tunnel client's own service) controls the remaining response
	// headers, including Set-Cookie/CORS/Location for its own public hostname — that is
	// the intended trust boundary. Still strip hop-by-hop headers so a backend cannot
	// desync framing (CL.TE/TE.CL) or poison downstream caches via
	// Connection/Transfer-Encoding/etc.
	removeHopByHopHeaders(resp.Header)

	// Copy headers from the tunnel response to the original response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Announce trailers (parsed by ReadResponse into resp.Trailer) so their
	// values can be written after the body — e.g. gRPC-Web status, checksums.
	if len(resp.Trailer) > 0 {
		names := make([]string, 0, len(resp.Trailer))
		for name := range resp.Trailer {
			names = append(names, name)
		}
		w.Header().Set("Trailer", strings.Join(names, ", "))
	}

	// Write the status code and the response body
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	for name, values := range resp.Trailer {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
}

// maxControlMessageSize bounds the bytes a single control message may occupy on the wire.
const maxControlMessageSize = 1 << 20 // 1 MiB

// errControlMessageTooLarge is returned once a single message exceeds maxControlMessageSize.
var errControlMessageTooLarge = errors.New("control message exceeds maximum size")

// resettableLimitReader is an io.LimitReader whose budget can be restored with reset,
// so a single json.Decoder can be reused across messages while still bounding each one.
type resettableLimitReader struct {
	r         io.Reader
	remaining int64
}

func (l *resettableLimitReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, errControlMessageTooLarge
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

func (l *resettableLimitReader) reset(limit int64) {
	l.remaining = limit
}

// serveControlStream decodes and dispatches a client's control messages until the stream closes or a decode error occurs.
func (s *Server) serveControlStream(session *yamux.Session, ctrlStream net.Conn) {
	// Reuse one decoder for the stream's lifetime: a fresh decoder per message would discard bytes it buffered past the current message, silently dropping pipelined messages.
	limited := &resettableLimitReader{r: ctrlStream, remaining: maxControlMessageSize}
	dec := json.NewDecoder(limited)
	for {
		var msg protocol.ControlMessage
		if err := dec.Decode(&msg); err != nil {
			log.Printf("Client %s disconnected: %v", session.RemoteAddr(), err)
			return
		}
		limited.reset(maxControlMessageSize) // restore the per-message size budget

		switch msg.Type {
		case protocol.RequestTunnelType:
			if err := s.handleRequestTunnel(&msg, session, ctrlStream); err != nil {
				log.Printf("Error handling tunnel request: %v", err)
			}
		default:
			log.Printf("Received unhandled message type: %q", msg.Type)
		}
	}
}

// handleClientConnection manages the lifecycle of a single connected client.
func (s *Server) handleClientConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("New client connected from %s", conn.RemoteAddr())

	sessionConn, ok := s.authenticate(conn)
	if !ok {
		log.Printf("Authentication failed for client %s", conn.RemoteAddr())
		return
	}

	log.Printf("Client %s authenticated successfully", conn.RemoteAddr())

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.KeepAliveInterval = s.config.KeepaliveInterval
	yamuxConfig.ConnectionWriteTimeout = s.config.ConnectionWriteTimeout
	session, err := yamux.Server(sessionConn, yamuxConfig)
	if err != nil {
		log.Printf("Error creating yamux session for %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer session.Close()

	defer s.cleanupTunnelsForSession(session)

	ctrlStream, err := session.AcceptStream()
	if err != nil {
		log.Printf("Unable to accept control stream from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer ctrlStream.Close()

	log.Printf("Control stream accepted from %s. Waiting for requests...", conn.RemoteAddr())

	s.serveControlStream(session, ctrlStream)

	log.Printf("Connection with client %s terminated.", conn.RemoteAddr())
}

// cleanupTunnelsForSession removes all tunnels associated with a client session.
// countTunnelsForSession returns how many active tunnels belong to a session.
func (s *Server) countTunnelsForSession(session *yamux.Session) int {
	s.tunnelsMu.RLock()
	defer s.tunnelsMu.RUnlock()
	n := 0
	for _, t := range s.tunnels {
		if t.Session == session {
			n++
		}
	}
	return n
}

func (s *Server) cleanupTunnelsForSession(session *yamux.Session) {
	// Both locks are held across the whole scan (it has to visit every tunnel to
	// find this session's), and httpTunnelsMu is the lock the public routing path
	// takes on every request — so nothing slow may happen in here. Collect what
	// was removed and log it afterwards: log.Printf serializes on its own mutex
	// and writes to stderr, which made the hold time an order of magnitude longer
	// than the map work itself (~22ms of 23ms with 10k tunnels).
	type removedTunnel struct{ id, publicURL string }
	var removed []removedTunnel

	// Lock order: httpTunnelsMu -> tunnelsMu (same as setupHTTPTunnel to avoid deadlock)
	s.httpTunnelsMu.Lock()
	s.tunnelsMu.Lock()
	for id, t := range s.tunnels {
		if t.Session == session {
			if t.Type == "http" {
				delete(s.httpTunnels, httpRoutingHost(t.PublicURL))
			}
			delete(s.tunnels, id)
			removed = append(removed, removedTunnel{id: t.ID, publicURL: t.PublicURL})
		}
	}
	s.tunnelsMu.Unlock()
	s.httpTunnelsMu.Unlock()

	for _, r := range removed {
		log.Printf("Cleaned up tunnel %s (%s) for disconnected client.", r.id, r.publicURL)
	}
}

// validSubdomain matches a single DNS label: lowercase alphanumerics and hyphens,
// not starting or ending with a hyphen, at most 63 characters.
var validSubdomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedSubdomains cannot be claimed by clients (server / infrastructure names).
var reservedSubdomains = map[string]bool{
	"www":       true,
	"admin":     true,
	"dashboard": true,
}

// sendTunnelError reports a tunnel-setup failure to the client over the control
// stream and returns the same message as an error for server-side logging.
func sendTunnelError(ctrlStream net.Conn, errMsg string) error {
	payload, _ := json.Marshal(protocol.TunnelResponse{Error: errMsg})
	respMsg := protocol.ControlMessage{Type: protocol.TunnelResponseType, RawPayload: payload}
	if err := json.NewEncoder(ctrlStream).Encode(respMsg); err != nil {
		return fmt.Errorf("%s (and failed to notify client: %w)", errMsg, err)
	}
	return fmt.Errorf("%s", errMsg)
}

func (s *Server) handleRequestTunnel(msg *protocol.ControlMessage, session *yamux.Session, ctrlStream net.Conn) error {
	var req protocol.RequestTunnel
	if err := json.Unmarshal(msg.RawPayload, &req); err != nil {
		return fmt.Errorf("error unmarshaling RequestTunnel payload: %w", err)
	}

	log.Printf("Received request for tunnel type %q from %s", req.Type, session.RemoteAddr())

	if s.config.MaxTunnelsPerSession > 0 {
		if n := s.countTunnelsForSession(session); n >= s.config.MaxTunnelsPerSession {
			return sendTunnelError(ctrlStream, fmt.Sprintf("tunnel limit reached (%d) for this session", s.config.MaxTunnelsPerSession))
		}
	}

	switch req.Type {
	case "tcp":
		return s.setupTCPTunnel(req, session, ctrlStream)
	case "http":
		return s.setupHTTPTunnel(req, session, ctrlStream)
	default:
		return sendTunnelError(ctrlStream, fmt.Sprintf("unsupported tunnel type: %s", req.Type))
	}
}

func (s *Server) setupHTTPTunnel(req protocol.RequestTunnel, session *yamux.Session, ctrlStream net.Conn) error {
	var subdomain string
	var host string

	// routingDomain is the Host-header key component (lowercase, port stripped).
	// The public URL instead keeps the configured Domain verbatim so an embedded
	// port survives into the address users actually dial.
	routingDomain := strings.ToLower(s.config.Domain)
	if h, _, err := net.SplitHostPort(routingDomain); err == nil {
		routingDomain = strings.ToLower(h)
	}

	// Validate a client-requested subdomain: it must be a single lowercase DNS label.
	// Reject (rather than silently ignore) malformed input so a client cannot inject
	// dots/uppercase/whitespace into the host key, shadow other labels, or desync the
	// case-insensitive Host lookup. Empty means "assign a random one". The reserved
	// set is the built-in list plus the operator-configured ReservedSubdomains.
	if req.Subdomain != "" {
		normalized := strings.ToLower(req.Subdomain)
		if !validSubdomain.MatchString(normalized) || reservedSubdomains[normalized] || slices.Contains(s.config.ReservedSubdomains, normalized) {
			return sendTunnelError(ctrlStream, fmt.Sprintf("invalid or reserved subdomain: %q", req.Subdomain))
		}
		req.Subdomain = normalized
	}

	s.httpTunnelsMu.Lock()
	defer s.httpTunnelsMu.Unlock()

	if req.Subdomain != "" {
		potentialHost := fmt.Sprintf("%s.%s", req.Subdomain, routingDomain)
		if _, exists := s.httpTunnels[potentialHost]; !exists {
			subdomain = req.Subdomain
			host = potentialHost
			log.Printf("Requested subdomain '%s' is available.", req.Subdomain)
		} else {
			log.Printf("Requested subdomain '%s' not available. A random one will be assigned.", req.Subdomain)
		}
	}

	if host == "" {
		for {
			subdomain = uuid.New().String()[:8]
			host = fmt.Sprintf("%s.%s", subdomain, routingDomain)
			if _, exists := s.httpTunnels[host]; !exists {
				break
			}
		}
	}

	schema := "http"
	if s.config.HTTPUseTLS {
		schema = "https"
	}

	// Bound concurrent public requests/hijacked connections per HTTP tunnel so a
	// public flood cannot exhaust goroutines/streams on the server and the client.
	var sem chan struct{}
	if s.config.MaxHTTPConnsPerTunnel > 0 {
		sem = make(chan struct{}, s.config.MaxHTTPConnsPerTunnel)
	}

	tunnel := &Tunnel{
		ID:         uuid.New().String(),
		Type:       "http",
		PublicURL:  fmt.Sprintf("%s://%s.%s", schema, subdomain, s.config.Domain),
		ClientAddr: session.RemoteAddr().String(),
		Status:     "active",
		CreatedAt:  time.Now(),
		Session:    session,
		sem:        sem,
	}

	s.tunnelsMu.Lock()
	s.tunnels[tunnel.ID] = tunnel
	s.tunnelsMu.Unlock()

	s.httpTunnels[host] = tunnel

	log.Printf("HTTP tunnel created: %s -> %s", tunnel.PublicURL, tunnel.ID)

	resp := protocol.TunnelResponse{PublicURL: tunnel.PublicURL}
	payload, _ := json.Marshal(resp)
	respMsg := protocol.ControlMessage{
		Type:       protocol.TunnelResponseType,
		RawPayload: payload,
	}
	if err := json.NewEncoder(ctrlStream).Encode(respMsg); err != nil {
		// Deregister the tunnel: leaving it published would show a ghost entry
		// (with a live routing key but no client that knows its URL) until the
		// whole session is cleaned up. Mirrors setupTCPTunnel.
		s.tunnelsMu.Lock()
		delete(s.tunnels, tunnel.ID)
		s.tunnelsMu.Unlock()
		delete(s.httpTunnels, host)
		return fmt.Errorf("error sending TunnelResponse: %w", err)
	}
	return nil
}

// tcpPublicAddr builds the address advertised for a TCP tunnel. The listener is
// bound to the wildcard ":0", whose Addr ("[::]:port" or "0.0.0.0:port") is not a
// destination a client can dial. Advertise the configured Domain host instead when
// one is set (it resolves to this server), keeping the assigned port; otherwise
// fall back to the listener's own address.
func (s *Server) tcpPublicAddr(listener net.Listener) string {
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return listener.Addr().String()
	}
	host := s.config.Domain
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return listener.Addr().String()
	}
	return net.JoinHostPort(host, port)
}

func (s *Server) setupTCPTunnel(req protocol.RequestTunnel, session *yamux.Session, ctrlStream net.Conn) error {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return fmt.Errorf("unable to start TCP listener: %w", err)
	}

	publicAddr := s.tcpPublicAddr(listener)
	tunnel := &Tunnel{
		ID:         uuid.New().String(),
		Type:       "tcp",
		PublicURL:  publicAddr,
		ClientAddr: session.RemoteAddr().String(),
		Status:     "active",
		CreatedAt:  time.Now(),
		Session:    session,
		listener:   listener,
	}

	s.tunnelsMu.Lock()
	s.tunnels[tunnel.ID] = tunnel
	s.tunnelsMu.Unlock()

	log.Printf("TCP tunnel created: %s -> %s", tunnel.PublicURL, tunnel.ID)

	resp := protocol.TunnelResponse{PublicURL: publicAddr}
	payload, _ := json.Marshal(resp)
	respMsg := protocol.ControlMessage{
		Type:       protocol.TunnelResponseType,
		RawPayload: payload,
	}
	if err := json.NewEncoder(ctrlStream).Encode(respMsg); err != nil {
		// Deregister the tunnel: leaving it published would show a ghost entry
		// (with a dead listener) until the whole session is cleaned up.
		s.tunnelsMu.Lock()
		delete(s.tunnels, tunnel.ID)
		s.tunnelsMu.Unlock()
		listener.Close()
		return fmt.Errorf("error sending TunnelResponse: %w", err)
	}

	go func() {
		defer listener.Close()
		go func() {
			<-session.CloseChan()
			listener.Close()
		}()

		// Bound concurrent public connections per tunnel so a public flood cannot
		// exhaust goroutines/streams on the server and the target client.
		var sem chan struct{}
		if s.config.MaxConnsPerTunnel > 0 {
			sem = make(chan struct{}, s.config.MaxConnsPerTunnel)
		}
		for {
			publicConn, err := listener.Accept()
			if err != nil {
				log.Printf("TCP listener for %s terminated.", publicAddr)
				return
			}

			if sem != nil {
				select {
				case sem <- struct{}{}:
				default:
					log.Printf("TCP tunnel %s: per-tunnel connection limit (%d) reached; rejecting %s", publicAddr, s.config.MaxConnsPerTunnel, publicConn.RemoteAddr())
					publicConn.Close()
					continue
				}
			}

			go func(publicConn net.Conn) {
				defer publicConn.Close()
				if sem != nil {
					defer func() { <-sem }()
				}
				log.Printf("Accepted public connection from %s, forwarding to client %s", publicConn.RemoteAddr(), session.RemoteAddr())

				stream, err := session.OpenStream()
				if err != nil {
					log.Printf("Unable to open new stream for client %s: %v", session.RemoteAddr(), err)
					return
				}
				defer stream.Close()

				// Account traffic once, at the public boundary. The stream relays the
				// same bytes, so measuring it too would double every reported figure.
				var ignoreIn, ignoreOut atomic.Uint64
				mPublicConn := tunnel_pkg.NewMeasuredConn(publicConn, &tunnel.TotalBytesIn, &tunnel.TotalBytesOut)
				mStream := tunnel_pkg.NewMeasuredConn(stream, &ignoreIn, &ignoreOut)

				tunnel_pkg.Proxy(mPublicConn, mStream)
			}(publicConn)
		}
	}()
	return nil
}

// authenticate handles the authentication flow.
func (s *Server) authenticate(conn net.Conn) (net.Conn, bool) {
	// Set a deadline to prevent clients from holding connections open without authenticating
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // Clear deadline after auth

	// Keep the decoder so any bytes it buffers past the auth message can be handed to
	// yamux instead of being dropped (a peer may pipeline the first session bytes).
	dec := json.NewDecoder(io.LimitReader(conn, maxControlMessageSize))
	var msg protocol.ControlMessage
	if err := dec.Decode(&msg); err != nil {
		log.Printf("Error decoding auth message: %v", err)
		return conn, false
	}

	if msg.Type != protocol.AuthRequestType {
		log.Printf("First message is not AuthRequest type, but %q", msg.Type)
		return conn, false
	}

	var authReq protocol.AuthRequest
	if err := json.Unmarshal(msg.RawPayload, &authReq); err != nil {
		log.Printf("Error unmarshaling AuthRequest payload: %v", err)
		return conn, false
	}

	valid := false
	for _, token := range s.config.ValidTokens {
		if constantTimeEqual(token, authReq.AuthToken) {
			valid = true
			break
		}
	}

	resp := protocol.AuthResponse{Success: valid}
	if !valid {
		resp.Error = "Invalid authentication token"
	}

	respMsg := protocol.ControlMessage{
		Type: protocol.AuthResponseType,
	}

	payload, _ := json.Marshal(resp)
	respMsg.RawPayload = payload

	if err := json.NewEncoder(conn).Encode(respMsg); err != nil {
		log.Printf("Error sending auth response: %v", err)
		return conn, false
	}

	// dec.Buffered() holds the JSON-lines delimiter (a trailing newline) plus any bytes
	// the peer pipelined after it. Trim the inter-message whitespace; whatever remains is
	// genuine session data (yamux frames never start with ASCII whitespace).
	buffered, _ := io.ReadAll(dec.Buffered())
	if buffered = bytes.TrimLeft(buffered, " \t\r\n"); len(buffered) > 0 {
		return &prefixConn{Conn: conn, prefix: buffered}, valid
	}
	return conn, valid
}
