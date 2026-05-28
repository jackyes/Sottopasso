package server

import (
	"Sottopasso/pkg/protocol"
	tunnel_pkg "Sottopasso/pkg/tunnel"
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
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
}

// Server is the main structure of our tunnel server.
type Server struct {
	config            *Config
	tunnels           map[string]*Tunnel
	tunnelsMu         sync.RWMutex
	httpTunnels       map[string]*Tunnel
	httpTunnelsMu     sync.RWMutex
	httpServer        *http.Server
	dashboardServer   *http.Server
	controlListener   net.Listener
	dashboardTemplate *template.Template
	csrfToken         string
}

// New creates a new server instance.
func New(config *Config) *Server {
	// Generate a random CSRF token for dashboard form protection
	csrfBytes := make([]byte, 32)
	rand.Read(csrfBytes)
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
		"csrfToken": func() string {
			return csrfToken
		},
	}).Parse(dashboardTemplate))

	return &Server{
		config:            config,
		tunnels:           make(map[string]*Tunnel),
		httpTunnels:       make(map[string]*Tunnel),
		dashboardTemplate: tmpl,
		csrfToken:         csrfToken,
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
	if s.controlListener != nil {
		s.controlListener.Close()
	}
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	if s.dashboardServer != nil {
		s.dashboardServer.Close()
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
	s.controlListener = ln
	defer s.controlListener.Close()

	for {
		conn, err := s.controlListener.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				break
			}
			log.Printf("Error accepting new TLS connection: %v", err)
			continue
		}
		go s.handleClientConnection(conn)
	}
	return nil
}

// startDashboardListener starts the web server for the status page.
func (s *Server) startDashboardListener() {
	if s.config.DashboardAddr == "" {
		return
	}

	handler := http.HandlerFunc(s.serveDashboard)
	authHandler := s.securityHeaders(s.basicAuth(handler))
	s.dashboardServer = &http.Server{
		Addr:         s.config.DashboardAddr,
		Handler:      authHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	useTLS := s.config.DashboardTLSCertFile != "" && s.config.DashboardTLSKeyFile != ""
	if useTLS {
		log.Printf("Secure status dashboard available at https://%s", s.config.DashboardAddr)
		if _, err := s.getTLSConfig(s.config.DashboardTLSCertFile, s.config.DashboardTLSKeyFile, "localhost"); err != nil {
			log.Printf("Unable to get TLS configuration for dashboard: %v", err)
			return
		}
		if err := s.dashboardServer.ListenAndServeTLS(s.config.DashboardTLSCertFile, s.config.DashboardTLSKeyFile); err != http.ErrServerClosed {
			log.Printf("Dashboard TLS server error: %v", err)
		}
	} else {
		log.Printf("Status dashboard available at http://%s", s.config.DashboardAddr)
		if err := s.dashboardServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("Dashboard server error: %v", err)
		}
	}
}

// startHTTPListener starts the public reverse proxy.
func (s *Server) startHTTPListener() {
	if s.config.HTTPAddr == "" {
		return
	}

	s.httpServer = &http.Server{
		Addr:              s.config.HTTPAddr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if s.config.HTTPUseTLS {
		log.Printf("HTTPS listener listening on %s", s.config.HTTPAddr)
		if err := s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile); err != http.ErrServerClosed {
			log.Printf("Fatal HTTPS listener error: %v", err)
		}
	} else {
		log.Printf("HTTP listener listening on %s", s.config.HTTPAddr)
		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("Fatal HTTP listener error: %v", err)
		}
	}
}

// basicAuth is an HTTP Basic authentication middleware.
func (s *Server) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.DashboardUsername == "" || s.config.DashboardPassword == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(s.config.DashboardUsername)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(s.config.DashboardPassword)) == 1
		if !ok || !userMatch || !passMatch {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Access"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Authentication required.\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds security headers to HTTP responses.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// serveDashboard is the handler for the status page.
func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleCloseTunnel(w, r)
		return
	}

	s.tunnelsMu.RLock()
	defer s.tunnelsMu.RUnlock()

	tunnels := make([]*Tunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		tunnels = append(tunnels, t)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.dashboardTemplate.Execute(w, tunnels); err != nil {
		log.Printf("Error executing dashboard template: %v", err)
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

	log.Printf("Closing tunnel %s on dashboard request", tunnelID)
	tunnel.Session.Close()

	http.Redirect(w, r, "/", http.StatusFound)
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

	keyOut, err := os.Create(keyFile)
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
	s.httpTunnelsMu.RLock()
	t, ok := s.httpTunnels[host]
	s.httpTunnelsMu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Tunnel for %s not found.", host)
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
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
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

// handleHijackedRequest manages protocols (WebSocket, SSE) that require
// connection hijacking instead of a standard request/response cycle.
// After hijacking, the raw TCP connection is proxied bidirectionally to the
// tunnel client. The tunnel client is responsible for producing the full HTTP
// response (status line + headers + body), including protocol-specific headers
// such as Upgrade/Connection for WebSocket or Content-Type: text/event-stream
// for SSE.
func (s *Server) handleHijackedRequest(protocol string, w http.ResponseWriter, r *http.Request, t *Tunnel) {
	host := r.Host
	log.Printf("%s request for host %s", protocol, host)

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

	stream, err := t.Session.OpenStream()
	if err != nil {
		log.Printf("Unable to open stream for %s request to %s: %v", protocol, host, err)
		return
	}
	defer stream.Close()

	// Write the request before starting the proxy to avoid a deadlock:
	// the tunnel client needs the HTTP request before it can produce a response,
	// and the proxy goroutines will start reading from both sides immediately.
	if err := r.Write(stream); err != nil {
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

	mClientConn := tunnel_pkg.NewMeasuredConn(clientConn, &t.TotalBytesIn, &t.TotalBytesOut)
	mStream := tunnel_pkg.NewMeasuredConn(stream, &t.TotalBytesOut, &t.TotalBytesIn)

	log.Printf("Starting %s proxy for %s", protocol, host)
	tunnel_pkg.Proxy(mClientConn, mStream)
	log.Printf("%s proxy for %s terminated", protocol, host)
}

func (s *Server) handleHTTPRequest(w http.ResponseWriter, r *http.Request, t *Tunnel) {
	host := r.Host
	stream, err := t.Session.OpenStream()
	if err != nil {
		log.Printf("Unable to open stream for host %s: %v", host, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer stream.Close()

	mStream := tunnel_pkg.NewMeasuredConn(stream, &t.TotalBytesOut, &t.TotalBytesIn)

	// Write the HTTP request to the tunnel stream
	if err := r.Write(mStream); err != nil {
		log.Printf("Error writing request to stream: %v", err)
		return
	}

	// Read the HTTP response from the tunnel stream
	resp, err := http.ReadResponse(bufio.NewReader(mStream), r)
	if err != nil {
		// If there is an error reading the response, it could be because the client
		// closed the connection. In this case, do not send an HTTP response.
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			log.Printf("Error reading response from stream: %v", err)
		}
		// We cannot send a header here because the connection may be in an indeterminate state.
		// Try sending a BadGateway, but it may fail.
		// w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers from the tunnel response to the original response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write the status code and the response body
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleClientConnection manages the lifecycle of a single connected client.
func (s *Server) handleClientConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("New client connected from %s", conn.RemoteAddr())

	if !s.authenticate(conn) {
		log.Printf("Authentication failed for client %s", conn.RemoteAddr())
		return
	}

	log.Printf("Client %s authenticated successfully", conn.RemoteAddr())

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.KeepAliveInterval = s.config.KeepaliveInterval
	yamuxConfig.ConnectionWriteTimeout = s.config.ConnectionWriteTimeout
	session, err := yamux.Server(conn, yamuxConfig)
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

	for {
		var msg protocol.ControlMessage
		if err := json.NewDecoder(io.LimitReader(ctrlStream, 1<<20)).Decode(&msg); err != nil {
			log.Printf("Client %s disconnected: %v", conn.RemoteAddr(), err)
			break
		}

		switch msg.Type {
		case protocol.RequestTunnelType:
			if err := s.handleRequestTunnel(&msg, session, ctrlStream); err != nil {
				log.Printf("Error handling tunnel request: %v", err)
			}
		default:
			log.Printf("Received unhandled message type: %s", msg.Type)
		}
	}

	log.Printf("Connection with client %s terminated.", conn.RemoteAddr())
}

// cleanupTunnelsForSession removes all tunnels associated with a client session.
func (s *Server) cleanupTunnelsForSession(session *yamux.Session) {
	// Lock order: httpTunnelsMu -> tunnelsMu (same as setupHTTPTunnel to avoid deadlock)
	s.httpTunnelsMu.Lock()
	defer s.httpTunnelsMu.Unlock()
	s.tunnelsMu.Lock()
	defer s.tunnelsMu.Unlock()

	for id, t := range s.tunnels {
		if t.Session == session {
			log.Printf("Cleaning up tunnel %s (%s) for disconnected client.", t.ID, t.PublicURL)
			if t.Type == "http" {
				host := strings.TrimPrefix(t.PublicURL, "http://")
				host = strings.TrimPrefix(host, "https://")
				delete(s.httpTunnels, host)
			}
			delete(s.tunnels, id)
		}
	}
}

func (s *Server) handleRequestTunnel(msg *protocol.ControlMessage, session *yamux.Session, ctrlStream net.Conn) error {
	var req protocol.RequestTunnel
	if err := json.Unmarshal(msg.RawPayload, &req); err != nil {
		return fmt.Errorf("error unmarshaling RequestTunnel payload: %w", err)
	}

	log.Printf("Received request for tunnel type '%s' from %s", req.Type, session.RemoteAddr())

	switch req.Type {
	case "tcp":
		return s.setupTCPTunnel(req, session, ctrlStream)
	case "http":
		return s.setupHTTPTunnel(req, session, ctrlStream)
	default:
		errMsg := fmt.Sprintf("unsupported tunnel type: %s", req.Type)
		resp := protocol.TunnelResponse{Error: errMsg}
		payload, _ := json.Marshal(resp)
		respMsg := protocol.ControlMessage{
			Type:       protocol.TunnelResponseType,
			RawPayload: payload,
		}
		json.NewEncoder(ctrlStream).Encode(respMsg)
		return fmt.Errorf("%s", errMsg)
	}
}

func (s *Server) setupHTTPTunnel(req protocol.RequestTunnel, session *yamux.Session, ctrlStream net.Conn) error {
	var subdomain string
	var host string

	domain := s.config.Domain
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}

	s.httpTunnelsMu.Lock()
	defer s.httpTunnelsMu.Unlock()

	if req.Subdomain != "" {
		potentialHost := fmt.Sprintf("%s.%s", req.Subdomain, domain)
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
			host = fmt.Sprintf("%s.%s", subdomain, domain)
			if _, exists := s.httpTunnels[host]; !exists {
				break
			}
		}
	}

	schema := "http"
	if s.config.HTTPUseTLS {
		schema = "https"
	}

	tunnel := &Tunnel{
		ID:         uuid.New().String(),
		Type:       "http",
		PublicURL:  fmt.Sprintf("%s://%s", schema, host),
		ClientAddr: session.RemoteAddr().String(),
		Status:     "active",
		CreatedAt:  time.Now(),
		Session:    session,
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
	return json.NewEncoder(ctrlStream).Encode(respMsg)
}

func (s *Server) setupTCPTunnel(req protocol.RequestTunnel, session *yamux.Session, ctrlStream net.Conn) error {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return fmt.Errorf("unable to start TCP listener: %w", err)
	}

	publicAddr := listener.Addr().String()
	tunnel := &Tunnel{
		ID:         uuid.New().String(),
		Type:       "tcp",
		PublicURL:  publicAddr,
		ClientAddr: session.RemoteAddr().String(),
		Status:     "active",
		CreatedAt:  time.Now(),
		Session:    session,
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
		listener.Close()
		return fmt.Errorf("error sending TunnelResponse: %w", err)
	}

	go func() {
		defer listener.Close()
		go func() {
			<-session.CloseChan()
			listener.Close()
		}()

		for {
			publicConn, err := listener.Accept()
			if err != nil {
				log.Printf("TCP listener for %s terminated.", publicAddr)
				return
			}

			go func(publicConn net.Conn) {
				defer publicConn.Close()
				log.Printf("Accepted public connection from %s, forwarding to client %s", publicConn.RemoteAddr(), session.RemoteAddr())

				stream, err := session.OpenStream()
				if err != nil {
					log.Printf("Unable to open new stream for client %s: %v", session.RemoteAddr(), err)
					return
				}
				defer stream.Close()

				mPublicConn := tunnel_pkg.NewMeasuredConn(publicConn, &tunnel.TotalBytesIn, &tunnel.TotalBytesOut)
				mStream := tunnel_pkg.NewMeasuredConn(stream, &tunnel.TotalBytesOut, &tunnel.TotalBytesIn)

				tunnel_pkg.Proxy(mPublicConn, mStream)
			}(publicConn)
		}
	}()
	return nil
}

// authenticate handles the authentication flow.
func (s *Server) authenticate(conn net.Conn) bool {
	// Set a deadline to prevent clients from holding connections open without authenticating
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // Clear deadline after auth

	var msg protocol.ControlMessage
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&msg); err != nil {
		log.Printf("Error decoding auth message: %v", err)
		return false
	}

	if msg.Type != protocol.AuthRequestType {
		log.Printf("First message is not AuthRequest type, but %s", msg.Type)
		return false
	}

	var authReq protocol.AuthRequest
	if err := json.Unmarshal(msg.RawPayload, &authReq); err != nil {
		log.Printf("Error unmarshaling AuthRequest payload: %v", err)
		return false
	}

	valid := false
	for _, token := range s.config.ValidTokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(authReq.AuthToken)) == 1 {
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
		return false
	}

	return valid
}

const dashboardTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sottopasso - Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #1a1a1a;
            --text-color: #e0e0e0;
            --header-color: #c0c0c0;
            --border-color: #333;
            --table-header-bg: #2c2c2c;
            --table-row-odd-bg: #252525;
            --accent-color: #007bff;
            --status-active: #28a745;
        }
        body.light-mode {
            --bg-color: #f5f5f5;
            --text-color: #333;
            --header-color: #555;
            --border-color: #ddd;
            --table-header-bg: #e9ecef;
            --table-row-odd-bg: #f8f9fa;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 2rem;
            transition: background-color 0.3s, color 0.3s;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }
        .header-left {
            display: flex;
            align-items: center;
        }
        .logo {
            width: 40px;
            height: 40px;
            margin-right: 1rem;
        }
        h1 {
            font-size: 2rem;
            font-weight: 600;
            color: var(--header-color);
        }
        .theme-switch-wrapper {
            display: flex;
            align-items: center;
        }
        .theme-switch {
            display: inline-block;
            height: 34px;
            position: relative;
            width: 60px;
        }
        .theme-switch input {
            display:none;
        }
        .slider {
            background-color: #ccc;
            bottom: 0;
            cursor: pointer;
            left: 0;
            position: absolute;
            right: 0;
            top: 0;
            transition: .4s;
        }
        .slider:before {
            background-color: #fff;
            bottom: 4px;
            content: "";
            height: 26px;
            left: 4px;
            position: absolute;
            transition: .4s;
            width: 26px;
        }
        input:checked + .slider {
            background-color: var(--accent-color);
        }
        input:checked + .slider:before {
            transform: translateX(26px);
        }
        .slider.round {
            border-radius: 34px;
        }
        .slider.round:before {
            border-radius: 50%;
        }
        .summary {
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }
        .summary span {
            font-weight: 600;
            color: var(--accent-color);
        }
        table {
            border-collapse: collapse;
            width: 100%;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background-color: var(--table-header-bg);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }
        tr:nth-child(odd) {
            background-color: var(--table-row-odd-bg);
        }
        .status-active {
            color: var(--status-active);
            font-weight: 600;
        }
        .url {
            word-break: break-all;
        }
        .action-button {
            background-color: #dc3545;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
        }
        .action-button:hover {
            background-color: #c82333;
        }
        @media (max-width: 768px) {
            body { padding: 1rem; }
            .header { flex-direction: column; align-items: flex-start; }
            .theme-switch-wrapper { margin-top: 1rem; }
            h1 { font-size: 1.8rem; }
            table, thead, tbody, th, td, tr {
                display: block;
            }
            thead tr {
                position: absolute;
                top: -9999px;
                left: -9999px;
            }
            tr {
                border: 1px solid var(--border-color);
                margin-bottom: 1rem;
                border-radius: 8px;
                background-color: var(--table-row-odd-bg);
            }
            td {
                border: none;
                border-bottom: 1px solid var(--border-color);
                position: relative;
                padding-left: 50%;
                padding-top: 0.75rem;
                padding-bottom: 0.75rem;
                display: flex;
                align-items: center;
            }
            tr:last-child td:last-child {
                border-bottom: none;
            }
            td:before {
                position: absolute;
                top: 50%;
                transform: translateY(-50%);
                left: 1rem;
                width: 40%;
                padding-right: 1rem;
                white-space: nowrap;
                font-weight: 600;
                text-transform: uppercase;
                font-size: 0.75rem;
                color: var(--header-color);
            }
            td:nth-of-type(1):before { content: "ID"; }
            td:nth-of-type(2):before { content: "Type"; }
            td:nth-of-type(3):before { content: "Public URL"; }
            td:nth-of-type(4):before { content: "Client"; }
            td:nth-of-type(5):before { content: "Status"; }
            td:nth-of-type(6):before { content: "Created"; }
            td:nth-of-type(7):before { content: "Uptime"; }
            td:nth-of-type(8):before { content: "Traffic (In / Out)"; }
            td:nth-of-type(9):before { content: "Action"; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <svg class="logo" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" style="stop-color:var(--accent-color);stop-opacity:1" />
                            <stop offset="100%" style="stop-color:var(--status-active);stop-opacity:1" />
                        </linearGradient>
                    </defs>
                    <path d="M10 50 Q 20 20, 50 30 T 90 50 M10 50 Q 20 80, 50 70 T 90 50" fill="none" stroke="url(#logoGradient)" stroke-width="10" stroke-linecap="round"/>
                </svg>
                <h1>Sottopasso</h1>
            </div>
            <div class="theme-switch-wrapper">
                <label class="theme-switch" for="checkbox">
                    <input type="checkbox" id="checkbox" />
                    <div class="slider round"></div>
                </label>
            </div>
        </div>

        <div class="summary">
            <p>Active tunnels: <span>{{ len . }}</span></p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Public URL</th>
                    <th>Client</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Uptime</th>
                    <th>Traffic (In / Out)</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {{range .}}
                <tr>
                    <td>{{ .ID }}</td>
                    <td>{{ .Type }}</td>
                    <td class="url">{{ .PublicURL }}</td>
                    <td>{{ .ClientAddr }}</td>
                    <td class="status-{{ .Status }}">{{ .Status }}</td>
                    <td>{{ .CreatedAt.Format "2006-01-02 15:04:05" }}</td>
                    <td>{{ duration .CreatedAt }}</td>
                    <td>{{ formatBytes .TotalBytesIn.Load }} / {{ formatBytes .TotalBytesOut.Load }}</td>
                    <td>
                        <form method="POST" style="margin:0;">
                            <input type="hidden" name="csrf_token" value="{{ csrfToken }}">
                            <input type="hidden" name="tunnelId" value="{{ .ID }}">
                            <button type="submit" class="action-button">Close</button>
                        </form>
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
    <script>
        const toggleSwitch = document.querySelector('.theme-switch input[type="checkbox"]');
        const currentTheme = localStorage.getItem('theme');

        if (currentTheme) {
            document.body.classList.add(currentTheme);
        
            if (currentTheme === 'light-mode') {
                toggleSwitch.checked = true;
            }
        }

        function switchTheme(e) {
            if (e.target.checked) {
                document.body.classList.add('light-mode');
                localStorage.setItem('theme', 'light-mode');
            }
            else {
                document.body.classList.remove('light-mode');
                localStorage.setItem('theme', 'dark-mode');
            }
        }

        toggleSwitch.addEventListener('change', switchTheme, false);
    </script>
</body>
</html>
`
