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

// Tunnel rappresenta un singolo tunnel attivo gestito dal server.
type Tunnel struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	PublicURL     string         `json:"public_url"`
	Status        string         `json:"status"`
	CreatedAt     time.Time      `json:"created_at"`
	TotalBytesIn  atomic.Uint64  `json:"total_bytes_in"`
	TotalBytesOut atomic.Uint64  `json:"total_bytes_out"`
	Session       *yamux.Session `json:"-"`
}

// Config contiene la configurazione per il server.
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

// Server è la struttura principale del nostro tunnel server.
type Server struct {
	config          *Config
	tunnels         map[string]*Tunnel
	tunnelsMu       sync.RWMutex
	httpTunnels     map[string]*Tunnel
	httpTunnelsMu   sync.RWMutex
	httpServer      *http.Server
	dashboardServer *http.Server
	controlListener net.Listener
}

// New crea una nuova istanza del server.
func New(config *Config) *Server {
	return &Server{
		config:      config,
		tunnels:     make(map[string]*Tunnel),
		httpTunnels: make(map[string]*Tunnel),
	}
}

// Start avvia tutti i listener del server.
func (s *Server) Start() error {
	go s.startHTTPListener()
	go s.startDashboardListener()
	return s.startControlListener()
}

// Shutdown arresta il server in modo pulito.
func (s *Server) Shutdown() {
	log.Println("Arresto dei server...")
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

// startControlListener avvia il listener per i client.
func (s *Server) startControlListener() error {
	lsConfig, err := s.getTLSConfig(s.config.TLSCertFile, s.config.TLSKeyFile, "localhost")
	if err != nil {
		return fmt.Errorf("impossibile ottenere la configurazione TLS di controllo: %w", err)
	}

	log.Printf("Il server di controllo TLS è in ascolto su %s", s.config.ControlAddr)
	ln, err := tls.Listen("tcp", s.config.ControlAddr, lsConfig)
	if err != nil {
		return fmt.Errorf("impossibile avviare il listener di controllo TLS: %w", err)
	}
	s.controlListener = ln
	defer s.controlListener.Close()

	for {
		conn, err := s.controlListener.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				break
			}
			log.Printf("Errore durante l'accettazione di una nuova connessione TLS: %v", err)
			continue
		}
		go s.handleClientConnection(conn)
	}
	return nil
}

// startDashboardListener avvia il server web per la pagina di stato.
func (s *Server) startDashboardListener() {
	if s.config.DashboardAddr == "" {
		return
	}

	handler := http.HandlerFunc(s.serveDashboard)
	authHandler := s.basicAuth(handler)
	s.dashboardServer = &http.Server{Addr: s.config.DashboardAddr, Handler: authHandler}

	useTLS := s.config.DashboardTLSCertFile != "" && s.config.DashboardTLSKeyFile != ""
	if useTLS {
		log.Printf("Dashboard di stato sicura disponibile su https://%s", s.config.DashboardAddr)
		if _, err := s.getTLSConfig(s.config.DashboardTLSCertFile, s.config.DashboardTLSKeyFile, "localhost"); err != nil {
			log.Fatalf("Impossibile ottenere la configurazione TLS per la dashboard: %v", err)
		}
		if err := s.dashboardServer.ListenAndServeTLS(s.config.DashboardTLSCertFile, s.config.DashboardTLSKeyFile); err != http.ErrServerClosed {
			log.Printf("Errore del server dashboard TLS: %v", err)
		}
	} else {
		log.Printf("Dashboard di stato disponibile su http://%s", s.config.DashboardAddr)
		if err := s.dashboardServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("Errore del server dashboard: %v", err)
		}
	}
}

// startHTTPListener avvia il reverse proxy pubblico.
func (s *Server) startHTTPListener() {
	if s.config.HTTPAddr == "" {
		return
	}

	s.httpServer = &http.Server{Addr: s.config.HTTPAddr, Handler: s}

	if s.config.HTTPUseTLS {
		log.Printf("Il listener HTTPS è in ascolto su %s", s.config.HTTPAddr)
		if err := s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile); err != http.ErrServerClosed {
			log.Fatalf("Errore fatale del listener HTTPS: %v", err)
		}
	} else {
		log.Printf("Il listener HTTP è in ascolto su %s", s.config.HTTPAddr)
		if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Errore fatale del listener HTTP: %v", err)
		}
	}
}

// basicAuth è un middleware per l'autenticazione HTTP Basic.
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
			w.Header().Set("WWW-Authenticate", `Basic realm="Accesso ristretto"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Autenticazione richiesta.\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveDashboard è l'handler per la pagina di stato.
func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
	s.tunnelsMu.RLock()
	defer s.tunnelsMu.RUnlock()

	tunnels := make([]*Tunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		tunnels = append(tunnels, t)
	}

	tmpl, err := template.New("dashboard").Funcs(template.FuncMap{
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
			return fmt.Sprintf("%.2f MB", mb)
		},
	}).Parse(dashboardTemplate)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Errore del template: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, tunnels)
}

// getTLSConfig carica o genera una configurazione TLS.
func (s *Server) getTLSConfig(certFile, keyFile, host string) (*tls.Config, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("Certificato TLS non trovato (%s), ne genero uno nuovo.", certFile)
		if err := generateSelfSignedCert(certFile, keyFile, host); err != nil {
			return nil, fmt.Errorf("impossibile generare il certificato auto-firmato: %w", err)
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("impossibile caricare la coppia di chiavi/certificati TLS: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// generateSelfSignedCert crea un certificato e una chiave auto-firmati.
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

// ServeHTTP implementa l'interfaccia http.Handler per il reverse proxy.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	s.httpTunnelsMu.RLock()
	t, ok := s.httpTunnels[host]
	s.httpTunnelsMu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Tunnel per %s non trovato.", host)
		return
	}

	// Gestione per WebSocket
	if isWebSocketRequest(r) {
		s.handleWebSocket(w, r, t)
		return
	}

	// Gestione per richieste HTTP normali
	s.handleHTTPRequest(w, r, t)
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request, t *Tunnel) {
	host := r.Host
	log.Printf("Richiesta WebSocket per l'host %s", host)

	// Hijack della connessione per ottenere la connessione TCP sottostante
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Impossibile effettuare l'hijack della connessione per WebSocket")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Hijack fallito per WebSocket: %v", err)
		// Non possiamo inviare una risposta HTTP, la connessione è andata
		return
	}
	defer clientConn.Close()

	// Apri lo stream verso il client del tunnel
	stream, err := t.Session.OpenStream()
	if err != nil {
		log.Printf("Impossibile aprire una stream per la richiesta WebSocket a %s: %v", host, err)
		return
	}
	defer stream.Close()

	// Inoltra la richiesta di upgrade originale al client
	// È importante che questa richiesta venga scritta prima di iniziare a leggere dalla connessione del client,
	// altrimenti si potrebbe creare un deadlock.
	if err := r.Write(stream); err != nil {
		log.Printf("Errore durante la scrittura della richiesta di upgrade WebSocket sulla stream: %v", err)
		return
	}

	// A questo punto, la connessione HTTP è stata "promossa" a una connessione TCP bidirezionale.
	// Dobbiamo fare da proxy tra la connessione del browser (clientConn) e la stream del tunnel.
	// Questo gestirà la risposta 101 e il successivo traffico WebSocket.
	mClientConn := tunnel_pkg.NewMeasuredConn(clientConn, &t.TotalBytesIn, &t.TotalBytesOut)
	mStream := tunnel_pkg.NewMeasuredConn(stream, &t.TotalBytesOut, &t.TotalBytesIn)

	log.Printf("Avvio del proxy WebSocket per %s", host)
	tunnel_pkg.Proxy(mClientConn, mStream)
	log.Printf("Proxy WebSocket per %s terminato", host)
}

func (s *Server) handleHTTPRequest(w http.ResponseWriter, r *http.Request, t *Tunnel) {
	host := r.Host
	stream, err := t.Session.OpenStream()
	if err != nil {
		log.Printf("Impossibile aprire una stream per l'host %s: %v", host, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer stream.Close()

	mStream := tunnel_pkg.NewMeasuredConn(stream, &t.TotalBytesOut, &t.TotalBytesIn)

	// Scrivi la richiesta HTTP nella stream del tunnel
	if err := r.Write(mStream); err != nil {
		log.Printf("Errore durante la scrittura della richiesta sulla stream: %v", err)
		return
	}

	// Leggi la risposta HTTP dalla stream del tunnel
	resp, err := http.ReadResponse(bufio.NewReader(mStream), r)
	if err != nil {
		// Se c'è un errore nella lettura della risposta, potrebbe essere perché il client
		// ha chiuso la connessione. In questo caso, non inviamo una risposta HTTP.
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			log.Printf("Errore durante la lettura della risposta dalla stream: %v", err)
		}
		// Non possiamo inviare un header qui perché la connessione potrebbe essere in uno stato indeterminato.
		// Proviamo a inviare un BadGateway, ma potrebbe fallire.
		// w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copia gli header dalla risposta del tunnel alla risposta originale
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Scrivi lo status code e il corpo della risposta
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleClientConnection gestisce il ciclo di vita di un singolo client connesso.
func (s *Server) handleClientConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("Nuovo client connesso da %s", conn.RemoteAddr())

	if !s.authenticate(conn) {
		log.Printf("Autenticazione fallita per il client %s", conn.RemoteAddr())
		return
	}

	log.Printf("Client %s autenticato con successo", conn.RemoteAddr())

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.KeepAliveInterval = s.config.KeepaliveInterval
	yamuxConfig.ConnectionWriteTimeout = s.config.ConnectionWriteTimeout
	session, err := yamux.Server(conn, yamuxConfig)
	if err != nil {
		log.Printf("Errore durante la creazione della sessione yamux per %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer session.Close()

	defer s.cleanupTunnelsForSession(session)

	ctrlStream, err := session.AcceptStream()
	if err != nil {
		log.Printf("Impossibile accettare la control stream da %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer ctrlStream.Close()

	log.Printf("Control stream accettata da %s. In attesa di richieste...", conn.RemoteAddr())

	decoder := json.NewDecoder(ctrlStream)
	for {
		var msg protocol.ControlMessage
		if err := decoder.Decode(&msg); err != nil {
			log.Printf("Client %s disconnesso: %v", conn.RemoteAddr(), err)
			break
		}

		switch msg.Type {
		case protocol.RequestTunnelType:
			if err := s.handleRequestTunnel(&msg, session, ctrlStream); err != nil {
				log.Printf("Errore durante la gestione della richiesta di tunnel: %v", err)
			}
		default:
			log.Printf("Received unhandled message type: %s", msg.Type)
		}
	}

	log.Printf("Connection with client %s terminated.", conn.RemoteAddr())
}

// cleanupTunnelsForSession removes all tunnels associated with a client session.
func (s *Server) cleanupTunnelsForSession(session *yamux.Session) {
	s.tunnelsMu.Lock()
	defer s.tunnelsMu.Unlock()
	s.httpTunnelsMu.Lock()
	defer s.httpTunnelsMu.Unlock()

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
		return fmt.Errorf("unsupported tunnel type: %s", req.Type)
	}
}

func (s *Server) setupHTTPTunnel(req protocol.RequestTunnel, session *yamux.Session, ctrlStream net.Conn) error {
	var subdomain string
	var host string

	s.httpTunnelsMu.Lock()
	defer s.httpTunnelsMu.Unlock()

	if req.Subdomain != "" {
		potentialHost := fmt.Sprintf("%s.%s", req.Subdomain, s.config.Domain)
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
			host = fmt.Sprintf("%s.%s", subdomain, s.config.Domain)
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
		ID:        uuid.New().String(),
		Type:      "http",
		PublicURL: fmt.Sprintf("%s://%s", schema, host),
		Status:    "active",
		CreatedAt: time.Now(),
		Session:   session,
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
		ID:        uuid.New().String(),
		Type:      "tcp",
		PublicURL: publicAddr,
		Status:    "active",
		CreatedAt: time.Now(),
		Session:   session,
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
	var msg protocol.ControlMessage
	if err := json.NewDecoder(conn).Decode(&msg); err != nil {
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
		if token == authReq.AuthToken {
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
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 2rem;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            align-items: center;
            margin-bottom: 2rem;
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
        @media (max-width: 768px) {
            body { padding: 1rem; }
            h1 { font-size: 1.5rem; }
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
            }
            td {
                border: none;
                border-bottom: 1px solid var(--border-color);
                position: relative;
                padding-left: 50%;
            }
            td:before {
                position: absolute;
                top: 0.5rem;
                left: 0.5rem;
                width: 45%;
                padding-right: 0.5rem;
                white-space: nowrap;
                font-weight: 600;
                text-transform: uppercase;
                font-size: 0.8rem;
                color: var(--header-color);
            }
            td:nth-of-type(1):before { content: "ID"; }
            td:nth-of-type(2):before { content: "Tipo"; }
            td:nth-of-type(3):before { content: "URL Pubblico"; }
            td:nth-of-type(4):before { content: "Stato"; }
            td:nth-of-type(5):before { content: "Creato il"; }
            td:nth-of-type(6):before { content: "Traffico (In / Out)"; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
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

        <div class="summary">
            <p>Tunnel attivi: <span>{{ len . }}</span></p>
        </div>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Tipo</th>
                    <th>URL Pubblico</th>
                    <th>Stato</th>
                    <th>Creato il</th>
                    <th>Traffico (In / Out)</th>
                </tr>
            </thead>
            <tbody>
                {{range .}}
                <tr>
                    <td>{{ .ID }}</td>
                    <td>{{ .Type }}</td>
                    <td class="url">{{ .PublicURL }}</td>
                    <td class="status-{{ .Status }}">{{ .Status }}</td>
                    <td>{{ .CreatedAt.Format "2006-01-02 15:04:05" }}</td>
                    <td>{{ formatBytes .TotalBytesIn.Load }} / {{ formatBytes .TotalBytesOut.Load }}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>
`
