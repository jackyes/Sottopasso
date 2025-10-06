package client

import (
	"Sottopasso/pkg/pool"
	"Sottopasso/pkg/protocol"
	customtls "Sottopasso/pkg/tls"
	"Sottopasso/pkg/tunnel"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"
)

// Config contains the configuration for the client.
type Config struct {
	ServerAddr             string        // Control server address (e.g., "tunnel.example.com:8080")
	AuthToken              string        // Authentication token to send to the server
	TunnelType             string        // Type of tunnel to request ("tcp", "http", or "udp")
	LocalPort              int           // Local port to expose
	Subdomain              string        // Requested subdomain (optional)
	InsecureSkipVerify     bool          // If true, ignores server TLS certificate verification
	KeepaliveInterval      time.Duration // Keepalive interval for yamux session
	ConnectionWriteTimeout time.Duration // Write timeout for yamux connection

	// TLS Session Resumption configuration
	TLSConfig TLSConfig
}

// TLSConfig contains configuration for TLS optimization
type TLSConfig struct {
	EnableSessionResumption bool `json:"enable_session_resumption"`
}

// Client is the main structure of our tunnel client.
type Client struct {
	config *Config
	pool   *pool.ConnectionPool
}

// New creates a new client instance.
func New(config *Config) *Client {
	return &Client{
		config: config,
	}
}

// Start connects to the server, authenticates, and manages the tunnel.
func (c *Client) Start() error {
	log.Printf("Connecting to TLS control server at %s...", c.config.ServerAddr)

	// Create base TLS config
	baseTLSConfig := &tls.Config{
		InsecureSkipVerify: c.config.InsecureSkipVerify,
	}

	// Enhance with session resumption if enabled
	var tlsConfig *tls.Config
	if c.config.TLSConfig.EnableSessionResumption {
		sessionManager := customtls.GetGlobalSessionManager()
		tlsConfig = sessionManager.GetClientTLSConfig(baseTLSConfig)
	} else {
		tlsConfig = baseTLSConfig
	}

	conn, err := tls.Dial("tcp", c.config.ServerAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("unable to connect to TLS server: %w", err)
	}
	defer conn.Close()

	log.Println("TLS connection established. Authenticating...")

	if err := c.authenticate(conn); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	log.Println("Authentication successful.")

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.KeepAliveInterval = c.config.KeepaliveInterval
	yamuxConfig.ConnectionWriteTimeout = c.config.ConnectionWriteTimeout

	session, err := yamux.Client(conn, yamuxConfig)
	if err != nil {
		return fmt.Errorf("unable to create yamux session: %w", err)
	}
	defer session.Close()

	// Initialize connection pool
	poolConfig := pool.PoolConfig{
		MaxSize:     100,
		IdleTimeout: 30 * time.Second,
		MaxIdle:     20,
	}
	c.pool = pool.NewConnectionPool(session, poolConfig)
	defer c.pool.Close()

	ctrlStream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("unable to open control stream: %w", err)
	}

	publicURL, err := c.requestTunnel(ctrlStream)
	if err != nil {
		return fmt.Errorf("tunnel request failed: %w", err)
	}
	log.Printf("Public tunnel available at: %s", publicURL)
	log.Printf("Forwarding to: localhost:%d", c.config.LocalPort)

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return fmt.Errorf("session terminated: %w", err)
		}
		go c.handleServerStream(stream)
	}
}

// requestTunnel sends a tunnel creation request and waits for the response.
func (c *Client) requestTunnel(ctrlStream net.Conn) (string, error) {
	req := protocol.RequestTunnel{
		Type:      c.config.TunnelType,
		LocalPort: c.config.LocalPort,
		Subdomain: c.config.Subdomain,
	}
	payload, _ := json.Marshal(req)
	msg := protocol.ControlMessage{
		Type:       protocol.RequestTunnelType,
		RawPayload: payload,
	}

	if err := json.NewEncoder(ctrlStream).Encode(msg); err != nil {
		return "", fmt.Errorf("unable to send tunnel request: %w", err)
	}

	var respMsg protocol.ControlMessage
	if err := json.NewDecoder(ctrlStream).Decode(&respMsg); err != nil {
		return "", fmt.Errorf("unable to decode tunnel response: %w", err)
	}

	if respMsg.Type != protocol.TunnelResponseType {
		return "", fmt.Errorf("received unexpected message type %s", respMsg.Type)
	}

	var tunnelResp protocol.TunnelResponse
	if err := json.Unmarshal(respMsg.RawPayload, &tunnelResp); err != nil {
		return "", fmt.Errorf("unable to unmarshal TunnelResponse payload: %w", err)
	}

	if tunnelResp.Error != "" {
		return "", fmt.Errorf("server responded with an error: %s", tunnelResp.Error)
	}

	return tunnelResp.PublicURL, nil
}

// handleServerStream handles a new stream opened by the server (a new public connection).
func (c *Client) handleServerStream(stream net.Conn) {
	defer stream.Close()
	connID := uuid.New().String()[:8]

	if c.config.TunnelType == "udp" {
		c.handleUDPServerStream(stream, connID)
	} else {
		c.handleTCPServerStream(stream, connID)
	}
}

// handleTCPServerStream handles TCP connections from the server.
func (c *Client) handleTCPServerStream(stream net.Conn, connID string) {
	log.Printf("[%s] New TCP connection from server, forwarding to localhost:%d.", connID, c.config.LocalPort)

	localConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", c.config.LocalPort))
	if err != nil {
		log.Printf("[%s] Unable to connect to local TCP service: %v", connID, err)
		return
	}
	defer localConn.Close()

	var bytesIn, bytesOut atomic.Uint64
	mStream := tunnel.NewMeasuredConn(stream, &bytesIn, &bytesOut, "tunnel")
	mLocalConn := tunnel.NewMeasuredConn(localConn, &bytesOut, &bytesIn, "local")

	tunnel.Proxy(mStream, mLocalConn)

	log.Printf("[%s] TCP connection terminated. Traffic: %d bytes in, %d bytes out.", connID, bytesIn.Load(), bytesOut.Load())
}

// handleUDPServerStream handles UDP connections from the server.
func (c *Client) handleUDPServerStream(stream net.Conn, connID string) {
	log.Printf("[%s] New UDP packet from server, forwarding to localhost:%d.", connID, c.config.LocalPort)

	// Get buffer pool instance
	bufferPool := pool.GetGlobalBufferPool()

	// Read address length (4 bytes)
	addrLenBytes := bufferPool.GetSmall()[:4]
	defer bufferPool.PutSmall(addrLenBytes)
	if _, err := io.ReadFull(stream, addrLenBytes); err != nil {
		log.Printf("[%s] Error reading address length: %v", connID, err)
		return
	}
	addrLen := binary.BigEndian.Uint32(addrLenBytes)

	// Read client address
	addrBytes := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBytes); err != nil {
		log.Printf("[%s] Error reading address: %v", connID, err)
		return
	}
	clientAddr := string(addrBytes)
	log.Printf("[%s] UDP packet from client %s", connID, clientAddr)

	// Read the UDP packet data using pooled buffer instead of io.ReadAll
	packetBuffer := bufferPool.GetLarge()
	defer bufferPool.PutLarge(packetBuffer)

	packetSize := 0
	for {
		n, err := stream.Read(packetBuffer[packetSize:])
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading UDP packet data: %v", connID, err)
			}
			break
		}
		packetSize += n
		if packetSize >= len(packetBuffer) {
			log.Printf("[%s] Warning: UDP packet exceeds maximum buffer size", connID)
			break
		}
	}

	// Connect to local UDP service
	localConn, err := net.Dial("udp", fmt.Sprintf("localhost:%d", c.config.LocalPort))
	if err != nil {
		log.Printf("[%s] Unable to connect to local UDP service: %v", connID, err)
		return
	}
	defer localConn.Close()

	// Send packet to local service
	if _, err := localConn.Write(packetBuffer[:packetSize]); err != nil {
		log.Printf("[%s] Error sending packet to local UDP service: %v", connID, err)
		return
	}

	// Read response from local service with timeout
	localConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	response := bufferPool.GetLarge()
	defer bufferPool.PutLarge(response)
	n, err := localConn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("[%s] Timeout waiting for response from local UDP service", connID)
		} else {
			log.Printf("[%s] Error reading response from local UDP service: %v", connID, err)
		}
		return
	}

	// Send response back to server
	if _, err := stream.Write(response[:n]); err != nil {
		log.Printf("[%s] Error sending response to server: %v", connID, err)
		return
	}

	log.Printf("[%s] UDP packet forwarded. Data: %d bytes in, %d bytes out.", connID, packetSize, n)
}

// authenticate sends credentials and waits for the server's response.
func (c *Client) authenticate(conn net.Conn) error {
	// Create and send the AuthRequest message
	authReq := protocol.AuthRequest{AuthToken: c.config.AuthToken}
	payload, _ := json.Marshal(authReq)
	msg := protocol.ControlMessage{
		Type:       protocol.AuthRequestType,
		RawPayload: payload,
	}

	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		return fmt.Errorf("error sending auth request: %w", err)
	}

	// Wait and read the server's response
	var respMsg protocol.ControlMessage
	if err := json.NewDecoder(conn).Decode(&respMsg); err != nil {
		return fmt.Errorf("error decoding auth response: %w", err)
	}

	if respMsg.Type != protocol.AuthResponseType {
		return fmt.Errorf("received unexpected message type %s", respMsg.Type)
	}

	var authResp protocol.AuthResponse
	if err := json.Unmarshal(respMsg.RawPayload, &authResp); err != nil {
		return fmt.Errorf("error unmarshaling AuthResponse payload: %w", err)
	}

	if !authResp.Success {
		return fmt.Errorf("server rejected authentication: %s", authResp.Error)
	}

	return nil
}
