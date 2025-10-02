package client

import (
	"Sottopasso/pkg/protocol"
	"Sottopasso/pkg/tunnel"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
	TunnelType             string        // Type of tunnel to request ("tcp" or "http")
	LocalPort              int           // Local port to expose
	Subdomain              string        // Requested subdomain (optional)
	InsecureSkipVerify     bool          // If true, ignores server TLS certificate verification
	KeepaliveInterval      time.Duration // Keepalive interval for yamux session
	ConnectionWriteTimeout time.Duration // Write timeout for yamux connection
}

// Client is the main structure of our tunnel client.
type Client struct {
	config *Config
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
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.config.InsecureSkipVerify,
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
	log.Printf("[%s] New connection from server, forwarding to localhost:%d.", connID, c.config.LocalPort)

	localConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", c.config.LocalPort))
	if err != nil {
		log.Printf("[%s] Unable to connect to local service: %v", connID, err)
		return
	}
	defer localConn.Close()

	var bytesIn, bytesOut atomic.Uint64
	mStream := tunnel.NewMeasuredConn(stream, &bytesIn, &bytesOut)
	mLocalConn := tunnel.NewMeasuredConn(localConn, &bytesOut, &bytesIn)

	tunnel.Proxy(mStream, mLocalConn)

	log.Printf("[%s] Connection terminated. Traffic: %d bytes in, %d bytes out.", connID, bytesIn.Load(), bytesOut.Load())
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
