package client

import (
	"Sottopasso/pkg/protocol"
	"Sottopasso/pkg/tunnel"
	"bytes"
	"crypto/tls"
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
	TunnelType             string        // Type of tunnel to request ("tcp" or "http")
	LocalPort              int           // Local port to expose
	Subdomain              string        // Requested subdomain (optional)
	InsecureSkipVerify     bool          // If true, ignores server TLS certificate verification
	KeepaliveInterval      time.Duration // Keepalive interval for yamux session
	ConnectionWriteTimeout time.Duration // Write timeout for yamux connection
	MaxConcurrentStreams   int           // Max concurrent server-opened streams handled at once (0 = unlimited)
	DialTimeout            time.Duration // Timeout dialing the local service (0 = no timeout)
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

// prefixConn returns buffered bytes before delegating to the underlying conn, so bytes
// a json.Decoder read past the auth response are not lost when yamux takes over.
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

	sessionConn, err := c.authenticate(conn)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	log.Println("Authentication successful.")

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.KeepAliveInterval = c.config.KeepaliveInterval
	yamuxConfig.ConnectionWriteTimeout = c.config.ConnectionWriteTimeout

	session, err := yamux.Client(sessionConn, yamuxConfig)
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

	var sem chan struct{}
	if c.config.MaxConcurrentStreams > 0 {
		sem = make(chan struct{}, c.config.MaxConcurrentStreams)
	}
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return fmt.Errorf("session terminated: %w", err)
		}
		if sem != nil {
			sem <- struct{}{} // backpressure: stop accepting once at capacity
		}
		go func(stream net.Conn) {
			if sem != nil {
				defer func() { <-sem }()
			}
			c.handleServerStream(stream)
		}(stream)
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
	if err := json.NewDecoder(io.LimitReader(ctrlStream, 1<<20)).Decode(&respMsg); err != nil {
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

	addr := fmt.Sprintf("localhost:%d", c.config.LocalPort)
	var localConn net.Conn
	var err error
	if c.config.DialTimeout > 0 {
		localConn, err = net.DialTimeout("tcp", addr, c.config.DialTimeout)
	} else {
		localConn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		log.Printf("[%s] Unable to connect to local service: %v", connID, err)
		return
	}
	defer localConn.Close()

	// Account traffic once, on the server-facing stream. localConn relays the same
	// bytes, so measuring it too would double the reported figures.
	var bytesIn, bytesOut, ignoreIn, ignoreOut atomic.Uint64
	mStream := tunnel.NewMeasuredConn(stream, &bytesIn, &bytesOut)
	mLocalConn := tunnel.NewMeasuredConn(localConn, &ignoreIn, &ignoreOut)

	tunnel.Proxy(mStream, mLocalConn)

	log.Printf("[%s] Connection terminated. Traffic: %d bytes in, %d bytes out.", connID, bytesIn.Load(), bytesOut.Load())
}

// authenticate sends credentials and waits for the server's response.
func (c *Client) authenticate(conn net.Conn) (net.Conn, error) {
	// Create and send the AuthRequest message
	authReq := protocol.AuthRequest{AuthToken: c.config.AuthToken}
	payload, _ := json.Marshal(authReq)
	msg := protocol.ControlMessage{
		Type:       protocol.AuthRequestType,
		RawPayload: payload,
	}

	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		return conn, fmt.Errorf("error sending auth request: %w", err)
	}

	// Wait and read the server's response. Keep the decoder so any bytes it buffers
	// past the response can be handed to yamux instead of being dropped.
	dec := json.NewDecoder(io.LimitReader(conn, 1<<20))
	var respMsg protocol.ControlMessage
	if err := dec.Decode(&respMsg); err != nil {
		return conn, fmt.Errorf("error decoding auth response: %w", err)
	}

	if respMsg.Type != protocol.AuthResponseType {
		return conn, fmt.Errorf("received unexpected message type %s", respMsg.Type)
	}

	var authResp protocol.AuthResponse
	if err := json.Unmarshal(respMsg.RawPayload, &authResp); err != nil {
		return conn, fmt.Errorf("error unmarshaling AuthResponse payload: %w", err)
	}

	if !authResp.Success {
		return conn, fmt.Errorf("server rejected authentication: %s", authResp.Error)
	}

	// dec.Buffered() holds the JSON-lines delimiter (a trailing newline) plus any bytes
	// the peer pipelined after it. Trim the inter-message whitespace; whatever remains is
	// genuine session data (yamux frames never start with ASCII whitespace).
	buffered, _ := io.ReadAll(dec.Buffered())
	if buffered = bytes.TrimLeft(buffered, " \t\r\n"); len(buffered) > 0 {
		return &prefixConn{Conn: conn, prefix: buffered}, nil
	}
	return conn, nil
}
