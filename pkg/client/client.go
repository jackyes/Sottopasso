package client

import (
	"Sottopasso/pkg/protocol"
	"Sottopasso/pkg/tunnel"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"
)

// Reconnect defaults, applied when the corresponding Config field is unset.
const (
	defaultReconnectMinBackoff = 1 * time.Second
	defaultReconnectMaxBackoff = 60 * time.Second
)

// FatalError marks a failure that reconnecting cannot fix, so Start gives up
// instead of retrying. Every other error is treated as transient.
type FatalError struct{ Err error }

func (e *FatalError) Error() string { return e.Err.Error() }
func (e *FatalError) Unwrap() error { return e.Err }

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
	ConnectTimeout         time.Duration // Timeout dialing the control server (0 = OS default)
	ReconnectMinBackoff    time.Duration // First reconnect delay (0 = 1s)
	ReconnectMaxBackoff    time.Duration // Reconnect delay ceiling (0 = 60s)
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

// nextBackoff doubles cur, clamped to max.
func nextBackoff(cur, max time.Duration) time.Duration {
	if cur <= 0 {
		return max
	}
	next := cur * 2
	if next > max || next < cur { // the second test catches duration overflow
		return max
	}
	return next
}

// jitter spreads d over [d/2, d] so clients that dropped together do not all
// come back at the same instant.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(rand.Int63n(int64(half)+1))
}

// subdomainOf returns the leading DNS label of a public URL's host, lowercased.
// setupHTTPTunnel builds HTTP public URLs as "<scheme>://<subdomain>.<domain>",
// so the first label is the subdomain the server actually granted. Returns ""
// when the URL cannot be parsed or carries no host.
func subdomainOf(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	label, _, _ := strings.Cut(host, ".")
	return strings.ToLower(label)
}

// Start keeps a tunnel up for as long as ctx lives, reconnecting with an
// exponential backoff whenever the session drops. It returns nil once ctx is
// cancelled, and a *FatalError when retrying cannot help (a rejected token).
func (c *Client) Start(ctx context.Context) error {
	minBackoff := c.config.ReconnectMinBackoff
	if minBackoff <= 0 {
		minBackoff = defaultReconnectMinBackoff
	}
	maxBackoff := c.config.ReconnectMaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultReconnectMaxBackoff
	}
	if maxBackoff < minBackoff {
		maxBackoff = minBackoff
	}

	delay := minBackoff
	attempt := 0
	for {
		// onEstablished runs synchronously inside runSession, so mutating the
		// loop state from it needs no extra synchronization. Resetting on a
		// working session means a tunnel that has been up for hours retries
		// immediately instead of starting at the ceiling.
		err := c.runSession(ctx, func() {
			delay = minBackoff
			attempt = 0
		})
		if ctx.Err() != nil {
			return nil // shutdown requested, not a failure
		}
		var fatal *FatalError
		if errors.As(err, &fatal) {
			return err
		}

		// Counted here rather than at the top of the loop so that the reset
		// above, which lands mid-iteration, still makes this read as 1.
		attempt++
		log.Printf("Connection lost: %v", err)
		wait := jitter(delay)
		log.Printf("Reconnecting in %s (attempt %d)...", wait.Round(time.Millisecond), attempt)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		delay = nextBackoff(delay, maxBackoff)
	}
}

// runSession performs one connection attempt: dial, authenticate, request the
// tunnel, then serve streams until the session dies. onEstablished, when
// non-nil, is called once the tunnel is confirmed up.
func (c *Client) runSession(ctx context.Context, onEstablished func()) error {
	log.Printf("Connecting to TLS control server at %s...", c.config.ServerAddr)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: c.config.ConnectTimeout},
		Config:    &tls.Config{InsecureSkipVerify: c.config.InsecureSkipVerify},
	}
	conn, err := dialer.DialContext(ctx, "tcp", c.config.ServerAddr)
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

	// Closing the session is what unblocks a parked AcceptStream, so a cancelled
	// ctx must reach it through this watcher rather than the deferred Close
	// below (which only runs once AcceptStream has already returned). yamux's
	// Close is idempotent, so the two racing is harmless.
	sessCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	go func() {
		<-sessCtx.Done()
		session.Close()
	}()

	ctrlStream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("unable to open control stream: %w", err)
	}

	// One decoder for the control stream's lifetime: a throwaway decoder per
	// response would discard bytes it buffered past the current message, losing
	// pipelined responses (the same bug once fixed on the server side).
	ctrlDec := json.NewDecoder(io.LimitReader(ctrlStream, 1<<20))

	publicURL, err := c.requestTunnel(ctrlStream, ctrlDec)
	if err != nil {
		return fmt.Errorf("tunnel request failed: %w", err)
	}

	// The server falls back to a random subdomain, without reporting an error,
	// when the requested one is still registered. After a dropped connection
	// that holder is usually this client's own previous session, which the
	// server only releases once it notices the old socket died. Drop the
	// session and retry so the public URL stays the one the user published.
	if want := strings.ToLower(c.config.Subdomain); want != "" && c.config.TunnelType == "http" {
		if got := subdomainOf(publicURL); got != want {
			log.Printf("WARNING: server granted subdomain %q instead of the requested %q. A previous session may still hold it, or another client owns it.", got, want)
			return fmt.Errorf("subdomain %q not granted (got %q)", want, got)
		}
	}

	log.Printf("Public tunnel available at: %s", publicURL)
	log.Printf("Forwarding to: localhost:%d", c.config.LocalPort)
	if onEstablished != nil {
		onEstablished()
	}

	// Relays parked reading from a silent local service only unwind once
	// handleServerStream's watcher closes them, so cancel before waiting.
	// Deferred calls run last-registered-first, putting cancelSession ahead of
	// wg.Wait.
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancelSession()

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
			select {
			case sem <- struct{}{}: // backpressure: stop accepting once at capacity
			case <-sessCtx.Done():
				// At capacity when the session died: waiting for a slot would
				// park here instead of returning to the reconnect loop.
				stream.Close()
				return fmt.Errorf("session terminated: %w", sessCtx.Err())
			}
		}
		wg.Add(1)
		go func(stream net.Conn) {
			defer wg.Done()
			if sem != nil {
				defer func() { <-sem }()
			}
			c.handleServerStream(sessCtx, stream)
		}(stream)
	}
}

// requestTunnel sends a tunnel creation request and waits for the response.
// dec must be the control stream's long-lived decoder, shared across requests.
func (c *Client) requestTunnel(ctrlStream net.Conn, dec *json.Decoder) (string, error) {
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
	if err := dec.Decode(&respMsg); err != nil {
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
// ctx is the session's context: its cancellation tears the relay down.
func (c *Client) handleServerStream(ctx context.Context, stream net.Conn) {
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

	// Proxy parks in a read until one side sends or closes, and the half-close
	// it does on the other direction will not wake that read. Force both ends
	// shut when the session dies, otherwise a local service holding an idle
	// connection open would keep this relay (and the reconnect) waiting.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			stream.Close()
			localConn.Close()
		case <-done:
		}
	}()

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
		// The token is wrong: reconnecting would only hammer the server.
		return conn, &FatalError{Err: fmt.Errorf("server rejected authentication: %s", authResp.Error)}
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
