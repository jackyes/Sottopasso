package protocol

import "encoding/json"

// MessageType defines the type of control message.
type MessageType string

const (
	// AuthRequestType is the type for an authentication request.
	AuthRequestType MessageType = "auth"
	// AuthResponseType is the type for an authentication response.
	AuthResponseType MessageType = "auth-resp"
	// RequestTunnelType is the type for a tunnel creation request.
	RequestTunnelType MessageType = "req-tunnel"
	// TunnelResponseType is the type for a tunnel creation response.
	TunnelResponseType MessageType = "tunnel-resp"
	// NewConnectionType is the type for notifying a new public connection.
	NewConnectionType MessageType = "new-conn"
)

// ControlMessage is a generic wrapper for all control messages.
// The Type field determines how to interpret the payload in RawPayload.
type ControlMessage struct {
	Type       MessageType     `json:"type"`
	RawPayload json.RawMessage `json:"payload"`
}

// AuthRequest is the message sent by the client for authentication.
type AuthRequest struct {
	AuthToken string `json:"auth_token"`
}

// AuthResponse is the server's response to the authentication request.
type AuthResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// RequestTunnel is the message sent by the client to request a new tunnel.
type RequestTunnel struct {
	Type      string `json:"type"` // "http" o "tcp"
	LocalPort int    `json:"local_port"`
	Subdomain string `json:"subdomain,omitempty"` // Request for a specific subdomain (optional)
}

// TunnelResponse is the server's response with the details of the created tunnel.
type TunnelResponse struct {
	PublicURL string `json:"public_url"`
	Error     string `json:"error,omitempty"`
}

// NewConnection notifies the client that a new external connection
// has been received and must be handled.
type NewConnection struct {
	// The ID of the tunnel to which this connection belongs, for future implementations
	// where a client can have multiple tunnels.
	TunnelID string `json:"tunnel_id"`
}
