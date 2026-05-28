package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestControlMessage_RoundTrip(t *testing.T) {
	inner := AuthRequest{AuthToken: "tok"}
	payload, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	msg := ControlMessage{Type: AuthRequestType, RawPayload: payload}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	var got ControlMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != AuthRequestType {
		t.Errorf("Type=%q, want %q", got.Type, AuthRequestType)
	}
	var gotInner AuthRequest
	if err := json.Unmarshal(got.RawPayload, &gotInner); err != nil {
		t.Fatal(err)
	}
	if gotInner.AuthToken != "tok" {
		t.Errorf("AuthToken=%q, want tok", gotInner.AuthToken)
	}
}

func TestAuthResponse_OmitemptyError(t *testing.T) {
	// Success with no error -> "error" key must be omitted.
	data, err := json.Marshal(AuthResponse{Success: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "error") {
		t.Errorf("expected omitempty to drop error field, got %s", data)
	}

	// Failure with an error -> "error" key present.
	data, err = json.Marshal(AuthResponse{Success: false, Error: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "nope") {
		t.Errorf("expected error field, got %s", data)
	}
}

func TestRequestTunnel_RoundTripAndOmitempty(t *testing.T) {
	// Subdomain omitted when empty.
	data, err := json.Marshal(RequestTunnel{Type: "http", LocalPort: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "subdomain") {
		t.Errorf("expected omitempty to drop subdomain, got %s", data)
	}

	var rt RequestTunnel
	if err := json.Unmarshal([]byte(`{"type":"tcp","local_port":22,"subdomain":"ssh"}`), &rt); err != nil {
		t.Fatal(err)
	}
	if rt.Type != "tcp" || rt.LocalPort != 22 || rt.Subdomain != "ssh" {
		t.Errorf("decoded %+v, unexpected", rt)
	}
}

func TestTunnelResponse_RoundTrip(t *testing.T) {
	data, err := json.Marshal(TunnelResponse{PublicURL: "http://x.localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "error") {
		t.Errorf("expected omitempty to drop error, got %s", data)
	}
	var tr TunnelResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		t.Fatal(err)
	}
	if tr.PublicURL != "http://x.localhost" {
		t.Errorf("PublicURL=%q", tr.PublicURL)
	}
}

func TestNewConnection_RoundTrip(t *testing.T) {
	var nc NewConnection
	if err := json.Unmarshal([]byte(`{"tunnel_id":"abc"}`), &nc); err != nil {
		t.Fatal(err)
	}
	if nc.TunnelID != "abc" {
		t.Errorf("TunnelID=%q, want abc", nc.TunnelID)
	}
}

func TestControlMessage_MalformedPayloadDecodesLater(t *testing.T) {
	// A ControlMessage with an invalid inner payload should still decode at the
	// envelope level; only the inner Unmarshal should fail.
	var msg ControlMessage
	if err := json.Unmarshal([]byte(`{"type":"auth","payload":"not-an-object"}`), &msg); err != nil {
		t.Fatalf("envelope decode should succeed: %v", err)
	}
	var ar AuthRequest
	if err := json.Unmarshal(msg.RawPayload, &ar); err == nil {
		t.Error("expected inner unmarshal of a string into AuthRequest to fail")
	}
}

func TestControlMessage_InvalidJSON(t *testing.T) {
	var msg ControlMessage
	if err := json.Unmarshal([]byte(`{bad json`), &msg); err == nil {
		t.Error("expected error decoding invalid JSON")
	}
}
