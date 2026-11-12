package server

import (
	"encoding/json"
	"net"
	"testing"

	"Sottopasso/pkg/protocol"
)

// requestHTTPTunnel asks s for an HTTP tunnel on subdomain and returns the
// response sent to the client.
func requestHTTPTunnel(t *testing.T, s *Server, subdomain string) protocol.TunnelResponse {
	t.Helper()
	sess, _ := newYamuxPair(t)
	ctrl1, ctrl2 := net.Pipe()
	defer ctrl1.Close()
	defer ctrl2.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.setupHTTPTunnel(protocol.RequestTunnel{Type: "http", Subdomain: subdomain}, sess, ctrl1)
	}()
	resp := readControl(t, ctrl2)
	<-errCh
	var tr protocol.TunnelResponse
	if err := json.Unmarshal(resp.RawPayload, &tr); err != nil {
		t.Fatalf("invalid TunnelResponse: %v", err)
	}
	return tr
}

// Operator-configured reserved names must block a request whatever the case
// or surrounding whitespace in the configuration file: requests are always
// lowercased, so "API" in the config used to block nothing.
func TestSetupHTTPTunnel_ReservedSubdomainsAreCaseInsensitive(t *testing.T) {
	s := New(&Config{Domain: "localhost", ReservedSubdomains: []string{"API", " Mail "}})
	for _, req := range []string{"api", "API", "mail", "MAIL"} {
		if tr := requestHTTPTunnel(t, s, req); tr.Error == "" {
			t.Errorf("subdomain %q was granted (%s) despite being reserved", req, tr.PublicURL)
		}
	}
	if len(s.httpTunnels) != 0 {
		t.Errorf("reserved subdomains created %d tunnels, want 0", len(s.httpTunnels))
	}
}

// Random subdomains are the only thing between a scanner and a tunnel that
// does no authentication of its own, so they must not be enumerable.
func TestRandomSubdomain_EntropyAndShape(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		sub := randomSubdomain()
		if len(sub) != 16 {
			t.Fatalf("randomSubdomain()=%q has %d characters, want 16 (80 bits)", sub, len(sub))
		}
		if !validSubdomain.MatchString(sub) {
			t.Fatalf("randomSubdomain()=%q is not a valid DNS label", sub)
		}
		if seen[sub] {
			t.Fatalf("randomSubdomain() repeated %q", sub)
		}
		seen[sub] = true
	}
}

func TestSetupHTTPTunnel_AssignsRandomSubdomain(t *testing.T) {
	s := New(&Config{Domain: "localhost"})
	tr := requestHTTPTunnel(t, s, "")
	if tr.Error != "" {
		t.Fatalf("setupHTTPTunnel: %s", tr.Error)
	}
	const prefix, suffix = "http://", ".localhost"
	sub := tr.PublicURL[len(prefix) : len(tr.PublicURL)-len(suffix)]
	if len(sub) != 16 || !validSubdomain.MatchString(sub) {
		t.Errorf("PublicURL=%q: random subdomain %q, want 16 DNS-safe characters", tr.PublicURL, sub)
	}
}
