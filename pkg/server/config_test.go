package server

import (
	"strings"
	"testing"
)

const (
	testToken    = "0123456789abcdef0123456789abcdef" // exactly minTokenLength
	testPassword = "correct-horse-battery"
)

// validConfig returns a configuration that passes Validate, with the
// dashboard enabled on loopback over plain HTTP.
func validConfig() *Config {
	return &Config{
		ValidTokens:       []string{testToken},
		DashboardAddr:     "127.0.0.1:4040",
		DashboardUsername: "admin",
		DashboardPassword: testPassword,
	}
}

func TestValidate_AcceptsValidConfig(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	c := validConfig()
	c.DashboardAddr = ""
	c.DashboardUsername, c.DashboardPassword = "", ""
	if err := c.Validate(); err != nil {
		t.Fatalf("config without dashboard rejected: %v", err)
	}
}

func TestValidate_Rejects(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Config)
		want   string
	}{
		{"no tokens", func(c *Config) { c.ValidTokens = nil }, "valid_tokens is empty"},
		{"empty token", func(c *Config) { c.ValidTokens = []string{testToken, ""} }, "valid_tokens[1] is empty"},
		{"blank token", func(c *Config) { c.ValidTokens = []string{"   "} }, "valid_tokens[0] is empty"},
		{"short token", func(c *Config) { c.ValidTokens = []string{"0123456789abcdef0123456789abcde"} }, "valid_tokens[0] is too short (31 characters, minimum 32)"},
		{"example token", func(c *Config) { c.ValidTokens = []string{"your-secret-token-here"} }, "valid_tokens[0] is an example value"},
		{"history token", func(c *Config) { c.ValidTokens = []string{"secret-token-2"} }, "valid_tokens[0] is an example value"},
		{"README token placeholder", func(c *Config) { c.ValidTokens = []string{"<output of openssl rand -hex 32>"} }, "valid_tokens[0] is an example value"},
		{"README password placeholder", func(c *Config) { c.DashboardPassword = "<a strong password>" }, "dashboard_password is an example value"},
		{"dashboard without password", func(c *Config) { c.DashboardPassword = "" }, "dashboard_username and dashboard_password are both required"},
		{"dashboard without username", func(c *Config) { c.DashboardUsername = "" }, "dashboard_username and dashboard_password are both required"},
		{"example password", func(c *Config) { c.DashboardPassword = "change-me" }, "dashboard_password is an example value"},
		{"history password", func(c *Config) { c.DashboardPassword = "sottopasso" }, "dashboard_password is an example value"},
		{"short password", func(c *Config) { c.DashboardPassword = "short-pass1" }, "dashboard_password is too short (11 characters, minimum 12)"},
		{"HTTP on all interfaces", func(c *Config) { c.DashboardAddr = ":4040" }, "no TLS"},
		{"HTTP on public address", func(c *Config) { c.DashboardAddr = "192.0.2.10:4040" }, "no TLS"},
		{"HTTP on hostname", func(c *Config) { c.DashboardAddr = "dashboard.example.com:4040" }, "no TLS"},
		{"only TLS cert", func(c *Config) { c.DashboardTLSCertFile = "cert.pem" }, "set both dashboard_tls_cert_file and dashboard_tls_key_file"},
		{"only TLS key", func(c *Config) { c.DashboardTLSKeyFile = "key.pem" }, "set both dashboard_tls_cert_file and dashboard_tls_key_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.modify(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("config accepted, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestValidate_DashboardLoopbackOrTLS(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:4040", "[::1]:4040", "localhost:4040", "LocalHost:4040"} {
		c := validConfig()
		c.DashboardAddr = addr
		if err := c.Validate(); err != nil {
			t.Errorf("HTTP dashboard on loopback %q rejected: %v", addr, err)
		}
	}
	c := validConfig()
	c.DashboardAddr = ":4040"
	c.DashboardTLSCertFile, c.DashboardTLSKeyFile = "cert.pem", "key.pem"
	if err := c.Validate(); err != nil {
		t.Errorf("TLS dashboard on all interfaces rejected: %v", err)
	}
}

// Errors name the setting but must never echo a secret back into the logs.
func TestValidate_ErrorsDoNotContainSecrets(t *testing.T) {
	const shortToken = "tok-0123456789"
	const shortPass = "pw-123"
	c := validConfig()
	c.ValidTokens = []string{shortToken}
	c.DashboardPassword = shortPass
	err := c.Validate()
	if err == nil {
		t.Fatal("weak secrets accepted")
	}
	for _, secret := range []string{shortToken, shortPass} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q contains the secret %q", err, secret)
		}
	}
}

func TestValidate_ReportsEveryProblem(t *testing.T) {
	c := validConfig()
	c.ValidTokens = []string{"short"}
	c.DashboardPassword = "change-me"
	c.DashboardAddr = ":4040"
	err := c.Validate()
	if err == nil {
		t.Fatal("invalid config accepted")
	}
	for _, want := range []string{"valid_tokens[0]", "dashboard_password", "no TLS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
