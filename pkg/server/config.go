package server

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// minTokenLength is the shortest accepted client token. 32 characters is 128
// bits of entropy for a hex token (openssl rand -hex 16); the documentation
// suggests openssl rand -hex 32.
const minTokenLength = 32

// minDashboardPasswordLength is the shortest accepted dashboard password. The
// dashboard limiter allows a handful of guesses per minute and source, so this
// only has to put the password out of reach of an online guessing attack.
const minDashboardPasswordLength = 12

// exampleSecrets are the placeholder tokens and passwords that appear in the
// example configuration files, the README and the repository history. They are
// public, so a server must never accept them.
var exampleSecrets = map[string]bool{
	"your-secret-token-here": true,
	"secret-token-1":         true,
	"secret-token-2":         true,
	"change-me":              true,
	"sottopasso":             true,
	// README placeholders, long enough to pass the length checks.
	"<output of openssl rand -hex 32>":   true,
	"<a strong password>":                true,
	"<one of the server's valid_tokens>": true,
}

// Validate rejects a configuration that would accept guessable secrets or send
// the dashboard password over the network in clear text. It returns every
// problem found, joined, and never includes a secret's value.
//
// It is separate from New so that library callers and tests can still build a
// Server from a partial Config; cmd/tunnel-server always calls it before
// starting.
func (c *Config) Validate() error {
	var errs []error

	if len(c.ValidTokens) == 0 {
		errs = append(errs, errors.New("valid_tokens is empty: no client could authenticate"))
	}
	for i, token := range c.ValidTokens {
		if err := checkSecret(token, minTokenLength); err != nil {
			errs = append(errs, fmt.Errorf("valid_tokens[%d] %w (generate one with: openssl rand -hex 32)", i, err))
		}
	}

	if c.DashboardAddr != "" {
		if c.DashboardUsername == "" || c.DashboardPassword == "" {
			errs = append(errs, errors.New("dashboard_addr is set, so dashboard_username and dashboard_password are both required (leave dashboard_addr empty to disable the dashboard)"))
		} else if err := checkSecret(c.DashboardPassword, minDashboardPasswordLength); err != nil {
			errs = append(errs, fmt.Errorf("dashboard_password %w", err))
		}

		hasCert, hasKey := c.DashboardTLSCertFile != "", c.DashboardTLSKeyFile != ""
		switch {
		case hasCert != hasKey:
			// Only one of the two used to fall back to plain HTTP without a word.
			errs = append(errs, errors.New("set both dashboard_tls_cert_file and dashboard_tls_key_file, or neither"))
		case !hasCert && !isLoopbackAddr(c.DashboardAddr):
			errs = append(errs, fmt.Errorf("dashboard_addr %q is reachable from the network but the dashboard has no TLS, so Basic Auth would send the password in clear text: set dashboard_tls_cert_file and dashboard_tls_key_file, or bind it to loopback (e.g. 127.0.0.1:4040) and reach it through SSH or a VPN", c.DashboardAddr))
		}
	}

	return errors.Join(errs...)
}

// checkSecret reports why secret is unacceptable, or nil. The error reads as
// the end of a sentence whose subject is the setting's name.
func checkSecret(secret string, minLen int) error {
	switch {
	case strings.TrimSpace(secret) == "":
		return errors.New("is empty")
	case exampleSecrets[secret]:
		return errors.New("is an example value from the documentation, which is public")
	case len(secret) < minLen:
		return fmt.Errorf("is too short (%d characters, minimum %d)", len(secret), minLen)
	}
	return nil
}

// isLoopbackAddr reports whether a listen address only accepts connections
// from the same machine. An empty host (":4040") listens on every interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
