package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These are behavioral (black-box) tests: they build the real binary and run it
// with various arguments, asserting exit codes and diagnostics. They cover the
// CLI's fast early-exit paths (help, argument validation, missing token) without
// reaching the blocking network code in main(). Coverage of a separate process is
// not reflected in `go tool cover`, but the behavior is verified end to end.

var clientBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "client-bin")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	clientBin = filepath.Join(dir, "tunnel-client")
	if runtime.GOOS == "windows" {
		clientBin += ".exe"
	}
	build := exec.Command("go", "build", "-o", clientBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("building tunnel-client failed: " + err.Error() + "\n" + string(out))
	}
	os.Exit(m.Run())
}

// runClient executes the built binary in an isolated working directory (so it does
// not pick up any real config.client.yml) with a hard timeout to prevent hangs.
func runClient(t *testing.T, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, clientBin, args...)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("client did not exit in time (args=%v); output:\n%s", args, out)
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running client failed: %v", err)
		}
	}
	return string(out), code
}

func TestClientCLI_Help(t *testing.T) {
	out, code := runClient(t, "help")
	if code != 0 {
		t.Errorf("help: exit=%d, want 0; output:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "usage") {
		t.Errorf("help output should contain usage; got:\n%s", out)
	}
}

func TestClientCLI_MissingToken(t *testing.T) {
	out, code := runClient(t) // no args, no config -> empty auth token
	if code == 0 {
		t.Errorf("expected non-zero exit when token is missing; output:\n%s", out)
	}
	if !strings.Contains(out, "Authentication token is required") {
		t.Errorf("want 'Authentication token is required'; got:\n%s", out)
	}
}

func TestClientCLI_SinglePositionalArgIsRejected(t *testing.T) {
	out, code := runClient(t, "http") // one non-help positional arg, no port
	if code == 0 {
		t.Errorf("expected non-zero exit for a single positional arg; output:\n%s", out)
	}
	if !strings.Contains(out, "Both protocol and port") {
		t.Errorf("want the protocol+port usage error; got:\n%s", out)
	}
}

func TestClientCLI_InvalidPort(t *testing.T) {
	out, code := runClient(t, "http", "notaport")
	if code == 0 {
		t.Errorf("expected non-zero exit for an invalid port; output:\n%s", out)
	}
	if !strings.Contains(out, "Invalid port number") {
		t.Errorf("want 'Invalid port number'; got:\n%s", out)
	}
}
