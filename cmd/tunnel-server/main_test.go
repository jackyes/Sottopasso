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

// Behavioral tests for the server CLI: build the binary and exercise the config
// validation paths that fail fast (before the blocking Start()). See the client
// main_test.go for notes on why subprocess coverage is not reflected in `go tool
// cover` yet the behavior is still verified.

var serverBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "server-bin")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	serverBin = filepath.Join(dir, "tunnel-server")
	if runtime.GOOS == "windows" {
		serverBin += ".exe"
	}
	build := exec.Command("go", "build", "-o", serverBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		panic("building tunnel-server failed: " + err.Error() + "\n" + string(out))
	}
	os.Exit(m.Run())
}

func runServer(t *testing.T, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin, args...)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("server did not exit in time (args=%v); output:\n%s", args, out)
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running server failed: %v", err)
		}
	}
	return string(out), code
}

func TestServerCLI_MissingConfigFile(t *testing.T) {
	out, code := runServer(t, "-config", "definitely-not-here.yml")
	if code == 0 {
		t.Errorf("expected non-zero exit for a missing config; output:\n%s", out)
	}
	if !strings.Contains(out, "Error reading configuration file") {
		t.Errorf("want config-read error; got:\n%s", out)
	}
}

func TestServerCLI_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(cfg, []byte("control_addr: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runServer(t, "-config", cfg)
	if code == 0 {
		t.Errorf("expected non-zero exit for invalid YAML; output:\n%s", out)
	}
	if !strings.Contains(out, "Error parsing YAML") {
		t.Errorf("want YAML parse error; got:\n%s", out)
	}
}

func TestServerCLI_InvalidDuration(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "dur.yml")
	content := "control_addr: \":0\"\nkeepalive_interval: \"notaduration\"\n"
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runServer(t, "-config", cfg)
	if code == 0 {
		t.Errorf("expected non-zero exit for an invalid duration; output:\n%s", out)
	}
	if !strings.Contains(out, "Invalid keepalive_interval") {
		t.Errorf("want keepalive duration error; got:\n%s", out)
	}
}
