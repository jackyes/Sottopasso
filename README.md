# Sottopasso

`Sottopasso` is a secure, self-hosted tunneling service, similar to ngrok, written entirely in Go. It allows you to securely expose local services (web servers, SSH, databases, etc.) to the Internet through a public server.

The application consists of two components:
*   `tunnel-server`: The daemon to run on a public machine with a fixed IP address.
*   `tunnel-client`: The command-line utility to run on the local machine to expose a service.

## Features

- **Secure Control Channel**: All communication between client and server occurs over a TLS-encrypted TCP channel multiplexed with `yamux` for maximum efficiency.
- **Token-based Authentication**: Only clients with a valid token can connect to the server.
- **HTTP(S) Tunnel**: Exposes a local web server on a unique subdomain of the public server.
- **TCP Tunnel**: Exposes a local TCP service (like SSH or a database) on a random public TCP port of the server.
- **Status Dashboard**: An optional web page, protected by TLS and Basic Auth, that shows all active tunnels in real time, their status, and data traffic.
- **Flexible Configuration**: Complete management via YAML files, with the possibility of override via command-line flags.
- **Automatic Certificate Generation**: The server automatically generates self-signed TLS certificates on first startup to simplify development and deployment.
- **Robust Management**: Automatic cleanup of tunnels on client disconnection and graceful shutdown of both components.
- **Automatic Reconnection**: The client rides out network failures on its own, reconnecting with an exponential backoff and reclaiming its subdomain so the public URL stays put.

## Compilation

You need to have **Go (version 1.18 or later)** installed.

1.  Clone the repository or download the files into a directory.
2.  Open a terminal in the main project directory.
3.  Compile the server and client for your platform:

    ```bash
    # Compile the server
    go build -o tunnel-server.exe ./cmd/tunnel-server

    # Compile the client
    go build -o tunnel-client.exe ./cmd/tunnel-client
    ```

    *On Linux or macOS, omit the `.exe` extension.*

## Configuration

The application is configured via two YAML files.

### Server (`config.server.yml`)

Create this file in the same directory as the `tunnel-server.exe` executable.

```yaml
# Configuration file for the Tunnel Server

# Address for the client control channel (TLS)
control_addr: ":8080"

# Address for public HTTP/HTTPS traffic
http_addr: ":8001"

# Base domain used to generate HTTP tunnel URLs
# For a public server, use a real domain (e.g., "tunnel.yourdomain.com")
domain: "localhost:8001"

# Paths for the control channel TLS certificate and key files.
# If not found, they will be automatically generated.
tls_cert_file: "cert.pem"
tls_key_file: "key.pem"

# List of valid authentication tokens for clients
valid_tokens:
  - "secret-token-1"
  - "secret-token-2"

# --- Status Dashboard Configuration ---

# Address for the status dashboard (e.g., ":4040"). Leave empty to disable.
dashboard_addr: ":4040"

# (Optional) Credentials to protect dashboard access with Basic Auth
dashboard_username: "admin"
dashboard_password: "sottopasso"

# (Optional) Paths for dashboard TLS files. If omitted, the dashboard will be HTTP.
# If not found, they will be automatically generated.
dashboard_tls_cert_file: "dashboard.cert.pem"
dashboard_tls_key_file: "dashboard.key.pem"
```

### Client (`config.client.yml`)

Create this file in the same directory as the `tunnel-client.exe` executable.

```yaml
# Configuration file for the Tunnel Client

# Address of the server to connect to (TLS connection)
server_addr: "127.0.0.1:8080"

# Authentication token to use for the connection
auth_token: "secret-token-1"

# If true, the client will not verify the validity of the server's TLS certificate.
# REQUIRED for development with self-signed certificates.
insecure_skip_verify: true
```

See `config.client.example.yml` for the full set of keys, including the timeout
and reconnection settings described below.

#### Reconnection

A TCP connection killed by the network — a NAT mapping expiring, a route flap, a
server that stops answering — is torn down without a FIN or an RST, so neither
side hears about it. The client only notices when a `yamux` keepalive ping goes
unanswered, which takes roughly `keepalive_interval + connection_write_timeout`;
until then the failing socket surfaces nothing but a read timeout from the OS.

When the session does drop, the client reconnects on its own: it waits
`reconnect_min_backoff`, doubles the delay after each failed attempt up to
`reconnect_max_backoff`, and keeps retrying indefinitely. Every wait is jittered
over `[d/2, d]`, and the delay resets as soon as a tunnel is up again, so a
long-lived tunnel that drops retries immediately instead of at the ceiling.
`Ctrl-C` interrupts the wait rather than running it out.

Two behaviours are worth knowing about:

- **A rejected auth token is fatal.** Retrying cannot fix a wrong token, so the
  client logs the rejection and exits with a non-zero status. Every other
  failure is treated as transient.
- **The requested subdomain is reclaimed, not replaced.** The server releases a
  subdomain only once it notices the old session died, and in the meantime it
  quietly hands out a random one instead. Rather than serve from a URL nobody
  was told about, the client drops such a session and retries until it gets its
  subdomain back. If the subdomain is permanently unavailable — a typo, a
  reserved label, or another client holding it — this retries forever at the
  backoff ceiling; the warning logged on each attempt quotes the subdomain that
  was granted instead.

## Usage

### 1. Start the Server

Run the compiled binary. It will use the `config.server.yml` file.

```bash
./tunnel-server.exe
```

On first startup, the necessary `.pem` files will be created if they don't exist.

### 2. Start the Client

The client is started by specifying the tunnel type (`http` or `tcp`) and the local port to expose.

**Example 1: Expose a local web server on port 3000**

```bash
# Assuming you have a web server listening on http://localhost:3000
./tunnel-client.exe http 3000
```

Expected output:
```
INFO[...] Starting Tunnel Client to expose local port 3000 via http
INFO[...] Connecting to TLS control server at 127.0.0.1:8080...
INFO[...] TLS connection established. Authenticating...
INFO[...] Authentication successful.
INFO[...] Public tunnel available at: http://<random-string>.localhost:8001
INFO[...] Forwarding to: localhost:3000
```

**Example 2: Expose a local SSH service on port 22**

```bash
./tunnel-client.exe tcp 22
```

Expected output:
```
INFO[...] Public tunnel available at: 127.0.0.1:54321
INFO[...] Forwarding to: localhost:22
```

### 3. Access the Dashboard

Open your browser and go to the configured address (e.g., `https://localhost:4040`). You will be prompted for the credentials defined in `config.server.yml` (`admin`/`sottopasso` in the example). You will see a table with all active tunnels and their traffic, which updates every 5 seconds.