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
control_addr: ":7780"

# Address for public HTTP/HTTPS traffic
http_addr: ":8001"

# Enable TLS for public traffic (HTTPS)
http_use_tls: true

# Base domain used to generate HTTP tunnel URLs
domain: "test.xxxx.com:8001"

# Paths for the control channel TLS certificate and key files.
tls_cert_file: "/etc/letsencrypt/live/test.xxxx.com/fullchain.pem"
tls_key_file: "/etc/letsencrypt/live/test.xxxx.com/privkey.pem"

# List of valid authentication tokens for clients
valid_tokens:
  - "secret-token-1"
  - "secret-token-2"

# Keepalive interval for the connection (e.g., 30s, 1m, 1h)
keepalive_interval: "30s"

# Write timeout for the connection (e.g., 10s, 1m)
connection_write_timeout: "500s"

# --- Connection Pool Configuration ---
# Connection pooling settings for improved performance
connection_pool:
  max_size: 100           # Maximum number of streams in the pool
  idle_timeout: "30s"     # How long an idle stream stays in the pool
  max_idle: 20            # Maximum number of idle streams

# --- Buffer Pool Configuration ---
# Buffer pooling settings for memory optimization
buffer_pool:
  small_buffer_size: 4096     # 4KB buffers for small operations
  medium_buffer_size: 16384   # 16KB buffers for medium operations
  large_buffer_size: 65536    # 64KB buffers for UDP and large transfers


# --- Status Dashboard Configuration ---

# Address for the status dashboard (e.g., ":4040")
dashboard_addr: ":4040"

# (Optional) Credentials to protect dashboard access with Basic Auth
dashboard_username: "admin"
dashboard_password: "sottopasso"

# (Optional) Paths for dashboard TLS files. If omitted, the dashboard will be HTTP.
# If not found, they will be automatically generated.
dashboard_tls_cert_file: "/etc/letsencrypt/live/test.xxxx.com/fullchain.pem"
dashboard_tls_key_file: "/etc/letsencrypt/live/test.xxxx.com/privkey.pem"

# --- TLS Session Resumption Configuration ---
# Settings for TLS performance optimization through session resumption
tls_config:
  enable_session_resumption: true    # Enable TLS session resumption for improved performance
  session_cache_ttl: "24h"           # How long sessions remain in cache (e.g., 1h, 24h)
  max_cache_size: 1000               # Maximum number of sessions to cache
  key_rotation_interval: "24h"       # How often to rotate session ticket keys

# --- Metrics Configuration ---
# Settings for performance metrics collection
metrics_config:
  enabled: true                      # Enable metrics collection
  collection_interval: "30s"         # How often to collect metrics
  retention_period: "24h"            # How long to keep metrics data
  enable_detailed_metrics: true      # Enable detailed per-tunnel metrics
  enable_connection_pool_stats: true # Enable connection pool statistics
  enable_buffer_pool_stats: true     # Enable buffer pool statistics
  enable_system_metrics: true        # Enable system-level metrics
  enable_latency_histograms: true    # Enable latency distribution tracking
  max_histogram_buckets: 50          # Maximum number of histogram buckets
  metrics_endpoint: "/metrics"       # Endpoint for metrics exposure
```

### Client (`config.client.yml`)

Create this file in the same directory as the `tunnel-client.exe` executable.

```yaml
# Configuration file for the Tunnel Client

# Address of the server to connect to (TLS connection)
server_addr: "xxxx.com:7780"

# Authentication token to use for the connection
auth_token: "secret-token-1"

# If true, the client will not verify the validity of the server's TLS certificate.
# Useful for development with self-signed certificates.
insecure_skip_verify: false

# Protocol to forward (http or tcp)
tunnel_protocol: "http"

# Local port to expose
local_port: 8080

# Requested subdomain (optional, only for http tunnels)
subdomain: "test"

# Keepalive interval for the connection (e.g., 30s, 1m, 1h)
keepalive_interval: "30s"

# Write timeout for the connection (e.g., 10s, 1m)
connection_write_timeout: "500s"

# --- Connection Pool Configuration ---
# Connection pooling settings for improved performance
connection_pool:
  max_size: 100           # Maximum number of streams in the pool
  idle_timeout: "30s"     # How long an idle stream stays in the pool
  max_idle: 20            # Maximum number of idle streams

# --- Buffer Pool Configuration ---
# Buffer pooling settings for memory optimization
buffer_pool:
  small_buffer_size: 4096     # 4KB buffers for small operations
  medium_buffer_size: 16384   # 16KB buffers for medium operations
  large_buffer_size: 65536    # 64KB buffers for UDP and large transfers

# --- TLS Session Resumption Configuration ---
# Settings for TLS performance optimization through session resumption
tls_config:
  enable_session_resumption: true    # Enable TLS session resumption for improved performance
```

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
