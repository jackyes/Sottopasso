package main

import (
	"Sottopasso/pkg/client"
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

// ConfigYAML reflects the structure of the config.client.yml file
type ConfigYAML struct {
	ServerAddr             string `yaml:"server_addr"`
	AuthToken              string `yaml:"auth_token"`
	InsecureSkipVerify     bool   `yaml:"insecure_skip_verify"`
	TunnelProtocol         string `yaml:"tunnel_protocol"`
	LocalPort              int    `yaml:"local_port"`
	Subdomain              string `yaml:"subdomain"`
	KeepaliveInterval      string `yaml:"keepalive_interval"`
	ConnectionWriteTimeout string `yaml:"connection_write_timeout"`
	MaxConcurrentStreams   int    `yaml:"max_concurrent_streams"`
	DialTimeout            string `yaml:"dial_timeout"`
	ConnectTimeout         string `yaml:"connect_timeout"`
	ReconnectMinBackoff    string `yaml:"reconnect_min_backoff"`
	ReconnectMaxBackoff    string `yaml:"reconnect_max_backoff"`
}

func main() {
	// Flag definitions
	configPath := flag.String("config", "config.client.yml", "Path to the client YAML configuration file")
	serverAddr := flag.String("server", "", "Tunnel server address (overrides config)")
	authToken := flag.String("token", "", "Authentication token (overrides config)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (overrides config)")
	tunnelType := flag.String("proto", "", "Protocol to forward (http or tcp, overrides config)")
	localPort := flag.Int("port", 0, "Local port to expose (overrides config)")
	subdomain := flag.String("subdomain", "", "Requested subdomain (overrides config)")
	keepaliveInterval := flag.String("keepalive-interval", "", "Keepalive interval (e.g., 30s, 1m). Overrides config.")
	connectionWriteTimeout := flag.String("connection-write-timeout", "", "Connection write timeout (e.g., 10s, 1m). Overrides config.")
	connectTimeout := flag.String("connect-timeout", "", "Timeout dialing the control server (e.g., 10s). Overrides config.")
	reconnectMinBackoff := flag.String("reconnect-min-backoff", "", "First reconnect delay (e.g., 1s). Overrides config.")
	reconnectMaxBackoff := flag.String("reconnect-max-backoff", "", "Reconnect delay ceiling (e.g., 60s). Overrides config.")
	flag.Parse()

	// Handle positional arguments: tunnel-client [protocol] [port]
	// Only process positional arguments if no tunnel-related flags were provided
	args := flag.Args()
	if len(args) == 1 {
		// Single argument could be "help" or other command
		if args[0] == "help" {
			flag.Usage()
			os.Exit(0)
		}
		// If it's not help and we're missing tunnel config, show error
		if *tunnelType == "" || *localPort == 0 {
			log.Fatal("Both protocol and port must be provided as positional arguments, or use flags. Use --help for usage.")
		}
	} else if len(args) >= 2 && *tunnelType == "" && *localPort == 0 {
		// Reject trailing arguments instead of dropping them: the flag package stops
		// parsing at the first positional argument, so flags placed after
		// "[protocol] [port]" would otherwise be silently ignored.
		if len(args) > 2 {
			log.Fatalf("Unexpected arguments after [protocol] [port]: %v. Flags must come before positional arguments.", args[2:])
		}
		// If protocol and port are provided as positional arguments and no flags were set, use them
		*tunnelType = args[0]
		port, err := strconv.Atoi(args[1])
		if err != nil {
			log.Fatalf("Invalid port number: %v", err)
		}
		*localPort = port
	} else if len(args) > 0 && (*tunnelType != "" || *localPort != 0) {
		log.Fatal("Conflicting arguments: provide the tunnel as flags OR as positional [protocol] [port], not both. Use --help for usage.")
	}

	// Load configuration from YAML
	configYAML := ConfigYAML{
		ServerAddr:             "127.0.0.1:8080",
		InsecureSkipVerify:     true,
		TunnelProtocol:         "http", // Default value
		LocalPort:              8080,   // Default value
		KeepaliveInterval:      "30s",  // Default value
		ConnectionWriteTimeout: "10s",  // Default value
		MaxConcurrentStreams:   256,    // Default value
		DialTimeout:            "10s",  // Default value
		ConnectTimeout:         "10s",  // Default value
		ReconnectMinBackoff:    "1s",   // Default value
		ReconnectMaxBackoff:    "60s",  // Default value
	}
	yamlFile, err := os.ReadFile(*configPath)
	if err == nil {
		// A malformed config must not be silently ignored: partial application would
		// leave fields (e.g. insecure_skip_verify) at insecure built-in defaults.
		if err := yaml.Unmarshal(yamlFile, &configYAML); err != nil {
			log.Fatalf("Error parsing YAML file %s: %v", *configPath, err)
		}
	}

	// Override configuration with flags if provided
	if *serverAddr != "" {
		configYAML.ServerAddr = *serverAddr
	}
	if *authToken != "" {
		configYAML.AuthToken = *authToken
	}
	if *tunnelType != "" {
		configYAML.TunnelProtocol = *tunnelType
	}
	if *localPort != 0 {
		configYAML.LocalPort = *localPort
	}
	if *subdomain != "" {
		configYAML.Subdomain = *subdomain
	}
	if *keepaliveInterval != "" {
		configYAML.KeepaliveInterval = *keepaliveInterval
	}
	if *connectionWriteTimeout != "" {
		configYAML.ConnectionWriteTimeout = *connectionWriteTimeout
	}
	if *connectTimeout != "" {
		configYAML.ConnectTimeout = *connectTimeout
	}
	if *reconnectMinBackoff != "" {
		configYAML.ReconnectMinBackoff = *reconnectMinBackoff
	}
	if *reconnectMaxBackoff != "" {
		configYAML.ReconnectMaxBackoff = *reconnectMaxBackoff
	}

	// Special handling for the boolean 'insecure' flag
	userSetInsecure := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "insecure" {
			userSetInsecure = true
		}
	})
	if userSetInsecure {
		configYAML.InsecureSkipVerify = *insecure
	}

	// Parse keepalive interval
	keepalive, err := time.ParseDuration(configYAML.KeepaliveInterval)
	if err != nil {
		log.Fatalf("Invalid keepalive_interval format: %v", err)
	}
	// yamux rejects a non-positive keepalive at session creation, which would
	// surface only after a successful authentication — catch it here instead.
	if keepalive <= 0 {
		log.Fatalf("keepalive_interval must be positive, got %q", configYAML.KeepaliveInterval)
	}

	// Parse connection write timeout
	writeTimeout, err := time.ParseDuration(configYAML.ConnectionWriteTimeout)
	if err != nil {
		log.Fatalf("Invalid connection_write_timeout format: %v", err)
	}
	if writeTimeout <= 0 {
		log.Fatalf("connection_write_timeout must be positive, got %q", configYAML.ConnectionWriteTimeout)
	}

	dialTimeout, err := time.ParseDuration(configYAML.DialTimeout)
	if err != nil {
		log.Fatalf("Invalid dial_timeout format: %v", err)
	}

	connTimeout, err := time.ParseDuration(configYAML.ConnectTimeout)
	if err != nil {
		log.Fatalf("Invalid connect_timeout format: %v", err)
	}
	if connTimeout < 0 {
		log.Fatalf("connect_timeout must not be negative, got %q", configYAML.ConnectTimeout)
	}

	minBackoff, err := time.ParseDuration(configYAML.ReconnectMinBackoff)
	if err != nil {
		log.Fatalf("Invalid reconnect_min_backoff format: %v", err)
	}
	if minBackoff <= 0 {
		log.Fatalf("reconnect_min_backoff must be positive, got %q", configYAML.ReconnectMinBackoff)
	}

	maxBackoff, err := time.ParseDuration(configYAML.ReconnectMaxBackoff)
	if err != nil {
		log.Fatalf("Invalid reconnect_max_backoff format: %v", err)
	}
	if maxBackoff < minBackoff {
		log.Fatalf("reconnect_max_backoff (%q) must be greater than or equal to reconnect_min_backoff (%q).",
			configYAML.ReconnectMaxBackoff, configYAML.ReconnectMinBackoff)
	}

	// Create final configuration for the client
	config := &client.Config{
		ServerAddr:             configYAML.ServerAddr,
		AuthToken:              configYAML.AuthToken,
		TunnelType:             configYAML.TunnelProtocol,
		LocalPort:              configYAML.LocalPort,
		Subdomain:              configYAML.Subdomain,
		InsecureSkipVerify:     configYAML.InsecureSkipVerify,
		KeepaliveInterval:      keepalive,
		ConnectionWriteTimeout: writeTimeout,
		MaxConcurrentStreams:   configYAML.MaxConcurrentStreams,
		DialTimeout:            dialTimeout,
		ConnectTimeout:         connTimeout,
		ReconnectMinBackoff:    minBackoff,
		ReconnectMaxBackoff:    maxBackoff,
	}

	if config.TunnelType != "http" && config.TunnelType != "tcp" {
		log.Fatalf("Invalid tunnel protocol %q: must be \"http\" or \"tcp\".", config.TunnelType)
	}

	if config.LocalPort < 1 || config.LocalPort > 65535 {
		log.Fatalf("Invalid local port %d: must be in the range 1-65535.", config.LocalPort)
	}

	if config.AuthToken == "" {
		log.Fatal("Authentication token is required.")
	}

	cli := client.New(config)

	// Start reconnects on its own until this context is cancelled, so a signal
	// is the only thing that ends a healthy client.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("Starting Tunnel Client to expose local port %d via %s", config.LocalPort, config.TunnelType)
	err = cli.Start(ctx)
	stop()

	if err != nil {
		log.Printf("Client error: %v", err)
		log.Println("Client stopped.")
		os.Exit(1)
	}

	log.Println("Closing client...")
	log.Println("Client stopped.")
}
