package main

import (
	"Sottopasso/pkg/client"
	"flag"
	"io/ioutil"
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
		// If protocol and port are provided as positional arguments and no flags were set, use them
		*tunnelType = args[0]
		port, err := strconv.Atoi(args[1])
		if err != nil {
			log.Fatalf("Invalid port number: %v", err)
		}
		*localPort = port
	} else if len(args) > 0 && (*tunnelType != "" || *localPort != 0) {
		log.Printf("Warning: Ignoring positional arguments because flags were provided")
	}

	// Load configuration from YAML
	configYAML := ConfigYAML{
		ServerAddr:             "127.0.0.1:8080",
		InsecureSkipVerify:     true,
		TunnelProtocol:         "http", // Default value
		LocalPort:              8080,   // Default value
		KeepaliveInterval:      "30s",  // Default value
		ConnectionWriteTimeout: "10s",  // Default value
	}
	yamlFile, err := ioutil.ReadFile(*configPath)
	if err == nil {
		yaml.Unmarshal(yamlFile, &configYAML)
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

	// Parse connection write timeout
	writeTimeout, err := time.ParseDuration(configYAML.ConnectionWriteTimeout)
	if err != nil {
		log.Fatalf("Invalid connection_write_timeout format: %v", err)
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
	}

	if config.AuthToken == "" {
		log.Fatal("Authentication token is required.")
	}

	cli := client.New(config)

	// Channel to listen for system signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start the client in a goroutine
	go func() {
		log.Printf("Starting Tunnel Client to expose local port %d via %s", config.LocalPort, config.TunnelType)
		if err := cli.Start(); err != nil {
			log.Printf("Client error: %v", err)
		}
		// If Start() terminates (e.g., due to disconnection), send a signal to terminate main
		quit <- syscall.SIGTERM
	}()

	// Wait for a signal (or for the client to terminate on its own)
	<-quit
	log.Println("Closing client...")

	// Here we could call a cli.Shutdown() method if it were necessary
	// to close other resources cleanly. For now, exiting is sufficient.
	log.Println("Client stopped.")
}
