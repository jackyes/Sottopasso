package main

import (
	"Sottopasso/pkg/server"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

// ConfigYAML reflects the structure of the config.server.yml file
type ConfigYAML struct {
	ControlAddr            string   `yaml:"control_addr"`
	HTTPAddr               string   `yaml:"http_addr"`
	HTTPUseTLS             bool     `yaml:"http_use_tls"`
	DashboardAddr          string   `yaml:"dashboard_addr"`
	Domain                 string   `yaml:"domain"`
	ValidTokens            []string `yaml:"valid_tokens"`
	TLSCertFile            string   `yaml:"tls_cert_file"`
	TLSKeyFile             string   `yaml:"tls_key_file"`
	DashboardUsername      string   `yaml:"dashboard_username"`
	DashboardPassword      string   `yaml:"dashboard_password"`
	DashboardTLSCertFile   string   `yaml:"dashboard_tls_cert_file"`
	DashboardTLSKeyFile    string   `yaml:"dashboard_tls_key_file"`
	KeepaliveInterval      string   `yaml:"keepalive_interval"`
	ConnectionWriteTimeout string   `yaml:"connection_write_timeout"`
}

func main() {
	configPath := flag.String("config", "config.server.yml", "Path to the server YAML configuration file")
	keepaliveInterval := flag.String("keepalive-interval", "", "Keepalive interval (e.g., 30s, 1m). Overrides config.")
	connectionWriteTimeout := flag.String("connection-write-timeout", "", "Connection write timeout (e.g., 10s, 1m). Overrides config.")
	flag.Parse()

	yamlFile, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Error reading configuration file %s: %v", *configPath, err)
	}

	var configYAML ConfigYAML
	// Set default values before unmarshaling
	configYAML.KeepaliveInterval = "30s"
	configYAML.ConnectionWriteTimeout = "10s"
	if err := yaml.Unmarshal(yamlFile, &configYAML); err != nil {
		log.Fatalf("Error parsing YAML file: %v", err)
	}

	// Override with flags if provided
	if *keepaliveInterval != "" {
		configYAML.KeepaliveInterval = *keepaliveInterval
	}
	if *connectionWriteTimeout != "" {
		configYAML.ConnectionWriteTimeout = *connectionWriteTimeout
	}

	keepalive, err := time.ParseDuration(configYAML.KeepaliveInterval)
	if err != nil {
		log.Fatalf("Invalid keepalive_interval format: %v", err)
	}

	writeTimeout, err := time.ParseDuration(configYAML.ConnectionWriteTimeout)
	if err != nil {
		log.Fatalf("Invalid connection_write_timeout format: %v", err)
	}

	config := &server.Config{
		ControlAddr:            configYAML.ControlAddr,
		HTTPAddr:               configYAML.HTTPAddr,
		HTTPUseTLS:             configYAML.HTTPUseTLS,
		DashboardAddr:          configYAML.DashboardAddr,
		Domain:                 configYAML.Domain,
		ValidTokens:            configYAML.ValidTokens,
		TLSCertFile:            configYAML.TLSCertFile,
		TLSKeyFile:             configYAML.TLSKeyFile,
		DashboardUsername:      configYAML.DashboardUsername,
		DashboardPassword:      configYAML.DashboardPassword,
		DashboardTLSCertFile:   configYAML.DashboardTLSCertFile,
		DashboardTLSKeyFile:    configYAML.DashboardTLSKeyFile,
		KeepaliveInterval:      keepalive,
		ConnectionWriteTimeout: writeTimeout,
	}

	srv := server.New(config)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Println("Starting Tunnel Server...")
		if err := srv.Start(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	<-quit
	log.Println("Received shutdown signal, starting graceful shutdown...")

	srv.Shutdown()

	time.Sleep(1 * time.Second)

	log.Println("Server stopped correctly.")
}
