package main

import (
	"Sottopasso/pkg/pool"
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

	// Buffer pool configuration
	BufferPool BufferPoolConfig `yaml:"buffer_pool"`

	// TLS configuration
	TLSConfig TLSConfigYAML `yaml:"tls_config"`

	// Metrics configuration
	MetricsConfig MetricsConfigYAML `yaml:"metrics_config"`
}

// TLSConfigYAML holds TLS configuration from YAML
type TLSConfigYAML struct {
	EnableSessionResumption bool   `yaml:"enable_session_resumption"`
	SessionCacheTTL         string `yaml:"session_cache_ttl"`
	MaxCacheSize            int    `yaml:"max_cache_size"`
	KeyRotationInterval     string `yaml:"key_rotation_interval"`
}

// MetricsConfigYAML holds metrics configuration from YAML
type MetricsConfigYAML struct {
	Enabled                   bool   `yaml:"enabled"`
	CollectionInterval        string `yaml:"collection_interval"`
	RetentionPeriod           string `yaml:"retention_period"`
	EnableDetailedMetrics     bool   `yaml:"enable_detailed_metrics"`
	EnableConnectionPoolStats bool   `yaml:"enable_connection_pool_stats"`
	EnableBufferPoolStats     bool   `yaml:"enable_buffer_pool_stats"`
	EnableSystemMetrics       bool   `yaml:"enable_system_metrics"`
	EnableLatencyHistograms   bool   `yaml:"enable_latency_histograms"`
	MaxHistogramBuckets       int    `yaml:"max_histogram_buckets"`
	MetricsEndpoint           string `yaml:"metrics_endpoint"`
}

// BufferPoolConfig holds configuration for the buffer pool
type BufferPoolConfig struct {
	SmallBufferSize  int `yaml:"small_buffer_size"`
	MediumBufferSize int `yaml:"medium_buffer_size"`
	LargeBufferSize  int `yaml:"large_buffer_size"`
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
	configYAML.BufferPool = BufferPoolConfig{
		SmallBufferSize:  4096,  // 4KB
		MediumBufferSize: 16384, // 16KB
		LargeBufferSize:  65536, // 64KB
	}
	configYAML.TLSConfig = TLSConfigYAML{
		EnableSessionResumption: true,
		SessionCacheTTL:         "24h",
		MaxCacheSize:            1000,
		KeyRotationInterval:     "24h",
	}
	configYAML.MetricsConfig = MetricsConfigYAML{
		Enabled:                   true,
		CollectionInterval:        "30s",
		RetentionPeriod:           "24h",
		EnableDetailedMetrics:     true,
		EnableConnectionPoolStats: true,
		EnableBufferPoolStats:     true,
		EnableSystemMetrics:       true,
		EnableLatencyHistograms:   true,
		MaxHistogramBuckets:       50,
		MetricsEndpoint:           "/metrics",
	}
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

	// Parse TLS configuration durations
	sessionCacheTTL, err := time.ParseDuration(configYAML.TLSConfig.SessionCacheTTL)
	if err != nil {
		log.Fatalf("Invalid session_cache_ttl format: %v", err)
	}
	keyRotationInterval, err := time.ParseDuration(configYAML.TLSConfig.KeyRotationInterval)
	if err != nil {
		log.Fatalf("Invalid key_rotation_interval format: %v", err)
	}

	// Parse metrics configuration durations
	collectionInterval, err := time.ParseDuration(configYAML.MetricsConfig.CollectionInterval)
	if err != nil {
		log.Fatalf("Invalid collection_interval format: %v", err)
	}
	retentionPeriod, err := time.ParseDuration(configYAML.MetricsConfig.RetentionPeriod)
	if err != nil {
		log.Fatalf("Invalid retention_period format: %v", err)
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
		TLSConfig: server.TLSConfig{
			EnableSessionResumption: configYAML.TLSConfig.EnableSessionResumption,
			SessionCacheTTL:         sessionCacheTTL,
			MaxCacheSize:            configYAML.TLSConfig.MaxCacheSize,
			KeyRotationInterval:     keyRotationInterval,
		},
		MetricsConfig: server.MetricsConfig{
			Enabled:                   configYAML.MetricsConfig.Enabled,
			CollectionInterval:        collectionInterval,
			RetentionPeriod:           retentionPeriod,
			EnableDetailedMetrics:     configYAML.MetricsConfig.EnableDetailedMetrics,
			EnableConnectionPoolStats: configYAML.MetricsConfig.EnableConnectionPoolStats,
			EnableBufferPoolStats:     configYAML.MetricsConfig.EnableBufferPoolStats,
			EnableSystemMetrics:       configYAML.MetricsConfig.EnableSystemMetrics,
			EnableLatencyHistograms:   configYAML.MetricsConfig.EnableLatencyHistograms,
			MaxHistogramBuckets:       configYAML.MetricsConfig.MaxHistogramBuckets,
			MetricsEndpoint:           configYAML.MetricsConfig.MetricsEndpoint,
		},
	}

	// Initialize global buffer pool with configuration
	bufferPoolConfig := pool.BufferPoolConfig{
		SmallBufferSize:  configYAML.BufferPool.SmallBufferSize,
		MediumBufferSize: configYAML.BufferPool.MediumBufferSize,
		LargeBufferSize:  configYAML.BufferPool.LargeBufferSize,
	}
	pool.InitGlobalBufferPool(bufferPoolConfig)

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
