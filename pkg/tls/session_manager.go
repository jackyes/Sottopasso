package tls

import (
	"crypto/rand"
	"crypto/tls"
	"sync"
	"sync/atomic"
	"time"

	"Sottopasso/pkg/metrics"
)

// SessionManager manages TLS session tickets and caching for improved performance
type SessionManager struct {
	mu sync.RWMutex

	// Session ticket keys (current and previous for rotation)
	currentKey [32]byte
	prevKey    [32]byte

	// Session cache for server-side session resumption
	sessionCache    map[string]*tls.ClientSessionState
	sessionCacheTTL time.Duration
	maxCacheSize    int

	// Metrics
	sessionResumptions atomic.Uint64
	sessionCacheHits   atomic.Uint64
	sessionCacheMisses atomic.Uint64
	keyRotations       atomic.Uint64
	handshakeErrors    atomic.Uint64

	// Configuration
	keyRotationInterval time.Duration
	cleanupInterval     time.Duration
	stopChan            chan struct{}
	running             bool
}

// SessionManagerConfig contains configuration for the TLS session manager
type SessionManagerConfig struct {
	// SessionCacheTTL defines how long sessions remain in cache
	SessionCacheTTL time.Duration `json:"session_cache_ttl"`

	// MaxCacheSize defines the maximum number of sessions to cache
	MaxCacheSize int `json:"max_cache_size"`

	// KeyRotationInterval defines how often to rotate session ticket keys
	KeyRotationInterval time.Duration `json:"key_rotation_interval"`

	// CleanupInterval defines how often to clean expired sessions
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// DefaultSessionManagerConfig returns the default configuration
func DefaultSessionManagerConfig() SessionManagerConfig {
	return SessionManagerConfig{
		SessionCacheTTL:     24 * time.Hour, // 24 hours
		MaxCacheSize:        1000,           // 1000 sessions
		KeyRotationInterval: 24 * time.Hour, // Rotate keys daily
		CleanupInterval:     1 * time.Hour,  // Cleanup hourly
	}
}

// NewSessionManager creates a new TLS session manager
func NewSessionManager(config SessionManagerConfig) *SessionManager {
	sm := &SessionManager{
		sessionCache:        make(map[string]*tls.ClientSessionState),
		sessionCacheTTL:     config.SessionCacheTTL,
		maxCacheSize:        config.MaxCacheSize,
		keyRotationInterval: config.KeyRotationInterval,
		cleanupInterval:     config.CleanupInterval,
		stopChan:            make(chan struct{}),
	}

	// Generate initial session ticket key
	if err := sm.generateSessionTicketKey(); err != nil {
		panic("failed to generate initial session ticket key: " + err.Error())
	}

	return sm
}

// Start begins the key rotation and cleanup background tasks
func (sm *SessionManager) Start() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.running {
		return
	}

	sm.running = true
	go sm.keyRotationLoop()
	go sm.cleanupLoop()
}

// Stop halts the background tasks
func (sm *SessionManager) Stop() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.running {
		return
	}

	sm.running = false
	close(sm.stopChan)
}

// GetSessionTicketKeys returns the current and previous session ticket keys
func (sm *SessionManager) GetSessionTicketKeys() [][32]byte {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	keys := make([][32]byte, 0, 2)
	if sm.currentKey != [32]byte{} {
		keys = append(keys, sm.currentKey)
	}
	if sm.prevKey != [32]byte{} {
		keys = append(keys, sm.prevKey)
	}
	return keys
}

// GetServerTLSConfig returns a TLS config for servers with session resumption enabled
func (sm *SessionManager) GetServerTLSConfig(baseConfig *tls.Config) *tls.Config {
	if baseConfig == nil {
		baseConfig = &tls.Config{}
	}

	// Create a copy of the base config
	config := baseConfig.Clone()

	// Enable session ticket support
	config.SessionTicketsDisabled = false

	// Set session ticket keys
	keys := sm.GetSessionTicketKeys()
	if len(keys) > 0 {
		config.SetSessionTicketKeys(keys)
	}

	// Set up session cache for server-side session resumption
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		clientConfig := config.Clone()

		// Enable session cache for this client
		clientConfig.ClientSessionCache = &serverSessionCache{sm: sm}

		return clientConfig, nil
	}

	// Optimize cipher suites for performance
	if config.CipherSuites == nil {
		config.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		}
	}

	// Set modern TLS version
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}

	// Prefer server cipher suites for better security
	config.PreferServerCipherSuites = true

	// Optimize curve preferences
	if config.CurvePreferences == nil {
		config.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}
	}

	return config
}

// GetClientTLSConfig returns a TLS config for clients with session resumption
func (sm *SessionManager) GetClientTLSConfig(baseConfig *tls.Config) *tls.Config {
	if baseConfig == nil {
		baseConfig = &tls.Config{}
	}

	config := baseConfig.Clone()

	// Enable session caching for clients
	config.ClientSessionCache = tls.NewLRUClientSessionCache(sm.maxCacheSize)

	// Use modern TLS settings
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}

	return config
}

// serverSessionCache implements tls.ClientSessionCache for server-side session resumption
type serverSessionCache struct {
	sm *SessionManager
}

func (ssc *serverSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	ssc.sm.mu.RLock()
	defer ssc.sm.mu.RUnlock()

	session, exists := ssc.sm.sessionCache[sessionKey]
	if exists {
		ssc.sm.sessionCacheHits.Add(1)
		// Update global metrics
		globalMetrics := metrics.GetGlobalMetrics()
		globalMetrics.TLSSessionCacheHits.Add(1)
	} else {
		ssc.sm.sessionCacheMisses.Add(1)
		// Update global metrics
		globalMetrics := metrics.GetGlobalMetrics()
		globalMetrics.TLSSessionCacheMisses.Add(1)
	}
	return session, exists
}

func (ssc *serverSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	ssc.sm.mu.Lock()
	defer ssc.sm.mu.Unlock()

	// If cache is full, remove oldest entry (simple eviction)
	if len(ssc.sm.sessionCache) >= ssc.sm.maxCacheSize {
		for key := range ssc.sm.sessionCache {
			delete(ssc.sm.sessionCache, key)
			break
		}
	}

	ssc.sm.sessionCache[sessionKey] = cs
	ssc.sm.sessionResumptions.Add(1)

	// Update global metrics
	globalMetrics := metrics.GetGlobalMetrics()
	globalMetrics.TLSSessionResumptions.Add(1)
	globalMetrics.TLSSessionCacheSize.Store(int32(len(ssc.sm.sessionCache)))
	globalMetrics.TLSErrors.Add(0) // Ensure TLS metrics are initialized
}

// SessionMetrics contains performance metrics for TLS session management
type SessionMetrics struct {
	SessionResumptions uint64 `json:"session_resumptions"`
	SessionCacheHits   uint64 `json:"session_cache_hits"`
	SessionCacheMisses uint64 `json:"session_cache_misses"`
	KeyRotations       uint64 `json:"key_rotations"`
	HandshakeErrors    uint64 `json:"handshake_errors"`
	CacheSize          int    `json:"cache_size"`
	CacheUtilization   int    `json:"cache_utilization"` // Percentage
}

// GetMetrics returns current session manager metrics
func (sm *SessionManager) GetMetrics() SessionMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	cacheSize := len(sm.sessionCache)
	cacheUtilization := 0
	if sm.maxCacheSize > 0 {
		cacheUtilization = (cacheSize * 100) / sm.maxCacheSize
	}

	return SessionMetrics{
		SessionResumptions: sm.sessionResumptions.Load(),
		SessionCacheHits:   sm.sessionCacheHits.Load(),
		SessionCacheMisses: sm.sessionCacheMisses.Load(),
		KeyRotations:       sm.keyRotations.Load(),
		HandshakeErrors:    sm.handshakeErrors.Load(),
		CacheSize:          cacheSize,
		CacheUtilization:   cacheUtilization,
	}
}

// generateSessionTicketKey generates a new session ticket key
func (sm *SessionManager) generateSessionTicketKey() error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Rotate keys: current becomes previous, new becomes current
	sm.prevKey = sm.currentKey
	sm.currentKey = key
	sm.keyRotations.Add(1)

	// Update global metrics
	globalMetrics := metrics.GetGlobalMetrics()
	globalMetrics.TLSKeyRotations.Add(1)

	return nil
}

// keyRotationLoop periodically rotates session ticket keys
func (sm *SessionManager) keyRotationLoop() {
	ticker := time.NewTicker(sm.keyRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := sm.generateSessionTicketKey(); err != nil {
				sm.handshakeErrors.Add(1)
				// Log error but continue
			}
		case <-sm.stopChan:
			return
		}
	}
}

// cleanupLoop periodically removes expired sessions from cache
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(sm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.cleanupExpiredSessions()
		case <-sm.stopChan:
			return
		}
	}
}

// cleanupExpiredSessions removes expired sessions from the cache
func (sm *SessionManager) cleanupExpiredSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Note: In a production system, we would track session creation time
	// and remove sessions older than sessionCacheTTL. For simplicity,
	// we're using a simple LRU eviction strategy when the cache is full.
	// In a more advanced implementation, we would track TTL per session.

	// For now, we just ensure the cache doesn't exceed max size
	if len(sm.sessionCache) > sm.maxCacheSize {
		// Remove random entries until we're under the limit
		toRemove := len(sm.sessionCache) - sm.maxCacheSize
		for key := range sm.sessionCache {
			delete(sm.sessionCache, key)
			toRemove--
			if toRemove <= 0 {
				break
			}
		}
	}

	// Update global metrics with current cache size
	globalMetrics := metrics.GetGlobalMetrics()
	globalMetrics.TLSSessionCacheSize.Store(int32(len(sm.sessionCache)))
}

// Global session manager instance
var (
	globalSessionManager     *SessionManager
	globalSessionManagerOnce sync.Once
)

// GetGlobalSessionManager returns the global TLS session manager instance
func GetGlobalSessionManager() *SessionManager {
	globalSessionManagerOnce.Do(func() {
		globalSessionManager = NewSessionManager(DefaultSessionManagerConfig())
		globalSessionManager.Start()
	})
	return globalSessionManager
}
