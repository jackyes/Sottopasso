package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// PerformanceMetrics holds comprehensive performance metrics for the tunnel system
type PerformanceMetrics struct {
	// Connection metrics
	ConnectionsActive   atomic.Int32
	ConnectionsTotal    atomic.Uint64
	ConnectionsFailed   atomic.Uint64
	ConnectionsDuration atomic.Uint64 // Total connection duration in milliseconds

	// Traffic metrics
	BytesIn    atomic.Uint64
	BytesOut   atomic.Uint64
	PacketsIn  atomic.Uint64
	PacketsOut atomic.Uint64

	// Latency metrics (in nanoseconds)
	ReadLatency  *Histogram
	WriteLatency *Histogram
	TCPLatency   *Histogram
	UDPLatency   *Histogram
	HTTPLatency  *Histogram
	TLSLatency   *Histogram // TLS handshake latency

	// Error metrics
	ReadErrors    atomic.Uint64
	WriteErrors   atomic.Uint64
	TimeoutErrors atomic.Uint64
	TLSErrors     atomic.Uint64

	// Protocol-specific metrics
	HTTPRequests         atomic.Uint64
	TCPConnections       atomic.Uint64
	UDPConnections       atomic.Uint64
	WebSocketConnections atomic.Uint64

	// TLS Session Resumption metrics
	TLSSessionResumptions atomic.Uint64
	TLSSessionCacheHits   atomic.Uint64
	TLSSessionCacheMisses atomic.Uint64
	TLSKeyRotations       atomic.Uint64
	TLSSessionCacheSize   atomic.Int32

	// Resource utilization
	GoroutineCount atomic.Int32
	MemoryUsage    atomic.Uint64

	// Timestamps for rate calculations
	lastResetTime time.Time
	mu            sync.RWMutex
}

// Histogram tracks latency distribution for performance metrics
type Histogram struct {
	mu         sync.RWMutex
	buckets    []uint64
	bucketSize time.Duration
	count      uint64
	sum        time.Duration
}

// NewHistogram creates a new histogram with the specified bucket size and count
func NewHistogram(bucketSize time.Duration, bucketCount int) *Histogram {
	return &Histogram{
		buckets:    make([]uint64, bucketCount),
		bucketSize: bucketSize,
	}
}

// Observe records a duration in the histogram
func (h *Histogram) Observe(duration time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.count++
	h.sum += duration

	bucket := int(duration / h.bucketSize)
	if bucket >= len(h.buckets) {
		bucket = len(h.buckets) - 1
	} else if bucket < 0 {
		bucket = 0
	}
	h.buckets[bucket]++
}

// Percentile calculates the specified percentile (0.0 to 1.0) of the histogram
func (h *Histogram) Percentile(p float64) time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.count == 0 {
		return 0
	}

	target := uint64(float64(h.count) * p)
	var count uint64

	for i, bucketCount := range h.buckets {
		count += bucketCount
		if count >= target {
			return time.Duration(i+1) * h.bucketSize
		}
	}

	return time.Duration(len(h.buckets)) * h.bucketSize
}

// Count returns the total number of observations
func (h *Histogram) Count() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.count
}

// Average returns the average duration
func (h *Histogram) Average() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.count == 0 {
		return 0
	}
	return h.sum / time.Duration(h.count)
}

// GlobalMetrics holds the global performance metrics instance
var (
	globalMetrics     *PerformanceMetrics
	globalMetricsOnce sync.Once
)

// GetGlobalMetrics returns the global performance metrics instance
func GetGlobalMetrics() *PerformanceMetrics {
	globalMetricsOnce.Do(func() {
		globalMetrics = &PerformanceMetrics{
			ReadLatency:   NewHistogram(1*time.Millisecond, 1000), // Up to 1 second
			WriteLatency:  NewHistogram(1*time.Millisecond, 1000),
			TCPLatency:    NewHistogram(1*time.Millisecond, 1000),
			UDPLatency:    NewHistogram(1*time.Millisecond, 1000),
			HTTPLatency:   NewHistogram(1*time.Millisecond, 1000),
			TLSLatency:    NewHistogram(10*time.Millisecond, 100), // Up to 1 second for TLS handshake
			lastResetTime: time.Now(),
		}
	})
	return globalMetrics
}

// Reset resets all metrics to zero
func (m *PerformanceMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ConnectionsActive.Store(0)
	m.ConnectionsTotal.Store(0)
	m.ConnectionsFailed.Store(0)
	m.ConnectionsDuration.Store(0)
	m.BytesIn.Store(0)
	m.BytesOut.Store(0)
	m.PacketsIn.Store(0)
	m.PacketsOut.Store(0)
	m.ReadErrors.Store(0)
	m.WriteErrors.Store(0)
	m.TimeoutErrors.Store(0)
	m.TLSErrors.Store(0)
	m.HTTPRequests.Store(0)
	m.TCPConnections.Store(0)
	m.UDPConnections.Store(0)
	m.WebSocketConnections.Store(0)

	// Reset TLS session metrics
	m.TLSSessionResumptions.Store(0)
	m.TLSSessionCacheHits.Store(0)
	m.TLSSessionCacheMisses.Store(0)
	m.TLSKeyRotations.Store(0)
	m.TLSSessionCacheSize.Store(0)

	// Reset histograms
	m.ReadLatency = NewHistogram(1*time.Millisecond, 1000)
	m.WriteLatency = NewHistogram(1*time.Millisecond, 1000)
	m.TCPLatency = NewHistogram(1*time.Millisecond, 1000)
	m.UDPLatency = NewHistogram(1*time.Millisecond, 1000)
	m.HTTPLatency = NewHistogram(1*time.Millisecond, 1000)
	m.TLSLatency = NewHistogram(10*time.Millisecond, 100)

	m.lastResetTime = time.Now()
}

// Snapshot returns a snapshot of current metrics
func (m *PerformanceMetrics) Snapshot() *MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &MetricsSnapshot{
		ConnectionsActive:     m.ConnectionsActive.Load(),
		ConnectionsTotal:      m.ConnectionsTotal.Load(),
		ConnectionsFailed:     m.ConnectionsFailed.Load(),
		ConnectionsDuration:   m.ConnectionsDuration.Load(),
		BytesIn:               m.BytesIn.Load(),
		BytesOut:              m.BytesOut.Load(),
		PacketsIn:             m.PacketsIn.Load(),
		PacketsOut:            m.PacketsOut.Load(),
		ReadErrors:            m.ReadErrors.Load(),
		WriteErrors:           m.WriteErrors.Load(),
		TimeoutErrors:         m.TimeoutErrors.Load(),
		TLSErrors:             m.TLSErrors.Load(),
		HTTPRequests:          m.HTTPRequests.Load(),
		TCPConnections:        m.TCPConnections.Load(),
		UDPConnections:        m.UDPConnections.Load(),
		WebSocketConnections:  m.WebSocketConnections.Load(),
		GoroutineCount:        m.GoroutineCount.Load(),
		MemoryUsage:           m.MemoryUsage.Load(),
		ReadLatencyP50:        m.ReadLatency.Percentile(0.5),
		ReadLatencyP95:        m.ReadLatency.Percentile(0.95),
		ReadLatencyP99:        m.ReadLatency.Percentile(0.99),
		WriteLatencyP50:       m.WriteLatency.Percentile(0.5),
		WriteLatencyP95:       m.WriteLatency.Percentile(0.95),
		WriteLatencyP99:       m.WriteLatency.Percentile(0.99),
		TCPLatencyP50:         m.TCPLatency.Percentile(0.5),
		TCPLatencyP95:         m.TCPLatency.Percentile(0.95),
		TCPLatencyP99:         m.TCPLatency.Percentile(0.99),
		UDPLatencyP50:         m.UDPLatency.Percentile(0.5),
		UDPLatencyP95:         m.UDPLatency.Percentile(0.95),
		UDPLatencyP99:         m.UDPLatency.Percentile(0.99),
		HTTPLatencyP50:        m.HTTPLatency.Percentile(0.5),
		HTTPLatencyP95:        m.HTTPLatency.Percentile(0.95),
		HTTPLatencyP99:        m.HTTPLatency.Percentile(0.99),
		TLSLatencyP50:         m.TLSLatency.Percentile(0.5),
		TLSLatencyP95:         m.TLSLatency.Percentile(0.95),
		TLSLatencyP99:         m.TLSLatency.Percentile(0.99),
		TLSSessionResumptions: m.TLSSessionResumptions.Load(),
		TLSSessionCacheHits:   m.TLSSessionCacheHits.Load(),
		TLSSessionCacheMisses: m.TLSSessionCacheMisses.Load(),
		TLSKeyRotations:       m.TLSKeyRotations.Load(),
		TLSSessionCacheSize:   m.TLSSessionCacheSize.Load(),
		Uptime:                time.Since(m.lastResetTime),
	}
}

// MetricsSnapshot represents a snapshot of performance metrics at a point in time
type MetricsSnapshot struct {
	ConnectionsActive    int32
	ConnectionsTotal     uint64
	ConnectionsFailed    uint64
	ConnectionsDuration  uint64
	BytesIn              uint64
	BytesOut             uint64
	PacketsIn            uint64
	PacketsOut           uint64
	ReadErrors           uint64
	WriteErrors          uint64
	TimeoutErrors        uint64
	TLSErrors            uint64
	HTTPRequests         uint64
	TCPConnections       uint64
	UDPConnections       uint64
	WebSocketConnections uint64
	GoroutineCount       int32
	MemoryUsage          uint64

	// Latency percentiles
	ReadLatencyP50  time.Duration
	ReadLatencyP95  time.Duration
	ReadLatencyP99  time.Duration
	WriteLatencyP50 time.Duration
	WriteLatencyP95 time.Duration
	WriteLatencyP99 time.Duration
	TCPLatencyP50   time.Duration
	TCPLatencyP95   time.Duration
	TCPLatencyP99   time.Duration
	UDPLatencyP50   time.Duration
	UDPLatencyP95   time.Duration
	UDPLatencyP99   time.Duration
	HTTPLatencyP50  time.Duration
	HTTPLatencyP95  time.Duration
	HTTPLatencyP99  time.Duration
	TLSLatencyP50   time.Duration
	TLSLatencyP95   time.Duration
	TLSLatencyP99   time.Duration

	// TLS Session Resumption metrics
	TLSSessionResumptions uint64
	TLSSessionCacheHits   uint64
	TLSSessionCacheMisses uint64
	TLSKeyRotations       uint64
	TLSSessionCacheSize   int32

	Uptime time.Duration
}

// ErrorRate returns the overall error rate as a percentage
func (s *MetricsSnapshot) ErrorRate() float64 {
	totalOps := s.ReadErrors + s.WriteErrors + s.TimeoutErrors + s.TLSErrors
	if totalOps == 0 {
		return 0
	}
	return float64(totalOps) / float64(s.ConnectionsTotal) * 100
}

// ThroughputIn returns the input throughput in bytes per second
func (s *MetricsSnapshot) ThroughputIn() float64 {
	return float64(s.BytesIn) / s.Uptime.Seconds()
}

// ThroughputOut returns the output throughput in bytes per second
func (s *MetricsSnapshot) ThroughputOut() float64 {
	return float64(s.BytesOut) / s.Uptime.Seconds()
}

// AverageConnectionDuration returns the average connection duration in milliseconds
func (s *MetricsSnapshot) AverageConnectionDuration() float64 {
	if s.ConnectionsTotal == 0 {
		return 0
	}
	return float64(s.ConnectionsDuration) / float64(s.ConnectionsTotal)
}
