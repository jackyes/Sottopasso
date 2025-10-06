package metrics

import (
	"Sottopasso/pkg/pool"
	"runtime"
	"sync"
	"time"
)

// MetricsCollector periodically collects and aggregates metrics from various sources
type MetricsCollector struct {
	mu                 sync.RWMutex
	connectionPools    []*pool.ConnectionPool
	bufferPool         *pool.BufferPool
	collectionInterval time.Duration
	stopChan           chan struct{}
	running            bool
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(collectionInterval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		connectionPools:    make([]*pool.ConnectionPool, 0),
		bufferPool:         pool.GetGlobalBufferPool(),
		collectionInterval: collectionInterval,
		stopChan:           make(chan struct{}),
	}
}

// RegisterConnectionPool adds a connection pool to be monitored
func (mc *MetricsCollector) RegisterConnectionPool(cp *pool.ConnectionPool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.connectionPools = append(mc.connectionPools, cp)
}

// Start begins the periodic metrics collection
func (mc *MetricsCollector) Start() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.running {
		return
	}

	mc.running = true
	go mc.collectionLoop()
}

// Stop halts the metrics collection
func (mc *MetricsCollector) Stop() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if !mc.running {
		return
	}

	mc.running = false
	close(mc.stopChan)
}

// collectionLoop runs the periodic metrics collection
func (mc *MetricsCollector) collectionLoop() {
	ticker := time.NewTicker(mc.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.collectMetrics()
		case <-mc.stopChan:
			return
		}
	}
}

// collectMetrics gathers metrics from all registered sources
func (mc *MetricsCollector) collectMetrics() {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// Collect system metrics
	mc.collectSystemMetrics()

	// Collect buffer pool metrics
	mc.collectBufferPoolMetrics()

	// Collect connection pool metrics
	mc.collectConnectionPoolMetrics()
}

// collectSystemMetrics gathers system-level metrics
func (mc *MetricsCollector) collectSystemMetrics() {
	globalMetrics := GetGlobalMetrics()

	// Update goroutine count
	globalMetrics.GoroutineCount.Store(int32(runtime.NumGoroutine()))

	// Update memory usage (approximate)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	globalMetrics.MemoryUsage.Store(m.Alloc)
}

// collectBufferPoolMetrics gathers buffer pool statistics
func (mc *MetricsCollector) collectBufferPoolMetrics() {
	if mc.bufferPool == nil {
		return
	}

	stats := mc.bufferPool.DetailedStats()

	// Update global metrics with buffer pool efficiency
	// Note: Buffer pool stats are already tracked internally, but we can
	// use this for additional monitoring if needed
	_ = stats // Currently just collecting, could be used for alerts
}

// collectConnectionPoolMetrics gathers connection pool statistics
func (mc *MetricsCollector) collectConnectionPoolMetrics() {
	globalMetrics := GetGlobalMetrics()

	var totalActive, totalIdle, totalConnections int32
	var totalUtilization float64

	for _, cp := range mc.connectionPools {
		stats := cp.DetailedStats()

		totalActive += stats.ActiveCount
		totalIdle += int32(stats.IdleCount)
		totalConnections += int32(stats.TotalCount)
		totalUtilization += stats.Utilization

		// Update global metrics with pool statistics
		globalMetrics.ConnectionsActive.Store(totalActive)
	}

	// Calculate average utilization
	poolCount := len(mc.connectionPools)
	if poolCount > 0 {
		avgUtilization := totalUtilization / float64(poolCount)
		_ = avgUtilization // Could be used for alerts or additional metrics
	}
}

// PoolMetricsSnapshot represents a snapshot of pool metrics
type PoolMetricsSnapshot struct {
	Timestamp       time.Time
	ConnectionPools []ConnectionPoolMetrics
	BufferPool      BufferPoolMetrics
	SystemMetrics   SystemMetrics
}

// ConnectionPoolMetrics represents metrics for a single connection pool
type ConnectionPoolMetrics struct {
	ActiveCount int32
	IdleCount   int
	TotalCount  int
	MaxSize     int
	Utilization float64
	IsClosed    bool
}

// BufferPoolMetrics represents metrics for the buffer pool
type BufferPoolMetrics struct {
	SmallAllocs      uint64
	MediumAllocs     uint64
	LargeAllocs      uint64
	SmallReturns     uint64
	MediumReturns    uint64
	LargeReturns     uint64
	TotalAllocs      uint64
	TotalReturns     uint64
	ReuseRate        float64
	MemoryEfficiency float64
}

// SystemMetrics represents system-level metrics
type SystemMetrics struct {
	GoroutineCount int32
	MemoryUsage    uint64
	Uptime         time.Duration
}

// GetPoolMetricsSnapshot returns a comprehensive snapshot of all pool metrics
func (mc *MetricsCollector) GetPoolMetricsSnapshot() PoolMetricsSnapshot {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	snapshot := PoolMetricsSnapshot{
		Timestamp: time.Now(),
	}

	// Collect connection pool metrics
	for _, cp := range mc.connectionPools {
		stats := cp.DetailedStats()
		snapshot.ConnectionPools = append(snapshot.ConnectionPools, ConnectionPoolMetrics{
			ActiveCount: stats.ActiveCount,
			IdleCount:   stats.IdleCount,
			TotalCount:  stats.TotalCount,
			MaxSize:     stats.MaxSize,
			Utilization: stats.Utilization,
			IsClosed:    stats.IsClosed,
		})
	}

	// Collect buffer pool metrics
	if mc.bufferPool != nil {
		stats := mc.bufferPool.DetailedStats()
		snapshot.BufferPool = BufferPoolMetrics{
			SmallAllocs:      stats.SmallAllocs,
			MediumAllocs:     stats.MediumAllocs,
			LargeAllocs:      stats.LargeAllocs,
			SmallReturns:     stats.SmallReturns,
			MediumReturns:    stats.MediumReturns,
			LargeReturns:     stats.LargeReturns,
			TotalAllocs:      stats.TotalAllocs,
			TotalReturns:     stats.TotalReturns,
			ReuseRate:        stats.ReuseRate,
			MemoryEfficiency: stats.MemoryEfficiency,
		}
	}

	// Collect system metrics
	globalMetrics := GetGlobalMetrics().Snapshot()
	snapshot.SystemMetrics = SystemMetrics{
		GoroutineCount: globalMetrics.GoroutineCount,
		MemoryUsage:    globalMetrics.MemoryUsage,
		Uptime:         globalMetrics.Uptime,
	}

	return snapshot
}

// Global collector instance
var (
	globalCollector     *MetricsCollector
	globalCollectorOnce sync.Once
)

// GetGlobalMetricsCollector returns the global metrics collector instance
func GetGlobalMetricsCollector() *MetricsCollector {
	globalCollectorOnce.Do(func() {
		// Default collection interval: 30 seconds
		globalCollector = NewMetricsCollector(30 * time.Second)
	})
	return globalCollector
}
