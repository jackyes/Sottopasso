package pool

import (
	"sync"
	"sync/atomic"
	"time"
)

// BufferPool manages a pool of byte buffers with multiple size classes
type BufferPool struct {
	smallPool  *sync.Pool // 4KB buffers
	mediumPool *sync.Pool // 16KB buffers
	largePool  *sync.Pool // 65KB buffers (UDP max size)

	// Statistics
	smallAllocs   atomic.Uint64
	mediumAllocs  atomic.Uint64
	largeAllocs   atomic.Uint64
	smallReturns  atomic.Uint64
	mediumReturns atomic.Uint64
	largeReturns  atomic.Uint64

	// Configuration
	smallSize  int
	mediumSize int
	largeSize  int
}

// BufferPoolConfig holds configuration for the buffer pool
type BufferPoolConfig struct {
	SmallBufferSize  int // Default: 4KB
	MediumBufferSize int // Default: 16KB
	LargeBufferSize  int // Default: 65KB (UDP max)
}

// DefaultBufferPoolConfig returns the default buffer pool configuration
func DefaultBufferPoolConfig() BufferPoolConfig {
	return BufferPoolConfig{
		SmallBufferSize:  4 * 1024,  // 4KB
		MediumBufferSize: 16 * 1024, // 16KB
		LargeBufferSize:  64 * 1024, // 64KB (close to 65KB UDP max)
	}
}

// NewBufferPool creates a new buffer pool with the specified configuration
func NewBufferPool(config BufferPoolConfig) *BufferPool {
	if config.SmallBufferSize <= 0 {
		config.SmallBufferSize = 4 * 1024
	}
	if config.MediumBufferSize <= 0 {
		config.MediumBufferSize = 16 * 1024
	}
	if config.LargeBufferSize <= 0 {
		config.LargeBufferSize = 64 * 1024
	}

	return &BufferPool{
		smallPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, config.SmallBufferSize)
			},
		},
		mediumPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, config.MediumBufferSize)
			},
		},
		largePool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, config.LargeBufferSize)
			},
		},
		smallSize:  config.SmallBufferSize,
		mediumSize: config.MediumBufferSize,
		largeSize:  config.LargeBufferSize,
	}
}

// GetSmall returns a small buffer (4KB)
func (bp *BufferPool) GetSmall() []byte {
	bp.smallAllocs.Add(1)
	return bp.smallPool.Get().([]byte)
}

// GetMedium returns a medium buffer (16KB)
func (bp *BufferPool) GetMedium() []byte {
	bp.mediumAllocs.Add(1)
	return bp.mediumPool.Get().([]byte)
}

// GetLarge returns a large buffer (65KB)
func (bp *BufferPool) GetLarge() []byte {
	bp.largeAllocs.Add(1)
	return bp.largePool.Get().([]byte)
}

// Get returns a buffer of the specified size, choosing the appropriate pool
func (bp *BufferPool) Get(size int) []byte {
	switch {
	case size <= bp.smallSize:
		return bp.GetSmall()
	case size <= bp.mediumSize:
		return bp.GetMedium()
	default:
		return bp.GetLarge()
	}
}

// PutSmall returns a small buffer to the pool
func (bp *BufferPool) PutSmall(buf []byte) {
	if len(buf) == bp.smallSize {
		bp.smallReturns.Add(1)
		bp.smallPool.Put(buf)
	}
	// If buffer size doesn't match, let GC handle it
}

// PutMedium returns a medium buffer to the pool
func (bp *BufferPool) PutMedium(buf []byte) {
	if len(buf) == bp.mediumSize {
		bp.mediumReturns.Add(1)
		bp.mediumPool.Put(buf)
	}
	// If buffer size doesn't match, let GC handle it
}

// PutLarge returns a large buffer to the pool
func (bp *BufferPool) PutLarge(buf []byte) {
	if len(buf) == bp.largeSize {
		bp.largeReturns.Add(1)
		bp.largePool.Put(buf)
	}
	// If buffer size doesn't match, let GC handle it
}

// Put returns a buffer to the appropriate pool based on its size
func (bp *BufferPool) Put(buf []byte) {
	switch len(buf) {
	case bp.smallSize:
		bp.PutSmall(buf)
	case bp.mediumSize:
		bp.PutMedium(buf)
	case bp.largeSize:
		bp.PutLarge(buf)
	default:
		// Non-standard size, let GC handle it
	}
}

// Stats returns buffer pool statistics
func (bp *BufferPool) Stats() BufferPoolStats {
	return BufferPoolStats{
		SmallAllocs:   bp.smallAllocs.Load(),
		MediumAllocs:  bp.mediumAllocs.Load(),
		LargeAllocs:   bp.largeAllocs.Load(),
		SmallReturns:  bp.smallReturns.Load(),
		MediumReturns: bp.mediumReturns.Load(),
		LargeReturns:  bp.largeReturns.Load(),
		SmallSize:     bp.smallSize,
		MediumSize:    bp.mediumSize,
		LargeSize:     bp.largeSize,
	}
}

// DetailedStats returns comprehensive buffer pool statistics
func (bp *BufferPool) DetailedStats() BufferPoolDetailedStats {
	stats := bp.Stats()
	return BufferPoolDetailedStats{
		BufferPoolStats:  stats,
		TotalAllocs:      stats.TotalAllocs(),
		TotalReturns:     stats.TotalReturns(),
		ReuseRate:        stats.ReuseRate(),
		MemoryEfficiency: float64(stats.TotalReturns()) / float64(stats.TotalAllocs()) * 100,
		Timestamp:        time.Now(),
	}
}

// BufferPoolDetailedStats holds detailed statistics about buffer pool usage
type BufferPoolDetailedStats struct {
	BufferPoolStats
	TotalAllocs      uint64
	TotalReturns     uint64
	ReuseRate        float64
	MemoryEfficiency float64
	Timestamp        time.Time
}

// BufferPoolStats holds statistics about buffer pool usage
type BufferPoolStats struct {
	SmallAllocs   uint64
	MediumAllocs  uint64
	LargeAllocs   uint64
	SmallReturns  uint64
	MediumReturns uint64
	LargeReturns  uint64
	SmallSize     int
	MediumSize    int
	LargeSize     int
}

// TotalAllocs returns the total number of buffer allocations
func (s BufferPoolStats) TotalAllocs() uint64 {
	return s.SmallAllocs + s.MediumAllocs + s.LargeAllocs
}

// TotalReturns returns the total number of buffer returns
func (s BufferPoolStats) TotalReturns() uint64 {
	return s.SmallReturns + s.MediumReturns + s.LargeReturns
}

// ReuseRate returns the buffer reuse rate as a percentage
func (s BufferPoolStats) ReuseRate() float64 {
	totalAllocs := s.TotalAllocs()
	if totalAllocs == 0 {
		return 0
	}
	return float64(s.TotalReturns()) / float64(totalAllocs) * 100
}

// Global buffer pool instance
var (
	globalBufferPool     *BufferPool
	globalBufferPoolOnce sync.Once
)

// GetGlobalBufferPool returns the global buffer pool instance
func GetGlobalBufferPool() *BufferPool {
	globalBufferPoolOnce.Do(func() {
		globalBufferPool = NewBufferPool(DefaultBufferPoolConfig())
	})
	return globalBufferPool
}

// BufferedCopy performs a buffered copy between two connections with deadlines
func BufferedCopy(dst, src interface{}, bufferPool *BufferPool, readTimeout, writeTimeout time.Duration) (written int64, err error) {
	buf := bufferPool.GetLarge()
	defer bufferPool.PutLarge(buf)

	for {
		// Set read deadline
		if conn, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
			conn.SetReadDeadline(time.Now().Add(readTimeout))
		}

		nr, er := readFrom(src, buf)
		if nr > 0 {
			// Set write deadline
			if conn, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
				conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			}

			nw, ew := writeTo(dst, buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != ErrEOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// Helper functions for BufferedCopy
func readFrom(reader interface{}, buf []byte) (int, error) {
	switch r := reader.(type) {
	case interface{ Read([]byte) (int, error) }:
		return r.Read(buf)
	default:
		return 0, ErrInvalidReader
	}
}

func writeTo(writer interface{}, buf []byte) (int, error) {
	switch w := writer.(type) {
	case interface{ Write([]byte) (int, error) }:
		return w.Write(buf)
	default:
		return 0, ErrInvalidWriter
	}
}

// Errors
var (
	ErrShortWrite    = &BufferError{"short write"}
	ErrEOF           = &BufferError{"EOF"}
	ErrInvalidReader = &BufferError{"invalid reader"}
	ErrInvalidWriter = &BufferError{"invalid writer"}
)

// BufferError represents a buffer pool error
type BufferError struct {
	msg string
}

func (e *BufferError) Error() string {
	return "buffer pool: " + e.msg
}
