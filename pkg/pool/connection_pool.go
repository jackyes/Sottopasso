package pool

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// PooledStream represents a Yamux stream that can be reused
type PooledStream struct {
	net.Conn
	pool     *ConnectionPool
	lastUsed time.Time
	streamID uint32
	isClosed bool
	mu       sync.RWMutex
}

// ConnectionPool manages a pool of Yamux streams for a session
type ConnectionPool struct {
	mu          sync.RWMutex
	session     *yamux.Session
	streams     map[uint32]*PooledStream
	idleStreams chan *PooledStream
	maxSize     int
	idleTimeout time.Duration
	maxIdle     int
	activeCount int32
	closed      bool
}

// PoolConfig holds configuration for the connection pool
type PoolConfig struct {
	MaxSize     int           // Maximum number of streams in the pool
	IdleTimeout time.Duration // How long an idle stream stays in the pool
	MaxIdle     int           // Maximum number of idle streams
}

// NewConnectionPool creates a new connection pool for a Yamux session
func NewConnectionPool(session *yamux.Session, config PoolConfig) *ConnectionPool {
	if config.MaxSize <= 0 {
		config.MaxSize = 100
	}
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 30 * time.Second
	}
	if config.MaxIdle <= 0 {
		config.MaxIdle = 20
	}

	pool := &ConnectionPool{
		session:     session,
		streams:     make(map[uint32]*PooledStream),
		idleStreams: make(chan *PooledStream, config.MaxIdle),
		maxSize:     config.MaxSize,
		idleTimeout: config.IdleTimeout,
		maxIdle:     config.MaxIdle,
	}

	// Start background cleanup goroutine
	go pool.cleanupIdleStreams()

	return pool
}

// GetStream acquires a stream from the pool or creates a new one
func (p *ConnectionPool) GetStream() (net.Conn, error) {
	if p.isClosed() {
		return nil, net.ErrClosed
	}

	// Try to get an idle stream first
	select {
	case pooledStream := <-p.idleStreams:
		if p.isStreamValid(pooledStream) {
			atomic.AddInt32(&p.activeCount, 1)
			pooledStream.lastUsed = time.Now()
			return pooledStream, nil
		}
		// If invalid, close it and try to create a new one
		pooledStream.closeInternal()
	default:
		// No idle streams available
	}

	// Check if we can create a new stream
	if int(atomic.LoadInt32(&p.activeCount)) >= p.maxSize {
		// Wait for an idle stream with timeout
		select {
		case pooledStream := <-p.idleStreams:
			if p.isStreamValid(pooledStream) {
				atomic.AddInt32(&p.activeCount, 1)
				pooledStream.lastUsed = time.Now()
				return pooledStream, nil
			}
			pooledStream.closeInternal()
		case <-time.After(5 * time.Second):
			return nil, &net.OpError{Op: "dial", Err: &timeoutError{}}
		}
	}

	// Create a new stream
	stream, err := p.session.OpenStream()
	if err != nil {
		return nil, err
	}

	pooledStream := &PooledStream{
		Conn:     stream,
		pool:     p,
		lastUsed: time.Now(),
		streamID: stream.StreamID(),
	}

	p.mu.Lock()
	p.streams[stream.StreamID()] = pooledStream
	p.mu.Unlock()

	atomic.AddInt32(&p.activeCount, 1)
	return pooledStream, nil
}

// ReturnStream returns a stream to the pool for reuse
func (p *ConnectionPool) ReturnStream(stream *PooledStream) {
	if p.isClosed() || stream.isClosed {
		return
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if stream.isClosed {
		return
	}

	// Check if stream is still valid
	if !p.isStreamValid(stream) {
		stream.closeInternal()
		return
	}

	// Try to return to idle pool
	select {
	case p.idleStreams <- stream:
		stream.lastUsed = time.Now()
		atomic.AddInt32(&p.activeCount, -1)
	default:
		// Idle pool is full, close the stream
		stream.closeInternal()
	}
}

// Close closes the entire connection pool and all streams
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	close(p.idleStreams)

	// Close all streams
	for _, stream := range p.streams {
		stream.closeInternal()
	}

	p.streams = make(map[uint32]*PooledStream)
	atomic.StoreInt32(&p.activeCount, 0)

	return nil
}

// Stats returns pool statistics
func (p *ConnectionPool) Stats() (active int32, idle int, total int) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	active = atomic.LoadInt32(&p.activeCount)
	idle = len(p.idleStreams)
	total = len(p.streams)

	return
}

// DetailedStats returns comprehensive pool statistics
func (p *ConnectionPool) DetailedStats() ConnectionPoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return ConnectionPoolStats{
		ActiveCount: atomic.LoadInt32(&p.activeCount),
		IdleCount:   len(p.idleStreams),
		TotalCount:  len(p.streams),
		MaxSize:     p.maxSize,
		IdleTimeout: p.idleTimeout,
		MaxIdle:     p.maxIdle,
		IsClosed:    p.closed,
		Utilization: float64(atomic.LoadInt32(&p.activeCount)) / float64(p.maxSize) * 100,
	}
}

// ConnectionPoolStats holds detailed statistics about connection pool usage
type ConnectionPoolStats struct {
	ActiveCount int32
	IdleCount   int
	TotalCount  int
	MaxSize     int
	IdleTimeout time.Duration
	MaxIdle     int
	IsClosed    bool
	Utilization float64
}

// isStreamValid checks if a stream is still usable
func (p *ConnectionPool) isStreamValid(stream *PooledStream) bool {
	if stream.isClosed {
		return false
	}

	// Check if the underlying stream is still alive
	// Yamux streams become unusable if the session is closed
	if p.session.IsClosed() {
		return false
	}

	// Check if stream has been idle too long
	if time.Since(stream.lastUsed) > p.idleTimeout {
		return false
	}

	return true
}

// isClosed checks if the pool is closed
func (p *ConnectionPool) isClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

// cleanupIdleStreams periodically removes expired idle streams
func (p *ConnectionPool) cleanupIdleStreams() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if p.isClosed() {
			return
		}

		p.mu.Lock()
		now := time.Now()
		for id, stream := range p.streams {
			if stream.isClosed {
				delete(p.streams, id)
				continue
			}

			// Remove streams that have been idle too long
			if now.Sub(stream.lastUsed) > p.idleTimeout {
				stream.closeInternal()
				delete(p.streams, id)
			}
		}
		p.mu.Unlock()
	}
}

// Close implements net.Conn interface for PooledStream
func (ps *PooledStream) Close() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.isClosed {
		return nil
	}

	// Actually close the stream - don't return to pool
	// This prevents premature reuse during active proxy operations
	return ps.closeInternal()
}

// closeInternal actually closes the underlying stream
func (ps *PooledStream) closeInternal() error {
	if ps.isClosed {
		return nil
	}

	ps.isClosed = true
	if ps.pool != nil {
		ps.pool.mu.Lock()
		delete(ps.pool.streams, ps.streamID)
		ps.pool.mu.Unlock()
		atomic.AddInt32(&ps.pool.activeCount, -1)
	}

	return ps.Conn.Close()
}

// Read implements net.Conn interface
func (ps *PooledStream) Read(b []byte) (int, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.isClosed {
		return 0, net.ErrClosed
	}

	return ps.Conn.Read(b)
}

// Write implements net.Conn interface
func (ps *PooledStream) Write(b []byte) (int, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.isClosed {
		return 0, net.ErrClosed
	}

	return ps.Conn.Write(b)
}

// LocalAddr implements net.Conn interface
func (ps *PooledStream) LocalAddr() net.Addr {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.isClosed {
		return nil
	}

	return ps.Conn.LocalAddr()
}

// RemoteAddr implements net.Conn interface
func (ps *PooledStream) RemoteAddr() net.Addr {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.isClosed {
		return nil
	}

	return ps.Conn.RemoteAddr()
}

// SetDeadline implements net.Conn interface
func (ps *PooledStream) SetDeadline(t time.Time) error {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.isClosed {
		return net.ErrClosed
	}

	return ps.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn interface
func (ps *PooledStream) SetReadDeadline(t time.Time) error {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.isClosed {
		return net.ErrClosed
	}

	return ps.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn interface
func (ps *PooledStream) SetWriteDeadline(t time.Time) error {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.isClosed {
		return net.ErrClosed
	}

	return ps.Conn.SetWriteDeadline(t)
}

// timeoutError implements net.Error for timeout errors
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "connection pool timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
