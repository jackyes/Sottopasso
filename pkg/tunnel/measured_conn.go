package tunnel

import (
	"net"
	"sync/atomic"
	"time"

	"Sottopasso/pkg/metrics"
)

// MeasuredConn is a wrapper around net.Conn that tracks comprehensive performance metrics.
type MeasuredConn struct {
	net.Conn
	bytesIn       *atomic.Uint64
	bytesOut      *atomic.Uint64
	readErrors    *atomic.Uint64
	writeErrors   *atomic.Uint64
	timeoutErrors *atomic.Uint64
	startTime     time.Time
	lastReadTime  time.Time
	lastWriteTime time.Time
	protocolType  string
}

// NewMeasuredConn creates a new MeasuredConn with enhanced metrics tracking.
func NewMeasuredConn(conn net.Conn, bytesIn, bytesOut *atomic.Uint64, protocolType string) *MeasuredConn {
	now := time.Now()
	return &MeasuredConn{
		Conn:          conn,
		bytesIn:       bytesIn,
		bytesOut:      bytesOut,
		readErrors:    &atomic.Uint64{},
		writeErrors:   &atomic.Uint64{},
		timeoutErrors: &atomic.Uint64{},
		startTime:     now,
		lastReadTime:  now,
		lastWriteTime: now,
		protocolType:  protocolType,
	}
}

// Read reads data from the connection and tracks metrics.
func (c *MeasuredConn) Read(p []byte) (n int, err error) {
	start := time.Now()
	n, err = c.Conn.Read(p)
	duration := time.Since(start)

	if n > 0 {
		c.bytesIn.Add(uint64(n))
		c.lastReadTime = time.Now()

		// Update global metrics
		metrics.GetGlobalMetrics().ReadLatency.Observe(duration)
		metrics.GetGlobalMetrics().PacketsIn.Add(1)
	}

	if err != nil {
		c.trackError(err, "read")
	}

	return
}

// Write writes data to the connection and tracks metrics.
func (c *MeasuredConn) Write(p []byte) (n int, err error) {
	start := time.Now()
	n, err = c.Conn.Write(p)
	duration := time.Since(start)

	if n > 0 {
		c.bytesOut.Add(uint64(n))
		c.lastWriteTime = time.Now()

		// Update global metrics
		metrics.GetGlobalMetrics().WriteLatency.Observe(duration)
		metrics.GetGlobalMetrics().PacketsOut.Add(1)
	}

	if err != nil {
		c.trackError(err, "write")
	}

	return
}

// trackError categorizes and counts different types of errors.
func (c *MeasuredConn) trackError(err error, operation string) {
	switch {
	case isTimeoutError(err):
		c.timeoutErrors.Add(1)
		metrics.GetGlobalMetrics().TimeoutErrors.Add(1)
	case operation == "read":
		c.readErrors.Add(1)
		metrics.GetGlobalMetrics().ReadErrors.Add(1)
	case operation == "write":
		c.writeErrors.Add(1)
		metrics.GetGlobalMetrics().WriteErrors.Add(1)
	}
}

// GetConnectionDuration returns the duration this connection has been active.
func (c *MeasuredConn) GetConnectionDuration() time.Duration {
	return time.Since(c.startTime)
}

// GetLastActivity returns the time of the last read or write operation.
func (c *MeasuredConn) GetLastActivity() time.Time {
	if c.lastReadTime.After(c.lastWriteTime) {
		return c.lastReadTime
	}
	return c.lastWriteTime
}

// GetErrorCounts returns the counts of different error types.
func (c *MeasuredConn) GetErrorCounts() (readErrors, writeErrors, timeoutErrors uint64) {
	return c.readErrors.Load(), c.writeErrors.Load(), c.timeoutErrors.Load()
}

// GetThroughput calculates current throughput in bytes per second.
func (c *MeasuredConn) GetThroughput() (inBps, outBps float64) {
	duration := c.GetConnectionDuration().Seconds()
	if duration > 0 {
		inBps = float64(c.bytesIn.Load()) / duration
		outBps = float64(c.bytesOut.Load()) / duration
	}
	return inBps, outBps
}

// isTimeoutError checks if the error is a timeout error.
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}
