package tunnel

import (
	"net"
	"sync/atomic"
)

// MeasuredConn is a wrapper around net.Conn that counts bytes read and written.
type MeasuredConn struct {
	net.Conn
	bytesIn  *atomic.Uint64
	bytesOut *atomic.Uint64
}

// NewMeasuredConn creates a new MeasuredConn.
func NewMeasuredConn(conn net.Conn, bytesIn, bytesOut *atomic.Uint64) *MeasuredConn {
	return &MeasuredConn{
		Conn:     conn,
		bytesIn:  bytesIn,
		bytesOut: bytesOut,
	}
}

// Read reads data from the connection and counts bytes read.
func (c *MeasuredConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 {
		c.bytesIn.Add(uint64(n))
	}
	return
}

// Write writes data to the connection and counts bytes written.
func (c *MeasuredConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if n > 0 {
		c.bytesOut.Add(uint64(n))
	}
	return
}
