package server

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// limitListener caps the connections open at once on a listener, in all and
// per source address (IPv6 grouped by /64). A connection over a cap is
// accepted and closed straight away, so the kernel backlog never fills and
// sources under their cap keep getting through. A slot is held until the
// connection is closed, idle keep-alive time included.
type limitListener struct {
	net.Listener
	sem   chan struct{} // nil = no global cap
	perIP *ipLimiter    // nil = no per-source cap
	log   *throttledLog
}

// newLimitListener wraps ln with the given caps (0 = unlimited). With both
// disabled it returns ln itself.
func newLimitListener(ln net.Listener, maxConns, maxPerIP int) net.Listener {
	if maxConns <= 0 && maxPerIP <= 0 {
		return ln
	}
	l := &limitListener{
		Listener: ln,
		perIP:    newIPLimiter(maxPerIP, 0, 0),
		log:      newThrottledLog(time.Second),
	}
	if maxConns > 0 {
		l.sem = make(chan struct{}, maxConns)
	}
	return l
}

// Accept returns the next connection within the caps. Connections over a cap
// are closed here and never reach the caller.
func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ok, releaseIP, reason := l.perIP.admit(limiterKey(c.RemoteAddr()))
		if !ok {
			l.log.printf("Rejecting public connection from %s: %s", c.RemoteAddr(), reason)
			c.Close()
			continue
		}
		if l.sem != nil {
			select {
			case l.sem <- struct{}{}:
			default:
				releaseIP()
				l.log.printf("Rejecting public connection from %s: global limit (%d) reached", c.RemoteAddr(), cap(l.sem))
				c.Close()
				continue
			}
		}
		release := releaseIP
		if l.sem != nil {
			release = func() { releaseIP(); <-l.sem }
		}
		return &limitedConn{Conn: c, release: release}, nil
	}
}

// limitedConn gives its limitListener slot back when it is closed, once.
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// CloseWrite forwards a half-close: net/http and the WebSocket relay rely on
// it, and the embedded net.Conn would otherwise hide it.
func (c *limitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// throttledLog writes at most one line per interval and counts the lines it
// dropped. Events visitors can trigger at will (refused connections, idle
// timeouts) go through it, so they cannot flood the log, whose lines carry
// visitors' addresses.
type throttledLog struct {
	mu         sync.Mutex
	interval   time.Duration
	last       time.Time
	suppressed int
}

func newThrottledLog(interval time.Duration) *throttledLog {
	return &throttledLog{interval: interval}
}

func (t *throttledLog) printf(format string, args ...any) {
	if t == nil {
		log.Printf(format, args...)
		return
	}
	t.mu.Lock()
	now := time.Now()
	if !t.last.IsZero() && now.Sub(t.last) < t.interval {
		t.suppressed++
		t.mu.Unlock()
		return
	}
	dropped := t.suppressed
	t.suppressed = 0
	t.last = now
	t.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	if dropped > 0 {
		msg += fmt.Sprintf(" (%d similar lines suppressed since the previous one)", dropped)
	}
	log.Print(msg)
}

// watchIdle calls onIdle once nothing has updated last (a UnixNano time) for
// timeout, then stops. The returned function stops the watch early.
func watchIdle(timeout time.Duration, last *atomic.Int64, onIdle func(idle time.Duration)) (stop func()) {
	done := make(chan struct{})
	go func() {
		tick := timeout / 2
		if tick < 100*time.Millisecond {
			tick = 100 * time.Millisecond
		}
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if idle := time.Since(time.Unix(0, last.Load())); idle > timeout {
					onIdle(idle)
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
