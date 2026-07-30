package server

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// maxTrackedIPs bounds the limiter's bookkeeping table so a peer rotating source
// addresses cannot grow it without limit.
const maxTrackedIPs = 65536

// ipLimiterSweepInterval throttles the O(len(entries)) reclaim scan.
const ipLimiterSweepInterval = time.Second

// ipEntry is the per-key state of the limiter: how many control connections the
// key currently holds, and how much of its attempt budget is left.
type ipEntry struct {
	active int
	tokens float64
	// lastSeen is when tokens was last recomputed; refill is derived from the
	// elapsed time since, so it must never be moved forward without refilling.
	lastSeen time.Time
}

// ipLimiter bounds, per source address, both the number of concurrent control
// connections and the rate at which new ones may be attempted.
//
// Both limits exist because MaxControlConnections alone does not stop a single
// peer from taking the whole budget: a control connection holds its slot for the
// entire session, and even an unauthenticated one holds it for the full
// authentication deadline. The concurrency cap keeps one peer from occupying
// every slot; the token bucket keeps it from churning through short-lived
// attempts fast enough to keep the budget saturated (or to brute-force a token).
//
// A nil *ipLimiter enforces nothing, so callers need no nil checks.
type ipLimiter struct {
	mu        sync.Mutex
	entries   map[string]*ipEntry
	maxActive int           // max concurrent connections per key (0 = unlimited)
	burst     float64       // token bucket capacity per key (0 = no rate limit)
	interval  time.Duration // one token is restored every interval
	lastSweep time.Time
	lastWarn  time.Time

	// now is the clock, replaced in tests to drive refills deterministically.
	now func() time.Time
}

// newIPLimiter returns a limiter for the given limits, or nil when neither is in
// effect (both zero, or a rate limit that could never refill).
func newIPLimiter(maxActive, burst int, interval time.Duration) *ipLimiter {
	if interval <= 0 {
		// Without a refill interval the bucket would never recover, locking out
		// every peer after its burst. Treat it as "rate limit disabled".
		burst = 0
	}
	if maxActive <= 0 && burst <= 0 {
		return nil
	}
	if maxActive < 0 {
		maxActive = 0
	}
	return &ipLimiter{
		entries:   make(map[string]*ipEntry),
		maxActive: maxActive,
		burst:     float64(burst),
		interval:  interval,
		now:       time.Now,
	}
}

// admit decides whether a new control connection from key may proceed. When it
// may, release must be called exactly once — after the connection is done — to
// give the concurrency slot back. When it may not, reason explains why and
// release is a no-op.
func (l *ipLimiter) admit(key string) (ok bool, release func(), reason string) {
	noop := func() {}
	if l == nil {
		return true, noop, ""
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	// Reclaim keys that have gone fully idle before looking ours up, so the entry
	// we are about to use cannot be swept from under us.
	if now.Sub(l.lastSweep) >= ipLimiterSweepInterval && len(l.entries) > 0 {
		l.lastSweep = now
		l.sweepLocked(now)
	}

	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= maxTrackedIPs {
			l.sweepLocked(now)
		}
		if len(l.entries) >= maxTrackedIPs {
			// Fail open: refusing unknown keys would turn a table filled with
			// rotated addresses into a lockout for every legitimate client, and
			// MaxControlConnections still bounds the total damage.
			if now.Sub(l.lastWarn) >= time.Minute {
				l.lastWarn = now
				log.Printf("Per-IP control limiter: tracking table full (%d keys); admitting %s without per-IP limits", len(l.entries), key)
			}
			return true, noop, ""
		}
		e = &ipEntry{tokens: l.burst, lastSeen: now}
		l.entries[key] = e
	} else {
		l.refillLocked(e, now)
	}

	if l.maxActive > 0 && e.active >= l.maxActive {
		return false, noop, fmt.Sprintf("per-IP concurrent control connection limit (%d) reached", l.maxActive)
	}
	// A rejected attempt spends no token: the peer stays throttled at exactly the
	// refill rate instead of being pushed further behind by its own retries.
	if l.burst > 0 && e.tokens < 1 {
		return false, noop, fmt.Sprintf("per-IP connection rate limit exceeded (burst %d, one attempt per %s)", int(l.burst), l.interval)
	}
	if l.burst > 0 {
		e.tokens--
	}
	e.active++

	var once sync.Once
	return true, func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			// lastSeen is deliberately left alone: moving it forward here would
			// discard the refill accrued while the connection was open.
			if e.active > 0 {
				e.active--
			}
		})
	}, ""
}

// refillLocked credits the tokens earned since e.lastSeen, capped at burst.
func (l *ipLimiter) refillLocked(e *ipEntry, now time.Time) {
	if l.burst <= 0 || l.interval <= 0 {
		e.lastSeen = now
		return
	}
	if elapsed := now.Sub(e.lastSeen); elapsed > 0 {
		e.tokens += float64(elapsed) / float64(l.interval)
		if e.tokens > l.burst {
			e.tokens = l.burst
		}
	}
	e.lastSeen = now
}

// sweepLocked drops keys that hold no connection and have refilled completely.
// Dropping any other key would hand its owner a fresh budget, so a peer that is
// still being throttled always keeps its entry.
func (l *ipLimiter) sweepLocked(now time.Time) {
	for key, e := range l.entries {
		l.refillLocked(e, now)
		if e.active == 0 && e.tokens >= l.burst {
			delete(l.entries, key)
		}
	}
}

// limiterKey reduces a remote address to the unit the per-IP limits apply to: a
// single address for IPv4, the /64 prefix for IPv6. IPv6 peers are routinely
// handed a whole /64, so limiting per address there would be bypassed by simply
// picking another address out of the same allocation.
func limiterKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP at all (net.Pipe and other synthetic addresses): key on the
		// raw string so tests and in-process listeners still get bookkeeping.
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
