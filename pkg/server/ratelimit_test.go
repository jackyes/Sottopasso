package server

import (
	"net"
	"sync"
	"testing"
	"time"
)

// fakeClock drives the limiter's refill deterministically.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// withClock swaps in a deterministic clock.
func withClock(l *ipLimiter, c *fakeClock) *ipLimiter {
	l.now = c.now
	return l
}

// --- newIPLimiter ---

func TestNewIPLimiter_DisabledWhenNoLimits(t *testing.T) {
	if l := newIPLimiter(0, 0, time.Second); l != nil {
		t.Error("both limits zero must yield a nil (no-op) limiter")
	}
	// A zero interval could never refill, so the rate limit must be treated as off
	// rather than locking every peer out after its burst.
	if l := newIPLimiter(0, 5, 0); l != nil {
		t.Error("burst without a refill interval must yield a nil limiter")
	}
	if l := newIPLimiter(0, 5, time.Second); l == nil {
		t.Error("a rate limit alone must yield a live limiter")
	}
	if l := newIPLimiter(2, 0, 0); l == nil {
		t.Error("a concurrency cap alone must yield a live limiter")
	}
}

// A nil limiter must admit everything so callers need no nil checks.
func TestIPLimiter_NilAdmitsEverything(t *testing.T) {
	var l *ipLimiter
	for i := 0; i < 3; i++ {
		ok, release, reason := l.admit("1.2.3.4")
		if !ok {
			t.Fatalf("nil limiter rejected: %s", reason)
		}
		release() // must not panic
	}
}

// --- concurrency cap ---

func TestIPLimiter_ConcurrencyCapPerKey(t *testing.T) {
	l := newIPLimiter(2, 0, 0)

	ok1, rel1, _ := l.admit("10.0.0.1")
	ok2, _, _ := l.admit("10.0.0.1")
	if !ok1 || !ok2 {
		t.Fatal("the first two connections must be admitted")
	}

	ok3, _, reason := l.admit("10.0.0.1")
	if ok3 {
		t.Fatal("the third concurrent connection must be rejected")
	}
	if reason == "" {
		t.Error("a rejection must carry a reason")
	}

	// A different source is unaffected by the first one's usage.
	if ok, _, reason := l.admit("10.0.0.2"); !ok {
		t.Errorf("another source must not be affected: %s", reason)
	}

	// Releasing frees the slot.
	rel1()
	if ok, _, reason := l.admit("10.0.0.1"); !ok {
		t.Errorf("a released slot must be reusable: %s", reason)
	}
}

// release must be idempotent: a double call cannot manufacture extra slots.
func TestIPLimiter_ReleaseIsIdempotent(t *testing.T) {
	l := newIPLimiter(1, 0, 0)
	_, rel, _ := l.admit("10.0.0.1")
	rel()
	rel()
	rel()

	if ok, _, _ := l.admit("10.0.0.1"); !ok {
		t.Fatal("the released slot must be reusable")
	}
	if ok, _, _ := l.admit("10.0.0.1"); ok {
		t.Fatal("repeated release must not raise the cap above 1")
	}
}

// --- rate limit ---

func TestIPLimiter_RateLimitBurstThenRefill(t *testing.T) {
	clock := newFakeClock()
	l := withClock(newIPLimiter(0, 3, time.Second), clock)

	for i := 0; i < 3; i++ {
		if ok, _, reason := l.admit("10.0.0.1"); !ok {
			t.Fatalf("attempt %d within the burst must be admitted: %s", i+1, reason)
		}
	}
	if ok, _, reason := l.admit("10.0.0.1"); ok {
		t.Fatal("the attempt past the burst must be rejected")
	} else if reason == "" {
		t.Error("a rejection must carry a reason")
	}

	// Half an interval is not enough for a whole token.
	clock.advance(500 * time.Millisecond)
	if ok, _, _ := l.admit("10.0.0.1"); ok {
		t.Fatal("half an interval must not yield a token")
	}

	// A full interval since the last refill yields exactly one.
	clock.advance(500 * time.Millisecond)
	if ok, _, _ := l.admit("10.0.0.1"); !ok {
		t.Fatal("a full interval must yield one token")
	}
	if ok, _, _ := l.admit("10.0.0.1"); ok {
		t.Fatal("only one token may be earned per interval")
	}

	// Refill is capped at the burst, no matter how long the peer waits.
	clock.advance(time.Hour)
	for i := 0; i < 3; i++ {
		if ok, _, _ := l.admit("10.0.0.1"); !ok {
			t.Fatalf("attempt %d after a long idle period must be admitted", i+1)
		}
	}
	if ok, _, _ := l.admit("10.0.0.1"); ok {
		t.Fatal("refill must be capped at the burst")
	}
}

// A throttled peer's own retries must not push it further behind.
func TestIPLimiter_RejectedAttemptSpendsNoToken(t *testing.T) {
	clock := newFakeClock()
	l := withClock(newIPLimiter(0, 1, time.Second), clock)

	if ok, _, _ := l.admit("10.0.0.1"); !ok {
		t.Fatal("the first attempt must be admitted")
	}
	for i := 0; i < 10; i++ {
		if ok, _, _ := l.admit("10.0.0.1"); ok {
			t.Fatal("attempts during the throttle must be rejected")
		}
	}
	clock.advance(time.Second)
	if ok, _, _ := l.admit("10.0.0.1"); !ok {
		t.Fatal("one interval after the last admitted attempt a token must be available")
	}
}

// --- table reclaim ---

// A key must not be reclaimed while it is still being throttled: dropping the
// entry would hand it a fresh burst.
func TestIPLimiter_SweepKeepsThrottledKeys(t *testing.T) {
	clock := newFakeClock()
	l := withClock(newIPLimiter(0, 2, time.Minute), clock)

	_, rel1, _ := l.admit("10.0.0.1")
	_, rel2, _ := l.admit("10.0.0.1")
	if ok, _, _ := l.admit("10.0.0.1"); ok {
		t.Fatal("the burst must be spent")
	}
	// Both connections are gone; only the spent attempt budget keeps the key alive.
	rel1()
	rel2()

	// Trigger a sweep (its throttle is one second) without refilling a full token.
	clock.advance(2 * time.Second)
	if ok, _, _ := l.admit("10.0.0.2"); !ok {
		t.Fatal("an unrelated source must be admitted")
	}
	if ok, _, _ := l.admit("10.0.0.1"); ok {
		t.Fatal("the throttled key must survive the sweep with its spent budget")
	}

	// Once fully refilled and idle it may be reclaimed; that is indistinguishable
	// from a fresh key, so the peer legitimately gets its burst back.
	clock.advance(2 * time.Minute)
	l.admit("10.0.0.3")
	l.mu.Lock()
	_, stillTracked := l.entries["10.0.0.1"]
	l.mu.Unlock()
	if stillTracked {
		t.Error("a fully refilled, idle key should have been reclaimed")
	}
}

// A key holding an open connection must never be reclaimed.
func TestIPLimiter_SweepKeepsActiveKeys(t *testing.T) {
	clock := newFakeClock()
	l := withClock(newIPLimiter(1, 2, time.Second), clock)

	if ok, _, _ := l.admit("10.0.0.1"); !ok {
		t.Fatal("the first connection must be admitted")
	}

	clock.advance(time.Hour) // fully refilled, but still holding a connection
	l.admit("10.0.0.2")      // triggers a sweep

	l.mu.Lock()
	_, stillTracked := l.entries["10.0.0.1"]
	l.mu.Unlock()
	if !stillTracked {
		t.Fatal("a key with an open connection must not be reclaimed")
	}
	if ok, _, _ := l.admit("10.0.0.1"); ok {
		t.Error("the concurrency cap must still be enforced after a sweep")
	}
}

// --- limiterKey ---

func TestLimiterKey(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"ipv4 with port", &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4040}, "203.0.113.7"},
		{"ipv4-in-ipv6 form", &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 1}, "203.0.113.7"},
		{"ipv6 groups by /64", &net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:3:4:5:6"), Port: 1}, "2001:db8:1:2::/64"},
		{"non-IP address", fakeAddr("pipe"), "pipe"},
		{"nil address", nil, ""},
	}
	for _, tc := range tests {
		if got := limiterKey(tc.addr); got != tc.want {
			t.Errorf("%s: limiterKey=%q, want %q", tc.name, got, tc.want)
		}
	}
}

// Two addresses inside one /64 must share a budget; a different /64 must not.
func TestLimiterKey_IPv6SameAllocationSharesLimit(t *testing.T) {
	l := newIPLimiter(1, 0, 0)

	first := limiterKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1})
	second := limiterKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff:ffff:ffff:ffff"), Port: 2})
	other := limiterKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 3})

	if ok, _, _ := l.admit(first); !ok {
		t.Fatal("the first address must be admitted")
	}
	if ok, _, _ := l.admit(second); ok {
		t.Error("another address in the same /64 must share the cap")
	}
	if ok, _, _ := l.admit(other); !ok {
		t.Error("a different /64 must have its own budget")
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

// --- concurrent use ---

// The limiter is touched from every accept goroutine: it must be race-free and
// must never admit more than the cap.
func TestIPLimiter_ConcurrentAdmitRespectsCap(t *testing.T) {
	const cap = 4
	l := newIPLimiter(cap, 0, 0)

	var mu sync.Mutex
	admitted := 0
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _, _ := l.admit("10.0.0.1"); ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if admitted != cap {
		t.Errorf("admitted=%d, want exactly %d", admitted, cap)
	}
}
