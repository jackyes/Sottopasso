package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newLockoutTestServer returns a server whose dashboard limiter locks a source
// out for one minute after maxFails failures, driven by the returned clock.
func newLockoutTestServer(t *testing.T, maxFails int) (*Server, *fakeClock) {
	t.Helper()
	s := New(&Config{
		DashboardUsername:        "admin",
		DashboardPassword:        "pw",
		DashboardAuthMaxFailures: maxFails,
		DashboardAuthLockout:     time.Minute,
	})
	if s.dashAuth == nil {
		t.Fatal("dashboard auth limiter unexpectedly disabled")
	}
	clock := newFakeClock()
	s.dashAuth.now = clock.now
	return s, clock
}

// dashboardAttempt sends one dashboard request from a fixed source address and
// returns the status code. user == "" sends no Authorization header at all.
func dashboardAttempt(s *Server, user, pass string) int {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.7:40000"
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	s.basicAuth(okHandler()).ServeHTTP(rec, req)
	return rec.Code
}

func TestBasicAuth_LocksOutAfterMaxFailures(t *testing.T) {
	s, _ := newLockoutTestServer(t, 3)
	for i := 1; i <= 3; i++ {
		if code := dashboardAttempt(s, "admin", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code=%d, want 401", i, code)
		}
	}
	if code := dashboardAttempt(s, "admin", "wrong"); code != http.StatusTooManyRequests {
		t.Fatalf("after 3 failures: code=%d, want 429", code)
	}
	// While locked out, even correct credentials are not checked.
	if code := dashboardAttempt(s, "admin", "pw"); code != http.StatusTooManyRequests {
		t.Fatalf("correct credentials during lockout: code=%d, want 429", code)
	}
}

// Once a lockout expires, failures must be counted again right away. The
// limiter used to keep the expired lockout on the entry until the next
// (throttled) sweep, and recordFail ignored every failure on an entry with a
// lockout set — so for up to a second after each lockout, guesses were
// unlimited and uncounted.
func TestBasicAuth_FailuresCountedRightAfterLockoutExpires(t *testing.T) {
	s, clock := newLockoutTestServer(t, 3)
	for i := 0; i < 3; i++ {
		dashboardAttempt(s, "admin", "wrong")
	}
	if code := dashboardAttempt(s, "admin", "wrong"); code != http.StatusTooManyRequests {
		t.Fatalf("not locked out after 3 failures: code=%d", code)
	}

	// A request shortly before expiry runs the throttled sweep, which must
	// keep the still-active lockout.
	clock.advance(time.Minute - 500*time.Millisecond)
	if code := dashboardAttempt(s, "admin", "wrong"); code != http.StatusTooManyRequests {
		t.Fatalf("lockout lifted early: code=%d, want 429", code)
	}

	// The lockout is now over, but the next sweep is still throttled.
	clock.advance(600 * time.Millisecond)
	for i := 1; i <= 3; i++ {
		if code := dashboardAttempt(s, "admin", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d after expiry: code=%d, want 401", i, code)
		}
	}
	if code := dashboardAttempt(s, "admin", "wrong"); code != http.StatusTooManyRequests {
		t.Fatalf("3 failures right after expiry did not lock out again: code=%d, want 429", code)
	}
}

// A request without credentials tests no password: it is the browser's first
// request before it shows the login prompt, and must not use up the budget.
func TestBasicAuth_MissingCredentialsDoNotCountAsFailures(t *testing.T) {
	s, _ := newLockoutTestServer(t, 3)
	for i := 1; i <= 10; i++ {
		if code := dashboardAttempt(s, "", ""); code != http.StatusUnauthorized {
			t.Fatalf("request %d without credentials: code=%d, want 401", i, code)
		}
	}
	if code := dashboardAttempt(s, "admin", "pw"); code != http.StatusOK {
		t.Fatalf("correct credentials after unauthenticated requests: code=%d, want 200", code)
	}
}

// --- authFailLimiter ---

func TestAuthFailLimiter_NilAllowsEverything(t *testing.T) {
	var l *authFailLimiter
	for i := 0; i < 10; i++ {
		if !l.attempt("k", true) {
			t.Fatal("nil limiter must never refuse")
		}
	}
	if newAuthFailLimiter(0, time.Minute) != nil || newAuthFailLimiter(5, 0) != nil {
		t.Error("non-positive limits must disable the limiter")
	}
}

// Checking the lockout and counting the failure must be one step: parallel
// failures may not all get through before the first of them is counted.
func TestAuthFailLimiter_ParallelFailuresStopAtLimit(t *testing.T) {
	const maxFails = 5
	l := newAuthFailLimiter(maxFails, time.Minute)

	var wg sync.WaitGroup
	var answered atomic.Int32
	start := make(chan struct{})
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if l.attempt("k", true) {
				answered.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := answered.Load(); got != maxFails {
		t.Fatalf("%d parallel failures were answered, want exactly %d", got, maxFails)
	}
}

func TestAuthFailLimiter_FailureWindowExpires(t *testing.T) {
	l := newAuthFailLimiter(3, time.Minute)
	clock := newFakeClock()
	l.now = clock.now

	l.attempt("k", true)
	l.attempt("k", true)
	clock.advance(time.Minute + time.Second)
	// The two old failures are outside the window: two new ones must not lock.
	l.attempt("k", true)
	l.attempt("k", true)
	if !l.attempt("k", false) {
		t.Fatal("failures from an expired window were still counted")
	}
	l.attempt("k", true)
	if l.attempt("k", false) {
		t.Fatal("3 failures within the window did not lock out")
	}
}

func TestAuthFailLimiter_SuccessIsNotRecorded(t *testing.T) {
	l := newAuthFailLimiter(3, time.Minute)
	for i := 0; i < 100; i++ {
		if !l.attempt("k", false) {
			t.Fatal("successful attempts must never lock out")
		}
	}
	if n := len(l.entries); n != 0 {
		t.Errorf("successful attempts created %d entries, want 0", n)
	}
}

func TestAuthFailLimiter_SweepDropsExpiredEntries(t *testing.T) {
	l := newAuthFailLimiter(2, time.Minute)
	clock := newFakeClock()
	l.now = clock.now

	l.attempt("locked", true)
	l.attempt("locked", true) // locks out
	l.attempt("window", true) // one failure, window running
	if n := len(l.entries); n != 2 {
		t.Fatalf("entries=%d, want 2", n)
	}
	clock.advance(2 * time.Minute)
	l.attempt("other", false) // any call runs the sweep
	if n := len(l.entries); n != 0 {
		t.Errorf("entries=%d after lockout and window expired, want 0", n)
	}
}
