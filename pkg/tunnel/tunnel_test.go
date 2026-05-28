package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn is a programmable net.Conn used to drive MeasuredConn under controlled
// Read/Write behavior (partial writes, errors accompanying data, EOF, etc.).
type fakeConn struct {
	readData []byte
	readErr  error // returned together with the final chunk of readData (or alone if no data)

	written  bytes.Buffer
	writeCap int   // if >0, accept at most this many bytes per Write
	writeErr error // returned from Write (together with the byte count)

	closedCount int
}

func (f *fakeConn) Read(p []byte) (int, error) {
	if len(f.readData) > 0 {
		n := copy(p, f.readData)
		f.readData = f.readData[n:]
		if len(f.readData) == 0 {
			return n, f.readErr
		}
		return n, nil
	}
	if f.readErr != nil {
		return 0, f.readErr
	}
	return 0, io.EOF
}

func (f *fakeConn) Write(p []byte) (int, error) {
	n := len(p)
	if f.writeCap > 0 && f.writeCap < n {
		n = f.writeCap
	}
	f.written.Write(p[:n])
	return n, f.writeErr
}

func (f *fakeConn) Close() error                       { f.closedCount++; return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return nil }
func (f *fakeConn) RemoteAddr() net.Addr               { return nil }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestNewMeasuredConn(t *testing.T) {
	var in, out atomic.Uint64
	fc := &fakeConn{}
	mc := NewMeasuredConn(fc, &in, &out)
	if mc == nil {
		t.Fatal("NewMeasuredConn returned nil")
	}
	if mc.Conn != fc {
		t.Error("embedded Conn is not the one passed in")
	}
}

func TestMeasuredConn_ReadCountsBytes(t *testing.T) {
	var in, out atomic.Uint64
	fc := &fakeConn{readData: []byte("hello")}
	mc := NewMeasuredConn(fc, &in, &out)

	buf := make([]byte, 16)
	n, err := mc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("n=%d, want 5", n)
	}
	if got := in.Load(); got != 5 {
		t.Errorf("bytesIn=%d, want 5", got)
	}
	if got := out.Load(); got != 0 {
		t.Errorf("bytesOut=%d, want 0 (Read must not touch bytesOut)", got)
	}
}

func TestMeasuredConn_ReadAccumulates(t *testing.T) {
	var in, out atomic.Uint64
	fc := &fakeConn{readData: []byte("abcdefghij")}
	mc := NewMeasuredConn(fc, &in, &out)

	buf := make([]byte, 4)
	for {
		_, err := mc.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if got := in.Load(); got != 10 {
		t.Errorf("accumulated bytesIn=%d, want 10", got)
	}
}

func TestMeasuredConn_ReadZeroDoesNotCount(t *testing.T) {
	var in, out atomic.Uint64
	fc := &fakeConn{} // no data -> (0, io.EOF)
	mc := NewMeasuredConn(fc, &in, &out)

	n, err := mc.Read(make([]byte, 8))
	if n != 0 || err != io.EOF {
		t.Fatalf("got (%d,%v), want (0, EOF)", n, err)
	}
	if got := in.Load(); got != 0 {
		t.Errorf("bytesIn=%d, want 0 on zero-byte read", got)
	}
}

// A Read may legitimately return n>0 together with an error; those bytes must
// still be counted.
func TestMeasuredConn_ReadCountsBytesEvenWithError(t *testing.T) {
	var in, out atomic.Uint64
	sentinel := errors.New("boom")
	fc := &fakeConn{readData: []byte("xyz"), readErr: sentinel}
	mc := NewMeasuredConn(fc, &in, &out)

	n, err := mc.Read(make([]byte, 8))
	if n != 3 || err != sentinel {
		t.Fatalf("got (%d,%v), want (3, boom)", n, err)
	}
	if got := in.Load(); got != 3 {
		t.Errorf("bytesIn=%d, want 3", got)
	}
}

func TestMeasuredConn_WriteCountsBytes(t *testing.T) {
	var in, out atomic.Uint64
	fc := &fakeConn{}
	mc := NewMeasuredConn(fc, &in, &out)

	n, err := mc.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("got (%d,%v), want (5,nil)", n, err)
	}
	if got := out.Load(); got != 5 {
		t.Errorf("bytesOut=%d, want 5", got)
	}
	if got := in.Load(); got != 0 {
		t.Errorf("bytesIn=%d, want 0 (Write must not touch bytesIn)", got)
	}
}

func TestMeasuredConn_WritePartialCountsActual(t *testing.T) {
	var in, out atomic.Uint64
	fc := &fakeConn{writeCap: 3}
	mc := NewMeasuredConn(fc, &in, &out)

	n, err := mc.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 {
		t.Fatalf("n=%d, want 3 (partial write)", n)
	}
	if got := out.Load(); got != 3 {
		t.Errorf("bytesOut=%d, want 3 (only bytes actually written counted)", got)
	}
}

func TestMeasuredConn_WriteCountsBytesEvenWithError(t *testing.T) {
	var in, out atomic.Uint64
	sentinel := errors.New("short write")
	fc := &fakeConn{writeCap: 2, writeErr: sentinel}
	mc := NewMeasuredConn(fc, &in, &out)

	n, err := mc.Write([]byte("hello"))
	if n != 2 || err != sentinel {
		t.Fatalf("got (%d,%v), want (2, short write)", n, err)
	}
	if got := out.Load(); got != 2 {
		t.Errorf("bytesOut=%d, want 2", got)
	}
}

// Concurrency: many goroutines reading/writing must produce exact totals under -race.
func TestMeasuredConn_ConcurrentCounting(t *testing.T) {
	const goroutines = 50
	const perGoroutine = 100

	var in, out atomic.Uint64
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				// fresh conn per call to avoid sharing the fakeConn buffer
				mc := NewMeasuredConn(&fakeConn{readData: []byte("ab")}, &in, &out)
				mc.Read(make([]byte, 8))
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				mc := NewMeasuredConn(&fakeConn{}, &in, &out)
				mc.Write([]byte("abc"))
			}
		}()
	}
	wg.Wait()

	if got := in.Load(); got != goroutines*perGoroutine*2 {
		t.Errorf("bytesIn=%d, want %d", got, goroutines*perGoroutine*2)
	}
	if got := out.Load(); got != goroutines*perGoroutine*3 {
		t.Errorf("bytesOut=%d, want %d", got, goroutines*perGoroutine*3)
	}
}

// --- Proxy ---

// TestProxy_BidirectionalAndCounts verifies data flows both ways through Proxy
// and that the per-direction byte counters are wired correctly.
func TestProxy_BidirectionalAndCounts(t *testing.T) {
	end1, a := net.Pipe()
	b, end2 := net.Pipe()

	var inA, outA, inB, outB atomic.Uint64
	ma := NewMeasuredConn(a, &inA, &outA)
	mb := NewMeasuredConn(b, &inB, &outB)

	done := make(chan struct{})
	go func() { Proxy(ma, mb); close(done) }()

	// end1 -> (a -> b) -> end2
	go func() { end1.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(end2, buf); err != nil {
		t.Fatalf("reading from end2: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("end2 got %q, want ping", buf)
	}

	// end2 -> (b -> a) -> end1
	go func() { end2.Write([]byte("pong")) }()
	if _, err := io.ReadFull(end1, buf); err != nil {
		t.Fatalf("reading from end1: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("end1 got %q, want pong", buf)
	}

	// Closing one peer must cause Proxy to tear down and return.
	end1.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Proxy did not return after a peer closed (possible goroutine leak/deadlock)")
	}

	// The byte counters are incremented by the proxy goroutines immediately after
	// each underlying pipe write returns, which races with the reads above (a
	// net.Pipe write unblocks the writer at the same instant the reader returns).
	// Poll for the expected totals rather than reading them synchronously.
	// "ping" entered via a (read) and left via b (write); "pong" the reverse.
	waitForCount(t, "inA", &inA, 4)
	waitForCount(t, "outB", &outB, 4)
	waitForCount(t, "inB", &inB, 4)
	waitForCount(t, "outA", &outA, 4)
}

// waitForCount polls an asynchronously-updated atomic counter until it reaches
// the expected value or a timeout elapses.
func waitForCount(t *testing.T, name string, c *atomic.Uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.Load() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Errorf("%s=%d, want %d", name, c.Load(), want)
}

// TestProxy_ClosesBothSides ensures that when Proxy finishes, both connections
// are closed (so neither side leaks an open fd).
func TestProxy_ClosesBothSides(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a1.Close()
	defer b1.Close()

	var x atomic.Uint64
	ma := NewMeasuredConn(a2, &x, &x)
	mb := NewMeasuredConn(b2, &x, &x)

	done := make(chan struct{})
	go func() { Proxy(ma, mb); close(done) }()

	a1.Close() // triggers EOF on a2 -> Proxy tears down

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Proxy did not return")
	}

	// b2 should now be closed by Proxy; a Write must fail.
	if _, err := b2.Write([]byte("x")); err == nil {
		t.Error("expected write to closed b2 to fail, but it succeeded")
	}
}

// TestProxy_NoLeakManyConnections runs many short-lived proxies; under -race and
// with a goroutine-count check this surfaces leaks from the teardown path.
func TestProxy_NoLeakManyConnections(t *testing.T) {
	for i := 0; i < 100; i++ {
		end1, a := net.Pipe()
		b, end2 := net.Pipe()
		var x atomic.Uint64
		ma := NewMeasuredConn(a, &x, &x)
		mb := NewMeasuredConn(b, &x, &x)

		done := make(chan struct{})
		go func() { Proxy(ma, mb); close(done) }()
		end1.Close()
		end2.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: Proxy did not return", i)
		}
	}
}
