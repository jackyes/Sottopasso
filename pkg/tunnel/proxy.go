package tunnel

import (
	"io"
	"sync"
)

// Proxy handles bidirectional data copying between two measured connections.
//
// When one direction reaches EOF, only the write side of its destination is
// closed (half-close) so data still in flight in the opposite direction is not
// truncated — e.g. a peer that shuts down its write side after sending a
// request must still receive the full response. Both connections are fully
// closed once both directions have finished.
func Proxy(a, b *MeasuredConn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDirection := func(dst, src *MeasuredConn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			if err != io.EOF {
				// log.Printf("Error copying: %v", err)
			}
		}
		// Propagate EOF to the destination's peer without tearing down the
		// reverse direction.
		dst.CloseWrite()
	}

	go copyDirection(a, b)
	go copyDirection(b, a)

	wg.Wait()
	a.Close()
	b.Close()
}
