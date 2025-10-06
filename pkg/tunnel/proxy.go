package tunnel

import (
	"io"
)

// Proxy handles bidirectional data copying between two measured connections.
func Proxy(a, b *MeasuredConn) {
	done := make(chan struct{}, 1)

	go func() {
		if _, err := io.Copy(a, b); err != nil {
			if err != io.EOF {
				// log.Printf("Error copying from B to A: %v", err)
			}
		}
		a.Close()
		b.Close()
		done <- struct{}{}
	}()

	go func() {
		if _, err := io.Copy(b, a); err != nil {
			if err != io.EOF {
				// log.Printf("Error copying from A to B: %v", err)
			}
		}
		a.Close()
		b.Close()
		done <- struct{}{}
	}()

	<-done
}
