package tunnel

import (
	"Sottopasso/pkg/pool"
	"io"
	"time"
)

// Proxy handles bidirectional data copying between two measured connections.
func Proxy(a, b *MeasuredConn) {
	done := make(chan struct{}, 2)

	go func() {
		if _, err := BufferedCopy(a, b, 30*time.Second, 30*time.Second); err != nil {
			if err != io.EOF {
				// log.Printf("Error copying from B to A: %v", err)
			}
		}
		done <- struct{}{}
	}()

	go func() {
		if _, err := BufferedCopy(b, a, 30*time.Second, 30*time.Second); err != nil {
			if err != io.EOF {
				// log.Printf("Error copying from A to B: %v", err)
			}
		}
		done <- struct{}{}
	}()

	// Wait for both directions to complete
	<-done
	<-done

	// Close connections only after both directions are done
	a.Close()
	b.Close()
}

// BufferedCopy performs a buffered copy between two connections with deadlines
func BufferedCopy(dst, src *MeasuredConn, readTimeout, writeTimeout time.Duration) (written int64, err error) {
	bufferPool := pool.GetGlobalBufferPool()
	buf := bufferPool.GetLarge()
	defer bufferPool.PutLarge(buf)

	for {
		// Set read deadline
		src.SetReadDeadline(time.Now().Add(readTimeout))

		nr, er := src.Read(buf)
		if nr > 0 {
			// Set write deadline
			dst.SetWriteDeadline(time.Now().Add(writeTimeout))

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}
