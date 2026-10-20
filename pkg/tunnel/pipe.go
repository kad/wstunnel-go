package tunnel

import (
	"io"
	"net"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// Pipe pipes data between a TCP connection and a WebSocket connection.
// It closes both connections when done.
func Pipe(tcpConn net.Conn, wsConn *wst.Conn) {
	PipeLive(tcpConn, wsConn, nil)
}

// PipeLive is Pipe that reports to a watchdog (see WatchWst). The frame hook
// installed there sees what arrives; l carries the time the pipe spends blocked
// writing to tcpConn, which must not count against the peer.
func PipeLive(tcpConn net.Conn, wsConn *wst.Conn, l *Liveness) {
	var wg sync.WaitGroup
	wg.Add(2)

	// TCP -> WebSocket
	go func() {
		defer wg.Done()
		defer func() {
			_ = wsConn.WriteMessage(wst.CloseMessage, wst.FormatCloseMessage(wst.CloseNormalClosure, ""))
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := tcpConn.Read(buf)
			if n > 0 {
				err = wsConn.WriteMessage(wst.BinaryMessage, buf[:n])
				if err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket -> TCP
	go func() {
		defer wg.Done()
		defer func() { _ = tcpConn.Close() }()
		for {
			messageType, p, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if messageType == wst.BinaryMessage || messageType == wst.TextMessage {
				_, err = l.writer(tcpConn).Write(p)
				if err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
}

// PipeGorilla pipes data between a TCP connection and a Gorilla WebSocket connection.
func PipeGorilla(tcpConn net.Conn, wsConn *websocket.Conn) {
	PipeGorillaLive(tcpConn, wsConn, nil)
}

// PipeGorillaLive is PipeGorilla that reports to a watchdog (see WatchGorilla).
// A message is forwarded as it arrives rather than after it is complete, so a
// long fragmented message keeps the peer alive while it streams in, and time
// spent blocked writing to tcpConn is not held against the peer.
func PipeGorillaLive(tcpConn net.Conn, wsConn *websocket.Conn, l *Liveness) {
	var wg sync.WaitGroup
	wg.Add(2)

	// TCP -> WebSocket
	go func() {
		defer wg.Done()
		defer func() {
			_ = wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := tcpConn.Read(buf)
			if n > 0 {
				err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
				if err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket -> TCP
	go func() {
		defer wg.Done()
		defer func() { _ = tcpConn.Close() }()
		gorillaToWriter(wsConn, tcpConn, l)
	}()

	wg.Wait()
}

// gorillaToWriter forwards data messages from wsConn to dst until the
// connection or dst fails. gorilla answers control frames itself while reading.
//
// A byte stream is copied as the message arrives. A packet destination, such as
// the UDP socket of a UDP tunnel, gets exactly one Write per message, even an
// empty one, because each Write is a datagram; the message is read whole first,
// as before, with the read still reporting progress to the watchdog.
func gorillaToWriter(wsConn *websocket.Conn, dst io.Writer, l *Liveness) {
	_, packet := dst.(net.PacketConn)
	// One buffer for the whole pipe. The wrappers below hide WriterTo and
	// ReaderFrom, so io.CopyBuffer really uses it; io.Copy would allocate 32 KiB
	// for every message, even a one byte one.
	buf := make([]byte, 32*1024)
	for {
		messageType, r, err := wsConn.NextReader()
		if err != nil {
			return
		}
		l.Touch()
		if messageType != websocket.BinaryMessage && messageType != websocket.TextMessage {
			continue
		}
		if packet {
			p, err := io.ReadAll(l.reader(r))
			if err != nil {
				return
			}
			if _, err := l.writer(dst).Write(p); err != nil {
				return
			}
			continue
		}
		w := struct{ io.Writer }{l.writer(dst)}
		rd := struct{ io.Reader }{l.reader(r)}
		if _, err := io.CopyBuffer(w, rd, buf); err != nil {
			return
		}
	}
}

// PipeRW pipes data between a ReadWriteCloser and a WebSocket connection.
func PipeRW(rw io.ReadWriteCloser, wsConn *wst.Conn) {
	PipeRWLive(rw, wsConn, nil)
}

// PipeRWLive is PipeRW that reports to a watchdog, like PipeLive.
func PipeRWLive(rw io.ReadWriteCloser, wsConn *wst.Conn, l *Liveness) {
	var wg sync.WaitGroup
	wg.Add(2)

	// RW -> WebSocket
	go func() {
		defer wg.Done()
		defer func() {
			_ = wsConn.WriteMessage(wst.CloseMessage, wst.FormatCloseMessage(wst.CloseNormalClosure, ""))
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := rw.Read(buf)
			if n > 0 {
				err = wsConn.WriteMessage(wst.BinaryMessage, buf[:n])
				if err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket -> RW
	go func() {
		defer wg.Done()
		defer func() { _ = rw.Close() }()
		for {
			messageType, p, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if messageType == wst.BinaryMessage || messageType == wst.TextMessage {
				_, err = l.writer(rw).Write(p)
				if err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
}

// PipeGorillaRW pipes data between a ReadWriteCloser and a Gorilla WebSocket connection.
func PipeGorillaRW(rw io.ReadWriteCloser, wsConn *websocket.Conn) {
	PipeGorillaRWLive(rw, wsConn, nil)
}

// PipeGorillaRWLive is PipeGorillaRW that reports to a watchdog, like PipeGorillaLive.
func PipeGorillaRWLive(rw io.ReadWriteCloser, wsConn *websocket.Conn, l *Liveness) {
	var wg sync.WaitGroup
	wg.Add(2)

	// RW -> WebSocket
	go func() {
		defer wg.Done()
		defer func() {
			_ = wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := rw.Read(buf)
			if n > 0 {
				err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
				if err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WebSocket -> RW
	go func() {
		defer wg.Done()
		defer func() { _ = rw.Close() }()
		gorillaToWriter(wsConn, rw, l)
	}()

	wg.Wait()
}

// PipeBiDir pipes data between two ReadWriteCloser objects.
func PipeBiDir(rwc1, rwc2 io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	// rwc1 -> rwc2
	go func() {
		defer wg.Done()
		defer func() { _ = rwc1.Close() }()
		defer func() { _ = rwc2.Close() }()
		_, _ = io.Copy(rwc2, rwc1)
	}()

	// rwc2 -> rwc1
	go func() {
		defer wg.Done()
		defer func() { _ = rwc1.Close() }()
		defer func() { _ = rwc2.Close() }()
		_, _ = io.Copy(rwc1, rwc2)
	}()

	wg.Wait()
}

// PipeUDP preserves UDP packet boundaries while forwarding to a framed stream.
func PipeUDP(conn net.Conn, stream *protocol.FramedUDPReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer func() { _ = conn.Close() }()
		defer func() { _ = stream.Close() }()

		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer func() { _ = conn.Close() }()
		defer func() { _ = stream.Close() }()

		for {
			packet, err := stream.ReadPacket()
			if err != nil {
				return
			}
			if _, err := conn.Write(packet); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}
