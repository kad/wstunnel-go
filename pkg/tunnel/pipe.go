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
				_, err = tcpConn.Write(p)
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
		for {
			messageType, p, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if messageType == websocket.BinaryMessage || messageType == websocket.TextMessage {
				_, err = tcpConn.Write(p)
				if err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()
}

// PipeRW pipes data between a ReadWriteCloser and a WebSocket connection.
func PipeRW(rw io.ReadWriteCloser, wsConn *wst.Conn) {
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
				_, err = rw.Write(p)
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
		for {
			messageType, p, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if messageType == websocket.BinaryMessage || messageType == websocket.TextMessage {
				_, err = rw.Write(p)
				if err != nil {
					return
				}
			}
		}
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
