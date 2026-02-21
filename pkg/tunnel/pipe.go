package tunnel

import (
	"io"
	"net"
	"sync"

	"github.com/gorilla/websocket"
)

// Pipe pipes data between a TCP connection and a WebSocket connection.
// It closes both connections when done.
func Pipe(tcpConn net.Conn, wsConn *websocket.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// TCP -> WebSocket
	go func() {
		defer wg.Done()
		defer func() { _ = wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")) }()
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
func PipeRW(rw io.ReadWriteCloser, wsConn *websocket.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// RW -> WebSocket
	go func() {
		defer wg.Done()
		defer func() { _ = wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")) }()
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
