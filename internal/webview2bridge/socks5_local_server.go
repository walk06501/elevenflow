package webview2bridge

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// localSOCKS5Server is a minimal, no-auth, CONNECT-only SOCKS5 server
// bound to 127.0.0.1 that forwards every connection through a
// caller-supplied dialer.
//
// Exists to bridge an in-process WireGuard tunnel (whose only Go-level
// handle is a netstack DialContext function, not something with a
// dialable network address) into the shape everything else already
// expects: a socks5://host:port Lease.URL that LocalProxy's existing
// dialSOCKS5 can use completely unchanged.
type localSOCKS5Server struct {
	listener net.Listener
	dial     func(network, addr string) (net.Conn, error)
}

// newLocalSOCKS5Server starts listening on 127.0.0.1:0 (OS picks a free
// port) and serves until Close is called.
func newLocalSOCKS5Server(dial func(network, addr string) (net.Conn, error)) (*localSOCKS5Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &localSOCKS5Server{listener: ln, dial: dial}
	go s.serve()
	return s, nil
}

func (s *localSOCKS5Server) Addr() string { return s.listener.Addr().String() }

func (s *localSOCKS5Server) Close() error { return s.listener.Close() }

func (s *localSOCKS5Server) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *localSOCKS5Server) handle(client net.Conn) {
	defer client.Close()

	// Greeting: VER, NMETHODS, METHODS[...] — always accept "no auth".
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHead); err != nil || reqHead[0] != 0x05 {
		return
	}
	if reqHead[1] != 0x01 { // only CONNECT is needed here
		writeSocksReply(client, 0x07) // command not supported
		return
	}

	var host string
	switch reqHead[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03: // domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, lenBuf); err != nil {
			return
		}
		nameBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(client, nameBuf); err != nil {
			return
		}
		host = string(nameBuf)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		writeSocksReply(client, 0x08) // address type not supported
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, fmt.Sprint(port))

	upConn, err := s.dial("tcp", target)
	if err != nil {
		writeSocksReply(client, 0x05) // connection refused
		return
	}
	defer upConn.Close()

	if err := writeSocksReply(client, 0x00); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(upConn, client); done <- struct{}{} }()
	go func() { io.Copy(client, upConn); done <- struct{}{} }()
	<-done
	<-done
}

// writeSocksReply's BND.ADDR/BND.PORT are irrelevant for a CONNECT client
// that only cares about success/failure, so 0.0.0.0:0 is fine here.
func writeSocksReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
