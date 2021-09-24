package server

import (
	"net"
	"time"
)

type Socks5Server struct {
	Listener net.Listener
}

func (s *Socks5Server) Addr() net.Addr {
	return s.Listener.Addr()
}

func (s *Socks5Server) Serve(h Handler) error {
	for {
		conn, err2 := s.Listener.Accept()
		if err2 != nil {
			if ne, ok := err2.(net.Error); ok && ne.Temporary() {
				time.Sleep(time.Millisecond * 5)
				continue
			}
			return err2
		}
		go h.HandleConnection(conn)
	}
}

func (s *Socks5Server) Close() error {
	return s.Listener.Close()
}
