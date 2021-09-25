package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

type Server struct {
	Listener net.Listener
}

func (s *Server) Serve(h Handler) error {
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

func (s *Server) Close() error {
	return s.Listener.Close()
}

var (
	// DefaultHandler is the default server handler.
	DefaultHandler Handler
)

func init() {
	DefaultHandler = &serverHandler{
		AuthMethods: AuthMethodUsernamePassword,
		Authenticate: func(username, password string) error {
			log.Printf("username: %s, password: %s", username, password)
			return nil
		},
	}
}

// Handler is interface for server handler.
type Handler interface {
	HandleConnection(conn net.Conn) error
}

type serverHandler struct {
	AuthMethods  AuthMethod
	Authenticate func(username, password string) error
}

func parseNegotiationRequest(conn net.Conn) (*NegotiationRequest, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	bytes := make([]byte, buf[1])
	_, err = io.ReadFull(conn, bytes)
	if err != nil {
		return nil, err
	}
	return &NegotiationRequest{
		VER:      buf[0],
		NMETHODS: buf[1],
		METHODS:  bytes,
	}, nil
}

func (h *serverHandler) Negotiation(conn net.Conn) error {
	request, err := parseNegotiationRequest(conn)
	if err != nil {
		return err
	}
	if !AssertVersion(request.VER) {
		return errors.New("")
	}
	found := false
	for _, method := range request.METHODS {
		if h.AuthMethods == AuthMethod(method) {
			found = true
			break
		}
	}
	if !found {
		_, _ = conn.Write(NegotiationReply{VER: Version5, METHOD: byte(AuthMethodNoAcceptableMethods)}.ToBytes())
		return errors.New("")
	}

	_, _ = conn.Write(NegotiationReply{VER: Version5, METHOD: byte(h.AuthMethods)}.ToBytes())
	return nil
}

func (h serverHandler) Auth(conn net.Conn) error {
	if h.AuthMethods == AuthMethodNotRequired {
		return nil
	}
	bytes := make([]byte, 2)
	_, err := io.ReadFull(conn, bytes)
	if err != nil {
		return err
	}
	i := make([]byte, bytes[1])

	_, err = io.ReadFull(conn, i)
	if err != nil {
		return err
	}
	i3 := make([]byte, 1)
	_, _ = io.ReadFull(conn, i3)
	i2 := make([]byte, i3[0])
	_, _ = io.ReadFull(conn, i2)
	request := UsernamePasswordSubnegotiation{
		VER:    bytes[0],
		ULEN:   bytes[1],
		UNAME:  i,
		PLEN:   i3[0],
		PASSWD: i2,
	}
	err = h.Authenticate(string(request.UNAME), string(request.PASSWD))
	if err != nil {
		_, _ = conn.Write(UsernamePasswordSubnegotiationResponse{VER: AuthUsernamePasswordVersion, STATUS: byte(StatusFailed)}.ToBytes())
		return err
	}
	_, _ = conn.Write(UsernamePasswordSubnegotiationResponse{VER: AuthUsernamePasswordVersion, STATUS: byte(StatusSucceeded)}.ToBytes())
	return nil
}

func AssertVersion(version byte) bool {
	return version == Version5
}

func ParseRequest(conn net.Conn) (*Request, error) {
	bytes := make([]byte, 4)
	_, _ = io.ReadFull(conn, bytes)
	var i []byte
	switch bytes[3] {
	case AddrTypeIPv4:
		i = make([]byte, net.IPv4len)
		_, _ = io.ReadFull(conn, i)
	case AddrTypeFQDN:
		ii := []byte{0}
		_, _ = io.ReadFull(conn, ii)
		i = make([]byte, ii[0])
		_, _ = io.ReadFull(conn, i)
	case AddrTypeIPv6:
		i = make([]byte, net.IPv6len)
		_, _ = io.ReadFull(conn, i)
	default:

	}
	port := make([]byte, 2)
	_, _ = io.ReadFull(conn, port)
	return &Request{
		VER:     bytes[0],
		CMD:     bytes[1],
		RSV:     bytes[2],
		ATYP:    bytes[3],
		DSTADDR: i,
		DSTPORT: port,
	}, nil
}

func (h *serverHandler) HandleConnection(conn net.Conn) error {
	err := h.Negotiation(conn)
	if err != nil {
		return err
	}
	if h.AuthMethods == AuthMethodUsernamePassword {
		if err = h.Auth(conn); err != nil {
			return err
		}
	}

	req, err := ParseRequest(conn)
	if err != nil {
		return err
	}

	switch Command(req.CMD) {
	case CmdConnect:
		return h.handleConnect(conn, req)

	case CmdBind:
		return h.handleBind(conn, req)

	//case socks.CmdUdp:
	//return h.handleUdp(conn, req)

	default:
		return fmt.Errorf("%d: unsupported command", req.CMD)
	}
}

func (h *serverHandler) handleConnect(conn net.Conn, req *Request) error {
	cc, err := net.Dial("tcp", req.Address())
	if err != nil {
		return err
	}
	defer cc.Close()
	addr := cc.LocalAddr().(*net.TCPAddr)
	var ATYP byte
	if addr.IP.To4() != nil {
		ATYP = AddrTypeIPv4
	} else {
		ATYP = AddrTypeIPv6
	}
	addr.IP.To4()
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(addr.Port))
	response := Response{
		VER:     Version5,
		REP:     byte(StatusSucceeded),
		RSV:     req.RSV,
		ATYP:    ATYP,
		BNDADDR: addr.IP,
		BNDPORT: bytes,
	}
	if _, err = conn.Write(response.ToBytes()); err != nil {
		return err
	}
	return transport(conn, cc)
}

func (h *serverHandler) handleBind(conn net.Conn, req *Request) error {
	addr := req.Address()
	bindAddr, _ := net.ResolveTCPAddr("tcp", addr)
	ln, err := net.ListenTCP("tcp", bindAddr) // strict mode: if the port already in use, it will return error
	if err != nil {
		log.Println(err)
		_, _ = conn.Write(Response{VER: Version5, REP: byte(StatusFailed), RSV: 0x0, ATYP: 0}.ToBytes())
		return err
	}

	//socksAddr := toSocksAddr(ln.Addr())
	// Issue: may not reachable when host has multi-interface
	//socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	//reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(ln.Addr().(*net.TCPAddr).Port))
	if _, err = conn.Write(Response{
		VER:     Version5,
		REP:     byte(StatusSucceeded),
		RSV:     req.RSV,
		ATYP:    req.ATYP,
		BNDADDR: ln.Addr().(*net.TCPAddr).IP,
		BNDPORT: bytes,
	}.ToBytes()); err != nil {
		ln.Close()
		return err
	}

	var pconn net.Conn
	accept := func() <-chan error {
		errc := make(chan error, 1)
		go func() {
			defer close(errc)
			defer ln.Close()

			c, err := ln.AcceptTCP()
			if err != nil {
				errc <- err
				return
			}
			pconn = c
		}()

		return errc
	}

	pc1, pc2 := net.Pipe()
	pipe := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer pc1.Close()

			errc <- transport(conn, pc1)
		}()

		return errc
	}

	defer pc2.Close()

	for {
		select {
		case err := <-accept():
			if err != nil || pconn == nil {
				return err
			}
			defer pconn.Close()

			//reply := gosocks5.NewReply(gosocks5.Succeeded, toSocksAddr(pconn.RemoteAddr()))
			remoteAddr := pconn.RemoteAddr().(*net.TCPAddr)
			i := make([]byte, 2)
			binary.BigEndian.PutUint16(i, uint16(remoteAddr.Port))
			r := Response{
				VER:     Version5,
				REP:     byte(StatusSucceeded),
				RSV:     req.RSV,
				ATYP:    req.ATYP,
				BNDADDR: remoteAddr.IP,
				BNDPORT: i,
			}
			if _, err = pc2.Write(r.ToBytes()); err != nil {
				return err
			}

			if err = transport(pc2, pconn); err != nil {
			}

			return err
		case err := <-pipe():
			ln.Close()
			return err
		}
	}
}

func transport(readWriter, writer io.ReadWriter) error {
	errChan := make(chan error, 1)
	go func() {
		_, err := io.Copy(readWriter, writer)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(writer, readWriter)
		errChan <- err
	}()

	err := <-errChan
	//if err != nil && err == io.EOF {
	//	err = nil
	//}
	return err
}

func toSocksAddr(addr net.Addr) *Addr {
	host := "0.0.0.0"
	port := 0
	var ip net.IP
	if addr != nil {
		h, p, _ := net.SplitHostPort(addr.String())
		if ips, err := net.LookupIP(h); err == nil && len(ips) > 0 {
			ip = ips[0]
		}
		host = h
		port, _ = strconv.Atoi(p)
	}
	return &Addr{
		IP:   ip,
		Name: host,
		Port: port,
	}
}
