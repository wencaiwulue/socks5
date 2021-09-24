package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"socks5/socks"
	"strconv"
)

type NegotiationRequest struct {
	VER      byte
	NMETHODS byte
	METHODS  []byte
}

type NegotiationReply struct {
	VER    byte
	METHOD byte
}

func (n NegotiationReply) ToBytes() []byte {
	return []byte{n.VER, n.METHOD}
}

type UsernamePasswordSubnegotiation struct {
	VER    byte
	ULEN   byte
	UNAME  []byte
	PLEN   byte
	PASSWD []byte
}

type UsernamePasswordSubnegotiationResponse struct {
	VER    byte
	STATUS byte
}

func (r UsernamePasswordSubnegotiationResponse) ToBytes() []byte {
	return []byte{r.VER, r.STATUS}
}

// Request
/*

+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

*/
type Request struct {
	VER     byte
	CMD     byte
	RSV     byte
	ATYP    byte
	DSTADDR []byte
	DSTPORT []byte
}

func (r *Request) Address() string {
	var s string
	if r.ATYP == socks.AddrTypeFQDN {
		s = bytes.NewBuffer(r.DSTADDR).String()
	} else {
		s = net.IP(r.DSTADDR).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.DSTPORT)))
	return net.JoinHostPort(s, p)
}

// Response
/*
   +----+-----+-------+------+----------+----------+
   |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
   +----+-----+-------+------+----------+----------+
   | 1  |  1  | X'00' |  1   | Variable |    2     |
   +----+-----+-------+------+----------+----------+
*/
type Response struct {
	VER     byte
	REP     byte
	RSV     byte
	ATYP    byte
	BNDADDR []byte
	BNDPORT []byte
}

func (r Response) ToBytes() []byte {
	var buffer bytes.Buffer
	buffer.Write([]byte{r.VER})
	buffer.Write([]byte{r.REP})
	buffer.Write([]byte{r.RSV})
	buffer.Write([]byte{r.ATYP})
	buffer.Write(r.BNDADDR)
	buffer.Write(r.BNDPORT)
	return buffer.Bytes()
}
