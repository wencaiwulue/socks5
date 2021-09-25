package socks5

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
)

/*
   +----+----------+----------+
   |VER | NMETHODS | METHODS  |
   +----+----------+----------+
   | 1  |    1     | 1 to 255 |
   +----+----------+----------+
*/
type NegotiationRequest struct {
	VER      byte
	NMETHODS byte
	METHODS  []byte
}

/*
   +----+--------+
   |VER | METHOD |
   +----+--------+
   | 1  |   1    |
   +----+--------+
*/
type NegotiationReply struct {
	VER    byte
	METHOD byte
}

func (n NegotiationReply) ToBytes() []byte {
	return []byte{n.VER, n.METHOD}
}

/*
   +----+------+----------+------+----------+
   |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
   +----+------+----------+------+----------+
   | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
   +----+------+----------+------+----------+
*/
type UsernamePasswordSubnegotiation struct {
	VER    byte
	ULEN   byte
	UNAME  []byte
	PLEN   byte
	PASSWD []byte
}

/*
   +----+--------+
   |VER | STATUS |
   +----+--------+
   | 1  |   1    |
   +----+--------+
*/
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
	if r.ATYP == AddrTypeFQDN {
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
