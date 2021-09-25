package socks5

// Wire protocol constants.
const (
	Version5 = 0x05

	AddrTypeIPv4 = 0x01
	AddrTypeFQDN = 0x03
	AddrTypeIPv6 = 0x04

	CmdConnect Command = 0x01 // establishes an active-open forward proxy connection
	CmdBind    Command = 0x02 // establishes a passive-open forward proxy connection
	CmdUdp     Command = 0x03 // establishes an active-open forward proxy connection with udp protocol

	AuthUsernamePasswordVersion              = 0x01 // username password authentication version
	AuthMethodNotRequired         AuthMethod = 0x00 // no authentication required
	AuthMethodUsernamePassword    AuthMethod = 0x02 // use username/password
	AuthMethodNoAcceptableMethods AuthMethod = 0xff // no acceptable authentication methods

	StatusSucceeded Reply = 0x00
	StatusFailed    Reply = 0x01
)
