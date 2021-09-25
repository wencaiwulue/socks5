// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socks5

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"
)

var network = "tcp4"
var address = "127.0.0.1:1080"

func setupServer() {
	listener, err := net.Listen(network, address)
	if err != nil {
		log.Fatal(err)
	}
	server := Server{Listener: listener}
	go server.Serve(DefaultHandler)
	time.Sleep(time.Second * 2)
}

func TestConnect(t *testing.T) {
	setupServer()
	socks5, err := SOCKS5(network, address, &UsernamePassword{
		Username: "aa",
		Password: "bbb",
	})
	t2 := &http.Transport{}
	t2.Dial = socks5.Dial
	t2.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks5.DialContext(ctx, network, addr)
	}
	//t2.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
	//	return socks5.DialContext(ctx, network, addr)
	//}
	client := http.Client{Transport: t2}
	response, err := client.Get("http://www.baidu.com")
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	bytes, _ := io.ReadAll(response.Body)
	fmt.Println(string(bytes[:]))
}

func TestBind(t *testing.T) {
	setupServer()
	u := UsernamePassword{
		Username: "aa",
		Password: "bbb",
	}
	d := &Dialer{
		ProxyNetwork: network,
		ProxyAddress: address,
		Cmd:          CmdBind,
		AuthMethods: []AuthMethod{
			AuthMethodNotRequired,
			AuthMethodUsernamePassword,
		},
		Authenticate: u.Authenticate,
	}

	conn, err := d.Dial("tcp", "8.8.8.8:53")
	if err != nil {
		log.Fatal(err)
	}
	b, err := hex.DecodeString("0001010000010000000000000a74787468696e6b696e6703636f6d0000010001")
	if err != nil {
		panic(err)
	}
	if _, err := conn.Write(b); err != nil {
		panic(err)
	}
	b = make([]byte, 2048)
	n, err := conn.Read(b)
	if err != nil {
		panic(err)
	}
	b = b[:n]
	b = b[len(b)-4:]
	log.Println(net.IPv4(b[0], b[1], b[2], b[3]))

}
func TestBind2(t *testing.T) {
	setupServer()
	u := UsernamePassword{
		Username: "aa",
		Password: "bbb",
	}
	d := &Dialer{
		ProxyNetwork: "tcp4",
		ProxyAddress: "127.0.0.1:1080",
		Cmd:          CmdBind,
		AuthMethods: []AuthMethod{
			AuthMethodNotRequired,
			AuthMethodUsernamePassword,
		},
		Authenticate: u.Authenticate,
	}

	conn, err := d.DialContext(context.TODO(), "tcp", "127.0.0.1:80")
	if err != nil {
		log.Fatal(err)
	}
	conn.Write([]byte("hello"))

	bytes, err := io.ReadAll(conn)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bytes))
}
