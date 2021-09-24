// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"socks5/socks"
	"testing"
	"time"
)

func TestSer(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:1080")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	server := Socks5Server{Listener: ln}
	go server.Serve(DefaultHandler)
	time.Sleep(time.Second * 2)
	socks5, err := proxy.SOCKS5("tcp4", "127.0.0.1:1080", &proxy.Auth{
		User:     "aa",
		Password: "bbb",
	}, nil)
	t2 := &http.Transport{}
	t2.Dial = socks5.Dial
	t2.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks5.Dial(network,addr)
	}
	t2.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks5.Dial(network,addr)
	}
	client := http.Client{Transport: t2}
	//conn, err := socks5.Dial("tcp4", "www.baidu.com:80")
	//if err != nil {
	//	log.Fatal(err)
	//}
	get, err := client.Get("http://www.baidu.com:80")
	if err!=nil{
		log.Fatal(err)
	}
	all, _ := io.ReadAll(get.Request.Body)
	fmt.Println(string(all))
}

func TestBind(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:1080")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	server := Socks5Server{Listener: ln}
	go server.Serve(DefaultHandler)
	time.Sleep(time.Second * 2)
	//socks5, err := proxy.SOCKS5("tcp4", "127.0.0.1:1080", &proxy.Auth{
	//	User:     "aa",
	//	Password: "bbb",
	//}, nil)
	//d := socks.NewDialer("tcp4", "127.0.0.1:1080")
	d := &socks.Dialer{ProxyNetwork: "tcp4", ProxyAddress: "127.0.0.1:1080", Cmd: socks.CmdBind}
	up := socks.UsernamePassword{
		Username: "aa",
		Password: "bbb",
	}
	d.AuthMethods = []socks.AuthMethod{
		socks.AuthMethodNotRequired,
		socks.AuthMethodUsernamePassword,
	}
	d.Authenticate = up.Authenticate

	conn, err := d.DialContext(context.TODO(), "tcp", "www.baidu.com:80")
	if err != nil {
		log.Fatal(err)
	}
	_, _ = conn.Write([]byte("hello"))
	bytes := make([]byte, 8)
	_, err = io.ReadFull(conn, bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bytes))
}
