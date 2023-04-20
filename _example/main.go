package main

import (
	"log"

	"github.com/ferama/go-socks"
)

func main() {
	conf := &socks.Config{}
	server, err := socks.New(conf)
	if err != nil {
		panic(err)
	}

	addr := "127.0.0.1:1080"
	log.Printf("starting local socks server at '%s'", addr)
	// Create SOCKS proxy on localhost port 1080
	// Test with curl:
	//		curl -x socks5://127.0.0.1:1080 http://ifconfig.co/json
	//		curl -x socks4://127.0.0.1:1080 http://ifconfig.co/json
	if err := server.ListenAndServe("tcp", addr); err != nil {
		panic(err)
	}
}
