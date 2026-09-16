package main

import (
	"flag"
	"log"

	"itter-cli/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	data := flag.String("data", "itter-relay.json", "state file")
	flag.Parse()
	log.Fatal(server.Run(*addr, *data))
}