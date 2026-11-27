// itter-relay stores and forwards encrypted DMs. It never sees plaintext.
//
//	itter-relay                          production: Supabase (SUPABASE_URL, SUPABASE_KEY)
//	itter-relay -mem -users users.txt    self-contained relay for local testing
//	itter-relay -release <username>      operator: free an account whose owner lost
//	                                     both the device and the recovery code
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"itter-cli/internal/server"
)

func main() {
	_ = godotenv.Load()
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	mem := flag.Bool("mem", false, "keep everything in memory (local testing, no Supabase)")
	users := flag.String("users", "", "with -mem: file of `username <authorized_keys line>` entries")
	ipHeader := flag.String("client-ip-header", os.Getenv("ITTER_CLIENT_IP_HEADER"),
		"header a trusted reverse proxy sets to the client address (e.g. Fly-Client-IP); rate limits use it")
	proxyProto := flag.Bool("proxy-protocol", os.Getenv("ITTER_PROXY_PROTOCOL") == "1",
		"expect a PROXY protocol line on every connection: for a relay behind itter's SSH app (listen on 127.0.0.1 only)")
	release := flag.String("release", "", "remove this user's DM identity and exit (operator recovery)")
	flag.Parse()

	var store server.Store
	if *mem {
		ms := server.NewMemStore()
		if *users != "" {
			if err := loadUsers(ms, *users); err != nil {
				log.Fatalf("users file: %v", err)
			}
		}
		log.Printf("in-memory store with users: %v", ms.Usernames())
		store = ms
	} else {
		st, err := server.NewSupabaseStore()
		if err != nil {
			log.Fatalf("relay init failed: %v (use -mem for a local relay)", err)
		}
		store = st
	}

	if *release != "" {
		if err := server.ReleaseIdentity(store, *release); err != nil {
			log.Fatalf("release %s: %v", *release, err)
		}
		fmt.Printf("DM identity of @%s removed. They can run `itter setup` again.\n", *release)
		return
	}

	opt := server.Options{ClientIPHeader: *ipHeader, ProxyProtocol: *proxyProto}
	if k := os.Getenv("ITTER_TOKEN_KEY"); k != "" {
		key, err := hex.DecodeString(k)
		if err != nil || len(key) < 32 {
			log.Fatal("ITTER_TOKEN_KEY must be at least 64 hex characters (openssl rand -hex 32)")
		}
		opt.TokenKey = key
	} else {
		log.Print("ITTER_TOKEN_KEY is not set: sessions end when this process does, and every client opens a new one afterwards")
	}
	if *proxyProto {
		if host, _, err := net.SplitHostPort(*addr); err != nil || !isLoopback(host) {
			log.Printf("WARNING: -proxy-protocol trusts whoever connects to say where a client comes from; %s is not a loopback address", *addr)
		}
		log.Print("expecting PROXY protocol lines: reachable through itter's SSH app only")
	} else if *ipHeader == "" && !*mem {
		log.Print("note: no -client-ip-header set; behind a reverse proxy all clients share one rate limit")
	}
	log.Fatal(server.Run(*addr, store, opt))
}

func loadUsers(ms *server.MemStore, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, key, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		ms.AddUser(user, strings.TrimSpace(key))
	}
	return sc.Err()
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
