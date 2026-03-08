package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"

	"github.com/creack/pty"
)

const (
	CertFile = "cert.pem"
	KeyFile  = "key.pem"
	Port     = ":8443"

	Username = "admin"
	Password = "admin"
)

func main() {
	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Fatal("failed to load TLS certificate:", err)
	}

	ln, err := tls.Listen("tcp", Port, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TLS server running on", Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Println("failed to cast to *tls.Conn")
			conn.Close()
			continue
		}

		go handleConnection(tlsConn)
	}
}

func handleConnection(conn *tls.Conn) {
	defer conn.Close()
	log.Println("client connected:", conn.RemoteAddr())

	reader := bufio.NewReader(conn)

	// Auth
	fmt.Fprint(conn, "Login: ")
	login, _ := reader.ReadString('\n')
	login = strings.TrimSpace(login)

	fmt.Fprint(conn, "Password: ")
	pass, _ := reader.ReadString('\n')
	pass = strings.TrimSpace(pass)

	if login != Username || pass != Password {
		fmt.Fprintln(conn, "auth failed")
		log.Println("auth failed:", conn.RemoteAddr())
		return
	}

	fmt.Fprintln(conn, "auth ok")
	log.Println("auth success:", conn.RemoteAddr())

	cmd := exec.Command("bash")
	// fix symbols
	cmd.Env = append(cmd.Env, "PS1=\\u@\\h:\\w$ ")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Println("failed to start shell:", err)
		return
	}
	defer ptmx.Close()

	// Shell -> Client
	go func() { _, _ = io.Copy(conn, ptmx) }() 
	_, _ = io.Copy(ptmx, conn)               
}