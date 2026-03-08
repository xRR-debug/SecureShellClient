package main

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"
)

const (
	ProgramName = "SecureShellClient"
	Version     = "0.0.3a"
	serverAddr  = "yourip:8443" //your server ip:port
	localPort   = "1337" //local telnet port
)

func waitProxyReady() {
	log.Printf("[%s] Status: Checking local port %s...", ProgramName, localPort)
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+localPort, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func openShellWindow() {
	waitProxyReady()
	log.Printf("[%s] Success: Proxy is ready. Opening Telnet window...", ProgramName)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "start", "/WAIT", "telnet.exe", "127.0.0.1", localPort)
	} else {
		cmd = exec.Command("xterm", "-u8", "-e", "telnet", "127.0.0.1", localPort)
	}
	
	err := cmd.Run()
	if err != nil {
		log.Printf("[ERROR] Terminal window was closed or failed: %v", err)
	}

	log.Printf("[%s] Event: Telnet window closed by user.", ProgramName)
	log.Printf("[%s] Status: Shutting down main process...", ProgramName)
	
	time.Sleep(2 * time.Second)
	log.Println("Goodbye!")
	os.Exit(0) 
}

func handleClient(local net.Conn) {
	remoteAddr := local.RemoteAddr().String()
	log.Printf("[CONN] New local session initiated from %s", remoteAddr)
	defer local.Close()

	log.Printf("[PROXY] Connecting to remote server: %s", serverAddr)
	remote, err := tls.Dial("tcp", serverAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("[ERROR] Remote TLS connection failed: %v", err)
		return
	}
	log.Printf("[PROXY] TLS Tunnel established. Waiting for credentials in Telnet window...")
	defer remote.Close()

	done := make(chan bool, 2)

	// Server -> Telnet 
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				break
			}
			_, _ = local.Write(buf[:n])

			if bytes.Contains(buf[:n], []byte("auth ok")) {
				log.Printf("[AUTH] SUCCESS: Session started for %s", remoteAddr)
				time.Sleep(150 * time.Millisecond)
				// Telnet Handshake fix
				_, _ = local.Write([]byte{255, 251, 1, 255, 251, 3, 255, 254, 34})
			} else if bytes.Contains(buf[:n], []byte("auth failed")) {
				log.Printf("[AUTH] FAILED: Invalid credentials from %s", remoteAddr)
			}
		}
		done <- true
	}()

	// Telnet -> Server
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := local.Read(buf)
			if err != nil {
				break
			}
			// Windows Telnet fix
			data := bytes.ReplaceAll(buf[:n], []byte{0}, []byte{})
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
			data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))

			_, err = remote.Write(data)
			if err != nil {
				break
			}
		}
		done <- true
	}()

	<-done
	log.Printf("[DISCONN] Local session for %s terminated.", remoteAddr)
}

func main() {
	log.SetOutput(os.Stdout)
	log.Printf("========================================")
	log.Printf("  %s v%s", ProgramName, Version)
	log.Printf("  System: %s (%s)", runtime.GOOS, runtime.GOARCH)
	log.Printf("  Target: %s", serverAddr)
	log.Printf("========================================")

	l, err := net.Listen("tcp", "127.0.0.1:"+localPort)
	if err != nil {
		log.Fatalf("[FATAL] Could not start local listener: %v", err)
	}
	log.Printf("[%s] Listening on 127.0.0.1:%s", ProgramName, localPort)

	go openShellWindow()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("[ERROR] Accept error: %v", err)
			continue
		}
		go handleClient(conn)
	}
}
