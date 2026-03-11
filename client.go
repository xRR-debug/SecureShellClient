package main

import (
	"fmt"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const (
	ProgramName = "SecureShellClient"
	Version     = "0.0.5"
	serverAddr  = "yourip:8443" // ваш сервер ip:port
	localPort   = "1337"
	caCertFile  = "cert.pem"
)

// Telnet IAC-команды
const (
	telnetIAC  = 255
	telnetWILL = 251
	telnetDONT = 254
	telnetEcho = 1
	telnetSGA  = 3  // Suppress Go Ahead
	telnetLM   = 34 // Linemode
)

var telnetHandshake = []byte{
	telnetIAC, telnetWILL, telnetSGA,
	telnetIAC, telnetWILL, telnetEcho,
	telnetIAC, telnetDONT, telnetLM,
}

func loadTLSConfig() (*tls.Config, error) {
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		log.Printf("[WARN] Could not parse CA cert from %s — falling back to system pool", caCertFile)
		pool, _ = x509.SystemCertPool()
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// waitForServer пытается подключиться к серверу в течение 60 секунд,
// логируя каждую неудачную попытку
func waitForServer(tlsConfig *tls.Config) error {
	deadline := time.Now().Add(60 * time.Second)
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp",
			serverAddr,
			tlsConfig,
		)
		if err == nil {
			conn.Close()
			log.Printf("[%s] Server reachable after %d attempt(s).", ProgramName, attempt)
			return nil
		}

		remaining := time.Until(deadline).Round(time.Second)
		log.Printf("[WAIT] Attempt %d: server unavailable (%v). Retrying... (%v left)", attempt, err, remaining)
		time.Sleep(3 * time.Second)
	}

	return fmt.Errorf("server %s did not respond within 60 seconds", serverAddr)
}

// openTelnetWindow открывает Telnet окно
func openTelnetWindow(quit chan<- struct{}) {
	log.Printf("[%s] Opening Telnet window...", ProgramName)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "start", "/WAIT", "telnet.exe", "127.0.0.1", localPort)
	} else {
		cmd = exec.Command("xterm", "-u8", "-e", "telnet", "127.0.0.1", localPort)
	}

	if err := cmd.Run(); err != nil {
		log.Printf("[ERROR] Terminal window error: %v", err)
	}

	log.Printf("[%s] Telnet window closed. Shutting down...", ProgramName)
	time.Sleep(500 * time.Millisecond)
	quit <- struct{}{}
}

func handleClient(local net.Conn, tlsConfig *tls.Config) {
	remoteAddr := local.RemoteAddr().String()
	log.Printf("[CONN] Telnet connected from %s", remoteAddr)
	defer local.Close()

	log.Printf("[PROXY] Connecting to server %s...", serverAddr)
	remote, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Printf("[ERROR] TLS connection failed: %v", err)
		// Сообщаем пользователю прямо в Telnet окно
		_, _ = local.Write([]byte("\r\nERROR: Cannot connect to server: " + err.Error() + "\r\n"))
		return
	}
	log.Printf("[PROXY] TLS tunnel established successfully.")
	defer remote.Close()

	done := make(chan struct{}, 2)

	// Server -> Telnet
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				break
			}
			_, _ = local.Write(buf[:n])

			if bytes.Contains(buf[:n], []byte("auth ok")) {
				log.Printf("[AUTH] SUCCESS for %s", remoteAddr)
				// Ждём пока Telnet обработает текст auth ok
				time.Sleep(300 * time.Millisecond)
				// Отправляем telnet handshake
				_, _ = local.Write(telnetHandshake)
				// Очищаем экран от мусора и переходим на новую строку
				time.Sleep(100 * time.Millisecond)
				_, _ = local.Write([]byte("\r\n"))
			} else if bytes.Contains(buf[:n], []byte("auth failed")) {
				log.Printf("[AUTH] FAILED for %s", remoteAddr)
			}
		}
	}()

	// Telnet -> Server
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := local.Read(buf)
			if err != nil {
				break
			}
			// Windows Telnet fix — нормализация переводов строк
			data := bytes.ReplaceAll(buf[:n], []byte{0}, []byte{})
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
			data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))

			if _, err = remote.Write(data); err != nil {
				break
			}
		}
	}()

	<-done
	<-done
	log.Printf("[DISCONN] Session for %s terminated.", remoteAddr)
}

func main() {
	log.SetOutput(os.Stdout)
	log.Printf("========================================")
	log.Printf("  %s v%s", ProgramName, Version)
	log.Printf("  System: %s/%s", runtime.GOOS, runtime.GOARCH)
	log.Printf("  Target: %s", serverAddr)
	log.Printf("========================================")

	tlsConfig, err := loadTLSConfig()
	if err != nil {
		log.Fatalf("[FATAL] Could not load TLS config: %v", err)
	}

	// Ждём доступности сервера до 60 секунд
	log.Printf("[%s] Waiting for server %s...", ProgramName, serverAddr)
	if err := waitForServer(tlsConfig); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:"+localPort)
	if err != nil {
		log.Fatalf("[FATAL] Could not start local listener: %v", err)
	}
	defer l.Close()
	log.Printf("[%s] Local proxy on 127.0.0.1:%s", ProgramName, localPort)

	quit := make(chan struct{}, 1)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, tlsConfig)
		}
	}()

	// Открываем Telnet только после того как убедились что сервер доступен
	go openTelnetWindow(quit)

	select {
	case <-quit:
		log.Println("Goodbye!")
	case s := <-sig:
		log.Printf("Received signal %v. Goodbye!", s)
	}
}
