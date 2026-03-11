package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/bcrypt"
	"os/exec"
)

const (
	CertFile = "cert.pem"
	KeyFile  = "key.pem"
	Port     = ":8443"

	// Сгенерировать хэш: htpasswd -bnBC 10 "" yourpassword | tr -d ':\n'
	// Или запустить: go run genhash/main.go
	Username     = "admin"
	PasswordHash = "$2a$10$IwHbmaRzrjshYRvtl76Gr.yBB65fRkkb/P81KS0pD9nJ.vKVfE1Q6"  //admin

	maxFailedAttempts = 5
	banDuration       = 5 * time.Minute
	authDelay         = 500 * time.Millisecond // задержка при неверном пароле
)

// --- Rate Limiter ---

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
}

type rateLimitEntry struct {
	failures  int
	bannedUntil time.Time
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{entries: make(map[string]*rateLimitEntry)}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) isBanned(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		return false
	}
	return time.Now().Before(e.bannedUntil)
}

func (rl *rateLimiter) recordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		e = &rateLimitEntry{}
		rl.entries[ip] = e
	}
	e.failures++
	if e.failures >= maxFailedAttempts {
		e.bannedUntil = time.Now().Add(banDuration)
		log.Printf("[SECURITY] IP %s banned for %v after %d failed attempts", ip, banDuration, e.failures)
	}
}

func (rl *rateLimiter) recordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.entries, ip)
}

// Периодически чистим старые записи
func (rl *rateLimiter) cleanup() {
	for range time.Tick(10 * time.Minute) {
		rl.mu.Lock()
		for ip, e := range rl.entries {
			if e.failures < maxFailedAttempts && time.Now().After(e.bannedUntil.Add(banDuration)) {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// --- Main ---

var limiter = newRateLimiter()

func main() {
	log.SetOutput(os.Stdout)

	cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Fatal("[FATAL] Failed to load TLS certificate:", err)
	}

	ln, err := tls.Listen("tcp", Port, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		log.Fatal("[FATAL]", err)
	}
	log.Println("[SERVER] TLS server running on", Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("[ERROR] Accept:", err)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Println("[ERROR] Failed to cast to *tls.Conn")
			conn.Close()
			continue
		}

		go handleConnection(tlsConn)
	}
}

func handleConnection(conn *tls.Conn) {
	defer conn.Close()

	// Получаем только IP без порта для rate limiting
	remoteIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		remoteIP = conn.RemoteAddr().String()
	}

	log.Printf("[CONN] Client connected: %s", conn.RemoteAddr())

	// Проверяем бан
	if limiter.isBanned(remoteIP) {
		log.Printf("[SECURITY] Rejected banned IP: %s", remoteIP)
		fmt.Fprintln(conn, "Too many failed attempts. Try again later.")
		return
	}

	reader := bufio.NewReader(conn)

	// Аутентификация
	fmt.Fprint(conn, "Login: ")
	login, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ERROR] Failed to read login from %s: %v", remoteIP, err)
		return
	}
	login = strings.TrimSpace(login)

	fmt.Fprint(conn, "Password: ")
	pass, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[ERROR] Failed to read password from %s: %v", remoteIP, err)
		return
	}
	pass = strings.TrimSpace(pass)

	// Сравниваем логин и bcrypt-хэш пароля
	loginOK := login == Username
	hashErr := bcrypt.CompareHashAndPassword([]byte(PasswordHash), []byte(pass))

	if !loginOK || hashErr != nil {
		// Искусственная задержка — защита от timing-атак и брутфорса
		time.Sleep(authDelay)
		fmt.Fprintln(conn, "auth failed")
		log.Printf("[AUTH] FAILED: Invalid credentials from %s", remoteIP)
		limiter.recordFailure(remoteIP)
		return
	}

	limiter.recordSuccess(remoteIP)
	fmt.Fprintln(conn, "auth ok")
	log.Printf("[AUTH] SUCCESS: %s authenticated from %s", login, remoteIP)

	// Запускаем shell
	// TERM=vt100 — Windows Telnet понимает только базовый терминал
	// PS1 без escape-цветов — иначе мусор в Telnet
	cmd := exec.Command("bash", "--norc", "--noprofile")
	cmd.Env = []string{
		"HOME=/root",
		"USER=root",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=vt100",
		"PS1=[\\w]$ ",
		"HISTFILE=/dev/null",
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("[ERROR] Failed to start shell for %s: %v", remoteIP, err)
		return
	}
	defer func() {
		ptmx.Close()
		log.Printf("[DISCONN] Session ended for %s", remoteIP)
	}()

	// Shell -> Client
	go func() { _, _ = io.Copy(conn, ptmx) }()
	// Client -> Shell
	_, _ = io.Copy(ptmx, conn)
}
