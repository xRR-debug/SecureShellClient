# SecureShellClient

TLS-туннель для удалённого доступа к shell через Telnet-клиент.

## Структура проекта

```
.
├
├── client.go   # Клиент (запускается на стороне пользователя)
├── server.go   # Сервер (запускается на удалённой машине)
├── genhash.go  # Утилита генерации bcrypt-хэша пароля
├── go.mod
└── go.sum
```

## Первоначальная настройка

### 1. Генерация TLS-сертификата

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=yourip"
```

Положите `cert.pem` и `key.pem` рядом с бинарником сервера.
Положите `cert.pem` рядом с бинарником клиента (для проверки сертификата).

### 2. Установка пароля

```bash
go run genhash.go
```

Скопируйте вывод в константу `PasswordHash` в `server.go`.

### 3. Адрес сервера

В `client.go` замените:
```go
serverAddr = "yourip:8443"
```

## Сборка

```bash
# Сервер (Linux)
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o server server.go

# Клиент
go build -o client client.go              # Linux

$env:GOOS=""; $env:GOARCH=""
go build -o client.exe client.go  # Windows
```

