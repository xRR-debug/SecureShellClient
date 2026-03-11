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
go run tools/genhash/main.go
```

Скопируйте вывод в константу `PasswordHash` в `cmd/server/main.go`.

### 3. Адрес сервера

В `cmd/client/main.go` замените:
```go
serverAddr = "yourip:8443"
```

## Сборка

```bash
# Сервер (Linux)
go build -o server ./cmd/server

# Клиент
go build -o client ./cmd/client              # Linux
GOOS=windows go build -o client.exe ./cmd/client  # Windows
```

## Что изменилось в v0.0.4

- Убран InsecureSkipVerify — TLS-сертификат теперь проверяется через CA
- Пароль хранится как bcrypt-хэш
- Rate limiting: бан IP на 5 минут после 5 неверных попыток
- Задержка 500 мс при неверном пароле (защита от брутфорса)
- Исправлена утечка горутины — ждём завершения обеих сторон
- Исправлен cmd.Env — shell получает полное окружение (PATH, HOME и т.д.)
- Telnet IAC-байты вынесены в именованные константы
- os.Exit убран из горутины — корректное завершение через канал
- Обработка SIGTERM / Ctrl+C
