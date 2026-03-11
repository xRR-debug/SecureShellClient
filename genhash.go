// Утилита для генерации bcrypt-хэша пароля.
// Запуск: go run tools/genhash/main.go

package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	password := "yourpassword" // замените на свой пароль

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Password : %s\n", password)
	fmt.Printf("Bcrypt   : %s\n", hash)
	fmt.Println("\nВставьте строку Bcrypt в PasswordHash в cmd/server/main.go")
}
