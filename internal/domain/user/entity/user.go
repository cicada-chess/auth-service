package entity

import (
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string
	Username  string
	Email     string
	Password  string
	Role      int
	Rating    int
	CreatedAt time.Time
	UpdatedAt time.Time
	IsActive  bool
}

func ComparePasswords(password, hash_password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash_password), []byte(password))

	return err == nil
}
