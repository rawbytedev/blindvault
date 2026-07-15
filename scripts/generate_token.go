package main

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func m() {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-client",
	})
	tokenString, _ := token.SignedString([]byte("super-secret-token"))
	fmt.Print(tokenString)
}
