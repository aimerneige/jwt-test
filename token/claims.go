package token

import "github.com/golang-jwt/jwt/v4"

type Claims struct {
	UserID   uint   `json:"user_id"`
	Identify string `json:"identify"`
	jwt.RegisteredClaims
}
