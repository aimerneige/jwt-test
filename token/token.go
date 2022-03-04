package token

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtKey []byte

// InitKey init jwt key
func InitKey(key string) {
	jwtKey = []byte(key)
}

// ReleaseToken release token
func ReleaseToken(userID uint, identify string, tokenExpireDuration time.Duration, notBeforeDuration time.Duration) (string, error) {
	currentTime := time.Now().UTC()
	expireTime := currentTime.Add(tokenExpireDuration)
	noeBeforeTime := currentTime.Add(notBeforeDuration)
	issuedAt := jwt.NewNumericDate(currentTime)
	expireAt := jwt.NewNumericDate(expireTime)
	notBefore := jwt.NewNumericDate(noeBeforeTime)
	claims := Claims{
		UserID:   userID,
		Identify: identify,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expireAt,
			IssuedAt:  issuedAt,
			NotBefore: notBefore,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// ParseToken parse token string
func ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	return token, claims, err
}

func keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, UnexpectedSigningMethodError{}
	}
	return jwtKey, nil
}

type UnexpectedSigningMethodError struct{}

func (e UnexpectedSigningMethodError) Error() string {
	return "Unexpected signing method"
}
