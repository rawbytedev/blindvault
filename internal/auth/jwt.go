package auth

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type JWTValidator struct {
	secret   []byte
	issuer   string // optional; empty = not enforced
	audience string // optional; empty = not enforced
}

type ValidatorConfig struct {
	Secret   string
	Issuer   string
	Audience string
}

func NewJWTValidator(cfg ValidatorConfig) *JWTValidator {
	return &JWTValidator{
		secret:   []byte(cfg.Secret),
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
	}
}

func (v *JWTValidator) Validate(tokenString string) (*Claims, error) {
	claims := &Claims{}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}),
		jwt.WithExpirationRequired(),
	}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	}, opts...)

	if err != nil {
		return nil, fmt.Errorf("token parse: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}
	if claims.Subject == "" {
		return nil, errors.New("token missing subject (sub) claim")
	}
	return claims, nil
}
