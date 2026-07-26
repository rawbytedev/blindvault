package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestJWTValidator_Validate(t *testing.T) {
	secret := "test-secret"
	validator := NewJWTValidator(secret)

	// Generate a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
	})
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	claims, err := validator.Validate(tokenString)
	require.NoError(t, err)
	require.Equal(t, "test-user", claims["sub"])

	// Invalid token
	_, err = validator.Validate("invalid-token")
	require.Error(t, err)

	// Wrong secret
	wrongValidator := NewJWTValidator("wrong-secret")
	_, err = wrongValidator.Validate(tokenString)
	require.Error(t, err)

	// Token with wrong signing method (e.g., none)
	badToken := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{})
	badTokenString, _ := badToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	_, err = validator.Validate(badTokenString)
	require.Error(t, err)
}
