package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func makeToken(t *testing.T, secret, subject, issuer, audience string, roles []string, admin bool) string {
	t.Helper()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Roles: roles,
		Admin: admin,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func TestJWTValidator_Valid(t *testing.T) {
	v := NewJWTValidator(ValidatorConfig{
		Secret:   "test-secret",
		Issuer:   "blindvault-test",
		Audience: "blindvault-api",
	})
	tok := makeToken(t, "test-secret", "user-1", "blindvault-test", "blindvault-api", []string{"issuer"}, false)

	got, err := v.Validate(tok)
	require.NoError(t, err)
	require.Equal(t, "user-1", got.Subject)
	require.True(t, got.HasRole("issuer"))
}

func TestJWTValidator_RejectsBadAlg(t *testing.T) {
	v := NewJWTValidator(ValidatorConfig{Secret: "test-secret"})
	bad := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "x"})
	s, _ := bad.SignedString(jwt.UnsafeAllowNoneSignatureType)
	_, err := v.Validate(s)
	require.Error(t, err)
}

func TestJWTValidator_RejectsMissingExp(t *testing.T) {
	v := NewJWTValidator(ValidatorConfig{Secret: "test-secret"})
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "x"})
	s, _ := tok.SignedString([]byte("test-secret"))
	_, err := v.Validate(s)
	require.Error(t, err)
}

func TestJWTValidator_RejectsWrongIssuer(t *testing.T) {
	v := NewJWTValidator(ValidatorConfig{Secret: "s", Issuer: "expected"})
	tok := makeToken(t, "s", "u", "wrong", "", nil, false)
	_, err := v.Validate(tok)
	require.Error(t, err)
}
