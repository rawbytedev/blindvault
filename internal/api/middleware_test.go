package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rawbytedev/blindvault/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAdminAuthMiddleware(t *testing.T) {
	cfg := &service.Config{
		AuthSecret:     "test-secret",
		UseMemoryStore: true,
	}
	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Admin token
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "admin",
		"admin": true,
	})
	adminTokenString, _ := adminToken.SignedString([]byte(cfg.AuthSecret))

	// Regular token
	userToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user",
	})
	userTokenString, _ := userToken.SignedString([]byte(cfg.AuthSecret))

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"no auth", "", http.StatusUnauthorized},
		{"invalid format", "Basic token", http.StatusUnauthorized},
		{"invalid token", "Bearer invalid", http.StatusUnauthorized},
		{"user token", "Bearer " + userTokenString, http.StatusForbidden},
		{"admin token", "Bearer " + adminTokenString, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()

			handler := server.AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler.ServeHTTP(rr, req)
			require.Equal(t, tt.wantStatus, rr.Code)
		})
	}
}
