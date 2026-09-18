package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rawbytedev/blindvault/pkg/apperr"
	"github.com/rawbytedev/blindvault/pkg/logger"
)

type contextKey string

const (
	claimsKey contextKey = "claims"
	adminKey  contextKey = "adminKey" // used in handlers

)

// AdminAuthMiddleware validates JWT and ensures the token has admin privileges.
func (s *Server) AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.respondErr(ctx, w, apperr.New(apperr.CodeUnauthorized, "missing authorization header"), "None", "admin_auth")
			return
		}
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			s.respondErr(ctx, w, apperr.New(apperr.CodeUnauthorized, "invalid authorization format"), "", "admin_auth")
			return
		}
		claims, err := s.jwtValidator.Validate(parts[1])
		if err != nil {

			s.respondErr(ctx, w, apperr.Wrap(apperr.CodeUnauthorized, err, "invalid token"), "", "admin_auth")
			return
		}
		// Check for admin claim
		admin, ok := claims["admin"]
		if !ok || admin != true {
			s.respondErr(ctx, w, apperr.New(apperr.CodeForbidden, "admin privileges required"), "", "admin_auth")
			return
		}
		// Extract admin identity (subject)
		adminID, _ := claims["sub"].(string)
		if adminID == "" {
			adminID = "unknown"
		}
		ctx = context.WithValue(ctx, adminKey, adminID)
		ctx = context.WithValue(ctx, claimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

// AuthMiddleware validates JWT for protected endpoints.
func (s *Server) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.respondErr(ctx, w, apperr.New(apperr.CodeUnauthorized, "missing authorization header"), "None", "auth_middleware")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			s.respondErr(ctx, w, apperr.New(apperr.CodeUnauthorized, "invalid authorization format"), "None", "auth_middleware")
			return
		}

		claims, err := s.jwtValidator.Validate(parts[1])
		if err != nil {
			s.respondErr(ctx, w, apperr.Wrap(apperr.CodeUnauthorized, err, "invalid token"), "None", "auth_middleware")
			return
		}

		// Store claims in context for later use (e.g., audit logging)
		ctx = context.WithValue(ctx, claimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

// LoggerMiddleware injects a request-scoped logger with request_id.
func (s *Server) LoggerMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, reqID := logger.WithRequestID(r.Context())
		ctx = logger.With(ctx, map[string]any{
			"remote_addr": r.RemoteAddr,
			"method":      r.Method,
			"path":        r.URL.Path,
		})
		w.Header().Set("X-Request-ID", reqID)

		// Wrap to capture status
		wrapped := newResponseWriter(w)
		next(wrapped, r.WithContext(ctx))

		logger.Info(ctx).
			Int("status", wrapped.Status()).
			Dur("duration", time.Since(start)).
			Msg("request completed")

		s.metrics.RecordHTTPRequest(r.Method, r.URL.Path, wrapped.Status(), time.Since(start))
	}
}

// RateLimitMiddleware applies per-IP rate limiting.
func (s *Server) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			ip = strings.TrimSpace(parts[0])
		}
		if !s.rateLimiter.Allow(ip) {
			s.respondErr(r.Context(), w, apperr.New(apperr.CodeTooManyRequest, "rate limit exceeded"), "None", "ratelimit")
			return
		}
		next(w, r)
	}
}

// RecoveryMiddleware recovers from panics and logs them.
func (s *Server) RecoveryMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				ctx := r.Context()
				logger.Error(ctx).Interface("panic", rec).Msg("panic recovered")
				s.respondErr(ctx, w, apperr.New(apperr.CodeInternal, "internal server error"), "None", "recovery")
			}
		}()
		next(w, r)
	}
}
