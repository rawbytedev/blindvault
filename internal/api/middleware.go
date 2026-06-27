package api

import (
	"blindvault/pkg/logger"
	"context"
	"net/http"
	"strings"
	"time"
)

// AuthMiddleware validates JWT for protected endpoints.
func (s *Server) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.respondError(ctx, w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			s.respondError(ctx, w, http.StatusUnauthorized, "invalid authorization format")
			return
		}

		claims, err := s.jwtValidator.Validate(parts[1])
		if err != nil {
			s.respondError(ctx, w, http.StatusUnauthorized, "invalid token")
			return
		}

		// Store claims in context for later use (e.g., audit logging)
		ctx = context.WithValue(ctx, "claims", claims)
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
		// Use a simple in-memory rate limiter or Redis-based
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !s.rateLimiter.Allow(ip) {
			s.respondError(r.Context(), w, http.StatusTooManyRequests, "rate limit exceeded")
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
				logger.Error(r.Context()).Interface("panic", rec).Msg("panic recovered")
				s.respondError(r.Context(), w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next(w, r)
	}
}
