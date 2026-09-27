package api

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rawbytedev/blindvault/internal/auth"
	"github.com/rawbytedev/blindvault/pkg/apperr"
	"github.com/rawbytedev/blindvault/pkg/logger"
)

// RequireRole — requires a specific role (or admin).
func (s *Server) RequireRole(role string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, err := s.authenticate(r)
			if err != nil {
				s.respondErr(r.Context(), w, err, "auth")
				return
			}
			if !claims.HasRole(role) {
				s.respondErr(r.Context(), w,
					apperr.Newf(apperr.CodeForbidden, "role %q required", role), "authz")
				return
			}
			next(w, r.WithContext(auth.WithClaims(r.Context(), claims)))
		}
	}
}

func (s *Server) authenticate(r *http.Request) (*auth.Claims, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, apperr.New(apperr.CodeUnauthorized, "missing authorization header")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, apperr.New(apperr.CodeUnauthorized, "invalid authorization format")
	}
	claims, err := s.jwtValidator.Validate(parts[1])
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeUnauthorized, err, "invalid token")
	}
	return claims, nil
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
		// Normalize remote host (strip port if present)
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = host
		}
		// Only trust X-Forwarded-For when the immediate peer is a private/trusted proxy
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			// check if remote is loopback or private
			remoteHost := ip
			parsed := net.ParseIP(remoteHost)

			if parsed != nil && (parsed.IsLoopback() || parsed.IsPrivate()) {
				parts := strings.Split(forwarded, ",")
				ip = strings.TrimSpace(parts[0])
			}
		}
		if !s.rateLimiter.Allow(ip) {
			s.respondErr(r.Context(), w, apperr.New(apperr.CodeTooManyRequest, "rate limit exceeded"), "ratelimit")
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
				s.respondErr(ctx, w, apperr.New(apperr.CodeInternal, "internal server error"), "recovery")
			}
		}()
		next(w, r)
	}
}
