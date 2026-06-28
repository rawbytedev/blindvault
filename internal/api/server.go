// Package api implements BlindVault HTTP server wiring, middleware, and request handling.
package api

import (
	"context"
	"net/http"
	"time"

	"blindvault/internal/auth"
	"blindvault/internal/service"
	"blindvault/internal/storage"
	"blindvault/pkg/logger"
	"blindvault/pkg/metrics"
)

// Server provides the HTTP server, middleware, and credential service for BlindVault.
type Server struct {
	httpServer        *http.Server
	config            *service.Config
	jwtValidator      *auth.JWTValidator
	rateLimiter       *RateLimiter
	credentialService *service.CredentialService
	metrics           metrics.MetricsReporter
}

// NewServer initializes a new Server with the given configuration, setting up storage, services, and HTTP handlers.
func NewServer(cfg *service.Config) (*Server, error) {
	// Init storage
	var nullifierStore storage.NullifierStore
	var err error
	metrics := GetMetrics()
	if cfg.UseMemoryStore {
		nullifierStore = storage.NewInMemoryNullifierStore()
	} else {
		nullifierStore, err = storage.NewRedisNullifierStore(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, time.Duration(cfg.RedisExpiration), metrics)
		if err != nil {
			return nil, err // use errors.Wrap later
		}
	}

	credService := service.NewCredentialService(cfg, nullifierStore)
	jwtValidator := auth.NewJWTValidator(cfg.AuthSecret)
	rateLimiter := NewRateLimiter(100, 20)

	s := &Server{
		config:            cfg,
		jwtValidator:      jwtValidator,
		rateLimiter:       rateLimiter,
		credentialService: credService,
		metrics:           metrics,
	}

	mux := http.NewServeMux()
	// Chain middlewares: Recovery -> Logger -> (Auth/RateLimit) -> Handler
	mux.HandleFunc("POST /v1/credential/issue",
		s.RecoveryMiddleware(
			s.LoggerMiddleware(
				s.RateLimitMiddleware(
					s.AuthMiddleware(s.handleIssue),
				),
			),
		),
	)
	mux.HandleFunc("POST /v1/credential/consume",
		s.RecoveryMiddleware(
			s.LoggerMiddleware(
				s.RateLimitMiddleware(s.handleConsume),
			),
		),
	)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.metricsHandler)

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// Start begins serving HTTP requests and periodically cleans up rate limiter state.
func (s *Server) Start() error {
	logger.Info(context.Background()).Str("addr", s.config.ListenAddr).Msg("starting server")
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.rateLimiter.Cleanup()
		}
	}()
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server and closes backend resources.
func (s *Server) Shutdown(ctx context.Context) error {
	logger.Info(ctx).Msg("shutting down server")
	if err := s.credentialService.Close(); err != nil {
		logger.Error(ctx).Err(err).Msg("failed to close credential service")
	}
	return s.httpServer.Shutdown(ctx)
}
