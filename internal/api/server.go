// Package api implements BlindVault HTTP server wiring, middleware, and request handling.
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/rawbytedev/blindvault/internal/auth"
	"github.com/rawbytedev/blindvault/internal/service"
	"github.com/rawbytedev/blindvault/internal/storage"
	"github.com/rawbytedev/blindvault/pkg/logger"
	"github.com/rawbytedev/blindvault/pkg/metrics"
)

// Server provides the HTTP server, middleware, and credential service for BlindVault.
type Server struct {
	httpServer        *http.Server
	config            *service.Config
	jwtValidator      *auth.JWTValidator
	rateLimiter       *RateLimiter
	credentialService *service.CredentialService
	metrics           metrics.MetricsReporter
	revocationStore   storage.RevocationStore
}

// NewServer initializes a new Server with the given configuration, setting up storage, services, and HTTP handlers.
func NewServer(cfg *service.Config) (*Server, error) {
	// Init storage
	var nullifierStore storage.NullifierStore
	var revocationStore storage.RevocationStore
	metrics := GetMetrics()
	if cfg.UseMemoryStore {
		nullifierStore = storage.NewInMemoryNullifierStore()
		revocationStore = storage.NewInMemoryRevocationStore()
	} else {
		redisClient, err := storage.NewRedisClient(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
		if err != nil {
			return nil, err
		}
		nullifierStore = storage.NewRedisNullifierStoreWithClient(redisClient, time.Duration(cfg.RedisExpiration))
		// Revocation store: use separate Redis if configured, otherwise reuse main client
		if cfg.RevocationRedisAddr != "" {
			revClient, err := storage.NewRedisClient(cfg.RevocationRedisAddr, cfg.RevocationRedisPassword, cfg.RevocationRedisDB)
			if err != nil {
				return nil, err
			}
			revocationStore = storage.NewRedisRevocationStore(revClient)
		} else {
			revocationStore = storage.NewRedisRevocationStore(redisClient)
		}
	}
	credService := service.NewCredentialService(cfg, nullifierStore, revocationStore, metrics)
	jwtValidator := auth.NewJWTValidator(cfg.AuthSecret)
	rateLimiter := NewRateLimiter(100, 20)

	s := &Server{
		config:            cfg,
		jwtValidator:      jwtValidator,
		rateLimiter:       rateLimiter,
		credentialService: credService,
		metrics:           metrics,
		revocationStore:   revocationStore,
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
	mux.HandleFunc("POST /v1/admin/revoke",
		s.RecoveryMiddleware(
			s.LoggerMiddleware(
				s.RateLimitMiddleware(
					s.AdminAuthMiddleware(s.handleAdminRevoke),
				),
			),
		),
	)
	mux.HandleFunc("DELETE /v1/admin/revoke",
		s.RecoveryMiddleware(
			s.LoggerMiddleware(
				s.RateLimitMiddleware(
					s.AdminAuthMiddleware(s.handleAdminUnrevoke),
				),
			),
		),
	)
	mux.HandleFunc("GET /v1/admin/revocations",
		s.RecoveryMiddleware(
			s.LoggerMiddleware(
				s.RateLimitMiddleware(
					s.AdminAuthMiddleware(s.handleAdminListRevocations),
				),
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
