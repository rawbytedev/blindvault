// Command server starts the BlindVault HTTP API server.
package main

import (
	"blindvault/pkg/logger"
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"blindvault/internal/api"
	"blindvault/internal/service"

	"gopkg.in/yaml.v3"
)

// main initializes server configuration, builds the API server, and handles graceful shutdown.
func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		panic(err)
	}

	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	server, err := api.NewServer(cfg)
	if err != nil {
		// Use background context for logging before request
		logger.Error(context.Background()).Err(err).Msg("failed to create server")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.Start(); err != nil {
			logger.Error(ctx).Err(err).Msg("server error")
			cancel()
		}
	}()

	<-sigChan
	logger.Info(ctx).Msg("shutting down gracefully...")
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error(shutdownCtx).Err(err).Msg("shutdown error")
	}
}

// loadConfig reads YAML configuration and applies environment variable overrides.
func loadConfig(path string) (*service.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg service.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Override with environment variables (using env vars as source of truth)
	if seed := os.Getenv("MASTER_SEED_HEX"); seed != "" {
		cfg.MasterSeedHex = seed
	}
	if epoch := os.Getenv("ACTIVE_EPOCH"); epoch != "" {
		cfg.ActiveEpoch = epoch
	}
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		cfg.RedisAddr = addr
	}
	if secret := os.Getenv("AUTH_SECRET"); secret != "" {
		cfg.AuthSecret = secret
	}

	return &cfg, nil
}
