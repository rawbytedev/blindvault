// Command server starts the BlindVault HTTP API server.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/rawbytedev/blindvault/internal/api"
	"github.com/rawbytedev/blindvault/internal/service"
	"github.com/rawbytedev/blindvault/pkg/logger"

	"gopkg.in/yaml.v3"
)

// main initializes server configuration, builds the API server, and handles graceful shutdown.
func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to YAML config file")
	envFile := flag.String("env-file", "", "path to .env file (optional; loaded before config)")
	envOverride := flag.Bool("env-override", false, "allow env-file to overwrite existing env vars")
	flag.Parse()

	if err := run(*configPath, *envFile, *envOverride); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(configPath, envFile string, envOverride bool) error {
	// Load env file FIRST so its values are visible downstream.
	ctx := context.Background()
	if envFile != "" {
		logger.Info(ctx).Msgf("Loading from env file: %s", envFile)
		if err := loadEnvFile(envFile, envOverride); err != nil {
			return fmt.Errorf("load env file: %w", err)
		}
	}
	cfg := &service.Config{}
	// Parse YAML.
	logger.Info(ctx).Msgf("Checking config file: %s", configPath)
	if _, err := os.Stat(configPath); err != nil {
		logger.Warn(ctx).Err(err).Msgf("config file not found, skipping: %s", configPath)
	} else {
		logger.Info(ctx).Msgf("Loading config file: %s", configPath)
		err := loadYAMLConfig(configPath, cfg)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
	}

	// Apply Env overrides to config
	logger.Info(ctx).Msg("Applying Env overrides")
	cfg.ApplyEnvOverrides()

	logger.Info(ctx).Msg("Loading master seed")
	if err := cfg.LoadMasterSeed(); err != nil {
		return fmt.Errorf("load master seed: %w", err)
	}

	// Validate config after env overrides and master seed load.
	logger.Info(ctx).Msg("Validating config")
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Post-validation warnings (non-fatal).
	logger.Info(ctx).Msg("checking for production warnings")
	if cfg.Mode.IsProduction() && envFile != "" {
		logger.Warn(ctx).Str("env_file", envFile).
			Msg("dotenv files in production are discouraged; prefer a secrets manager")
	}

	// Build server.
	server, err := api.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	// Start with signal-driven shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info(ctx).Msg("shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	return server.Shutdown(shutdownCtx)
}

// loadEnvFile loads a .env file into the process environment.
// When override is false, existing environment variables take precedence.
func loadEnvFile(path string, override bool) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}
	if override {
		return godotenv.Overload(path)
	}
	return godotenv.Load(path)
}

// loadYAMLConfig reads and unmarshals the YAML config file.
func loadYAMLConfig(path string, cfg *service.Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return err
	}
	return nil
}
