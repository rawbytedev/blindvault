package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rawbytedev/blindvault/v2/internal/service"
	"github.com/stretchr/testify/require"
)

func TestServerInitialization(t *testing.T) {
	config := &service.Config{
		UseMemoryStore: true,
		AuthSecret:     "testsecret",
		RateLimit:      10,
		RateLimitBurst: 5,
		MaxClients:     100,
		ListenAddr:     "localhost:8080",
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to initialize server: %v", err)
	}
	if server == nil {
		t.Fatal("Expected server to be initialized, got nil")
	}
	if server.httpServer == nil {
		t.Fatal("Expected httpServer to be initialized, got nil")
	}
	// Prepare to stop the server after a short delay to avoid blocking the test indefinitely
	go func() {
		time.Sleep(3 * time.Second)
		err := server.Shutdown(context.Background())
		if err != nil {
			t.Errorf("Failed to shutdown server: %v", err)
		}
	}()

	err = server.Start()
	require.Error(t, err, http.ErrServerClosed, "Expected server to be closed after shutdown")
}

func TestLiveConfigServerInitialization(t *testing.T) {
	config := &service.Config{
		UseMemoryStore: false,
		AuthSecret:     "testsecret",
		RateLimit:      10,
		RateLimitBurst: 5,
		MaxClients:     100,
		ListenAddr:     "localhost:8081",
		RedisAddr:      "localhost:6379",
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to initialize server with live config: %v", err)
	}
	if server == nil {
		t.Fatal("Expected server to be initialized, got nil")
	}
	if server.httpServer == nil {
		t.Fatal("Expected httpServer to be initialized, got nil")
	}
	// Prepare to stop the server after a short delay to avoid blocking the test indefinitely
	go func() {
		time.Sleep(3 * time.Second)
		err := server.Shutdown(context.Background())
		if err != nil {
			t.Errorf("Failed to shutdown server: %v", err)
		}
	}()

	err = server.Start()
	require.Error(t, err, http.ErrServerClosed, "Expected server to be closed after shutdown")
}
