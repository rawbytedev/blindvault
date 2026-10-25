package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/rawbytedev/blindvault/v2/internal/service"
	"github.com/stretchr/testify/require"
)

// spawn a test server with demo store enabled
func setupTestDemoServer(t *testing.T) (*httptest.Server, *service.Config) {
	cfg := &service.Config{
		ListenAddr:      ":8080",
		MasterSeedHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		ActiveEpoch:     "2026-01",
		SupportedEpochs: []string{"2026-01", "2026-02"},
		DST:             "BCIS-TEST",
		AuthSecret:      "test-secret",
		UseMemoryStore:  true,
		RateLimitBurst:  20,
		RateLimit:       100,
		UseDemo:         true,
	}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	ts := httptest.NewServer(server.httpServer.Handler)
	return ts, cfg
}

// TestDemoStoreStoreCredentialsSuccess tests storing credentials in the demo store
func TestDemoStoreStoreCredentialsSuccess(t *testing.T) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	var response struct {
		TicketID string `json:"ticket_id"`
	}
	req.Ciphertext = "test-credential"
	body, err := json.Marshal(req)
	require.NoError(t, err)
	ts, _ := setupTestDemoServer(t)
	defer ts.Close()
	resp, err := makeRequest(ts, "POST", "/demo/store", body, "")
	require.NoError(t, err)
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	require.NotEmpty(t, response.TicketID)
	require.Equal(t, 200, resp.StatusCode)
}

// TestDemoStoreStoreCredentialsFailure tests storing credentials in the demo store with invalid request
func TestDemoStoreStoreCredentialsFailure(t *testing.T) {
	// wrong json format
	var req struct {
		Cipher string `json:"cipher"`
	}
	var response ErrorResponse
	req.Cipher = "test-credential"
	body, err := json.Marshal(req)
	require.NoError(t, err)
	ts, _ := setupTestDemoServer(t)
	defer ts.Close()
	resp, err := makeRequest(ts, "POST", "/demo/store", body, "")
	require.NoError(t, err)
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, 400, response.Code)
	require.NotEmpty(t, response.Error)
	require.Equal(t, "invalid request", response.Error)
}

// TestDemoStoreRetrieveCredentialsSuccess tests retrieving credentials from the demo store
func TestDemoStoreRetrieveCredentialsSuccess(t *testing.T) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	var response struct {
		TicketID string `json:"ticket_id"`
	}
	ts, _ := setupTestDemoServer(t)
	defer ts.Close()
	req.Ciphertext = "test-credential"
	body, err := json.Marshal(req)
	require.NoError(t, err)
	resp, err := makeRequest(ts, "POST", "/demo/store", body, "")
	require.NoError(t, err)
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	require.NotEmpty(t, response.TicketID)
	require.Equal(t, 200, resp.StatusCode)
	resp2, err := makeRequest(ts, "GET", "/demo/retrieve?ticket_id="+response.TicketID, nil, "")
	require.NoError(t, err)
	var response2 struct {
		Ciphertext string `json:"ciphertext"`
	}
	err = json.NewDecoder(resp2.Body).Decode(&response2)
	require.NoError(t, err)
	require.Equal(t, req.Ciphertext, response2.Ciphertext)
	require.Equal(t, 200, resp2.StatusCode)

}

// TestDemoStoreRetrieveCredentialsFailure tests retrieving credentials from the demo store with invalid ticket_id
func TestDemoStoreRetrieveCredentialsFailure(t *testing.T) {
	var response ErrorResponse
	ts, _ := setupTestDemoServer(t)
	defer ts.Close()
	resp, err := makeRequest(ts, "GET", "/demo/retrieve?ticket_id=invalid-ticket-id", nil, "")
	require.NoError(t, err)
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, 404, response.Code)
	require.NotEmpty(t, response.Error)
	require.Equal(t, "ticket not found", response.Error)
}
