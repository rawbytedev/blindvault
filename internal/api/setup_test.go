package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rawbytedev/blindvault/v2/internal/auth"
	"github.com/rawbytedev/blindvault/v2/internal/service"
	"github.com/rawbytedev/blindvault/v2/pkg/crypto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func setupTestServer(t *testing.T) (*httptest.Server, *service.Config) {
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
	}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	ts := httptest.NewServer(server.httpServer.Handler)
	return ts, cfg
}

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

// setupBenchServer creates a server with in-memory storage for pure performance baselines.
// For Redis benchmarks, override the config to use a real Redis instance.
func setupBenchServer(b *testing.B) (*httptest.Server, *service.Config, []byte) {
	cfg := &service.Config{
		ListenAddr:      ":8080",
		MasterSeedHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		ActiveEpoch:     "2026-01",
		SupportedEpochs: []string{"2026-01"},
		DST:             "BCIS-TEST",
		AuthSecret:      "bench-secret",
		UseMemoryStore:  true,
		RateLimitBurst:  0,
		RateLimit:       0,
	}
	// Disable all logging for benchmarks (no output, no allocation)
	zerolog.SetGlobalLevel(zerolog.Disabled)

	server, err := NewServer(cfg)
	require.NoError(b, err)

	ts := httptest.NewServer(server.httpServer.Handler)

	// Pre-generate a valid JWT for all requests
	jwt := generateJWT(cfg.AuthSecret)
	authHeader := []byte("Bearer " + jwt)

	return ts, cfg, authHeader
}

// generateBenchBlindedMessage creates a fresh blinded message for each request.
func generateBenchBlindedMessage(b *testing.B) (blindedHex string, blindingFactor crypto.Scalar) {
	engine := crypto.NewBLS12Engine()
	msg := []byte("bench-handler-message")
	dst := []byte("BCIS-TEST")

	point, err := engine.HashToCurve(msg, dst)
	require.NoError(b, err)

	r, err := crypto.NewRandomScalar()
	require.NoError(b, err)

	blinded, err := engine.BlindMessage(point, r)
	require.NoError(b, err)

	return hex.EncodeToString(blinded.Compress()), r
}

func setupTestDummyServer(t *testing.T) (*httptest.Server, *service.Config) {
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
	}
	server, err := NewServer(cfg)
	server.credentialService = &DummyCredentialService{}
	require.NoError(t, err)
	ts := httptest.NewServer(server.httpServer.Handler)
	return ts, cfg
}

// generateJWT creates a valid JWT for testing.
func generateJWT(secret string) string {
	claims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test-client",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Roles: []string{"issuer", "admin"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := tok.SignedString([]byte(secret))
	return s
}

// createBlindedMessage blinds a message for testing.
func createBlindedMessage(t *testing.T, engine crypto.Engine, msg []byte, dst []byte) (blindedHex string, blindFactor crypto.Scalar) {
	point, err := engine.HashToCurve(msg, dst)
	require.NoError(t, err)

	r, err := crypto.NewRandomScalar()
	require.NoError(t, err)

	blinded, err := engine.BlindMessage(point, r)
	require.NoError(t, err)

	return hex.EncodeToString(blinded.Compress()), r
}

func unblindSignature(t *testing.T, engine crypto.Engine, blindSigHex string, r crypto.Scalar) string {
	sigBytes, err := hex.DecodeString(blindSigHex)
	require.NoError(t, err)
	sig, err := crypto.DeserializeG1(sigBytes)
	require.NoError(t, err)

	unblinded, err := engine.UnblindSignature(sig, r)
	require.NoError(t, err)

	return hex.EncodeToString(unblinded.Compress())
}

// createWitness returns the G1 point H(msg) as hex.
func createWitness(t *testing.T, engine crypto.Engine, msg []byte, dst []byte) string {
	point, err := engine.HashToCurve(msg, dst)
	require.NoError(t, err)
	return hex.EncodeToString(point.Compress())
}
func issueAndUnblind(t *testing.T, ts *httptest.Server, cfg *service.Config, class string, msg []byte) (sigHex, witnessHex, epoch, classRet string) {
	engine := crypto.NewBLS12Engine()
	dst := []byte(cfg.DST)

	blindedHex, blindFactor := createBlindedMessage(t, engine, msg, dst)
	issueReq := IssueRequest{
		BlindedMessage:  blindedHex,
		CredentialClass: class,
	}
	jsonBody, err := json.Marshal(issueReq)
	require.NoError(t, err)

	jwt := generateJWT(cfg.AuthSecret)
	resp, err := makeRequest(ts, "POST", "/v1/credential/issue", jsonBody, "Bearer "+jwt)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var issueResp IssueResponse
	err = json.NewDecoder(resp.Body).Decode(&issueResp)
	require.NoError(t, err)

	unblindedHex := unblindSignature(t, engine, issueResp.BlindSignature, blindFactor)
	witnessHex = createWitness(t, engine, msg, dst)

	return unblindedHex, witnessHex, issueResp.KeyEpoch, class
}

// makeRequest sends an HTTP request to the test server.
func makeRequest(ts *httptest.Server, method, path string, body []byte, authHeader string) (*http.Response, error) {
	client := &http.Client{}
	req, err := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return client.Do(req)
}
