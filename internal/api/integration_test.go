package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"blindvault/internal/service"
	"blindvault/pkg/crypto"

	"github.com/golang-jwt/jwt/v5"
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
	}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	ts := httptest.NewServer(server.httpServer.Handler)
	return ts, cfg
}

// generateJWT creates a valid JWT for testing.
func generateJWT(secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-client",
		"iat": 1516239022,
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

// createBlindedMessage blinds a message for testing.
func createBlindedMessage(t *testing.T, engine *crypto.BLS12Engine, msg []byte, dst []byte) (blindedHex string, blindFactor crypto.Scalar) {
	point, err := engine.HashToCurve(msg, dst)
	require.NoError(t, err)

	r, err := crypto.NewRandomScalar()
	require.NoError(t, err)

	blinded, err := engine.BlindMessage(point, r)
	require.NoError(t, err)

	return hex.EncodeToString(blinded.Compress()), r
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

func TestHealthEndpoint(t *testing.T) {
	ts, _ := setupTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]string
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	require.Equal(t, "ok", body["status"])
}

func TestIssueValidRequest(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	msg := []byte("test message")
	dst := []byte(cfg.DST)

	blindedHex, _ := createBlindedMessage(t, engine, msg, dst)

	reqBody := IssueRequest{
		BlindedMessage:  blindedHex,
		CredentialClass: "test_class",
	}
	jsonBody, err := json.Marshal(reqBody)
	require.NoError(t, err)

	jwt := generateJWT(cfg.AuthSecret)
	resp, err := makeRequest(ts, "POST", "/v1/credential/issue", jsonBody, "Bearer "+jwt)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check status
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode response
	var respBody IssueResponse
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	require.NoError(t, err)

	// Validate fields
	require.NotEmpty(t, respBody.BlindSignature, "blind_signature is empty")
	require.NotEmpty(t, respBody.PublicKey, "public_key is empty")
	require.Equal(t, cfg.ActiveEpoch, respBody.KeyEpoch, "key_epoch mismatch")
	require.NotEmpty(t, respBody.Proof.R1, "proof.R1 empty")
	require.NotEmpty(t, respBody.Proof.R2, "proof.R2 empty")
	require.NotEmpty(t, respBody.Proof.S, "proof.S empty")
	require.NotEmpty(t, respBody.Proof.C, "proof.C empty")

	// Ensure they are valid hex
	_, err = hex.DecodeString(respBody.BlindSignature)
	require.NoError(t, err, "blind_signature not valid hex")
	_, err = hex.DecodeString(respBody.PublicKey)
	require.NoError(t, err, "public_key not valid hex")
	_, err = hex.DecodeString(respBody.Proof.R1)
	require.NoError(t, err, "proof.R1 not valid hex")
	_, err = hex.DecodeString(respBody.Proof.R2)
	require.NoError(t, err, "proof.R2 not valid hex")
	_, err = hex.DecodeString(respBody.Proof.S)
	require.NoError(t, err, "proof.S not valid hex")
	_, err = hex.DecodeString(respBody.Proof.C)
	require.NoError(t, err, "proof.C not valid hex")

	// Optionally: verify the proof can be deserialized and verified against the blinded point
	// (we'll skip for now, but you can add later)
}
