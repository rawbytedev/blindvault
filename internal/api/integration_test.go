package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rawbytedev/blindvault/v2/internal/service"
	"github.com/rawbytedev/blindvault/v2/pkg/crypto"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

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

func TestRateLimitMiddleware_UsesForwardedForHeader(t *testing.T) {
	cfg := &service.Config{
		ListenAddr:      ":8080",
		MasterSeedHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		ActiveEpoch:     "2026-01",
		SupportedEpochs: []string{"2026-01"},
		DST:             "BCIS-TEST",
		AuthSecret:      "test-secret",
		UseMemoryStore:  true,
		RateLimit:       1,
		RateLimitBurst:  1,
	}
	server, err := NewServer(cfg)
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/limited", server.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	for _, forwardedIP := range []string{"203.0.113.10", "198.51.100.25"} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/limited", nil)
		require.NoError(t, err)
		req.Header.Set("X-Forwarded-For", forwardedIP)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

// TestMultipleClasses verifies that credentials from different classes are isolated.
func TestMultipleClasses(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	dst := []byte(cfg.DST)

	classes := []string{"class_a", "class_b"}
	msgs := [][]byte{[]byte("message for class a"), []byte("message for class b")}
	jwt := generateJWT(cfg.AuthSecret)

	for i, class := range classes {
		// Issue for each class
		blindedHex, blindFactor := createBlindedMessage(t, engine, msgs[i], dst)
		issueReq := IssueRequest{
			BlindedMessage:  blindedHex,
			CredentialClass: class,
		}
		jsonBody, err := json.Marshal(issueReq)
		require.NoError(t, err)

		resp, err := makeRequest(ts, "POST", "/v1/credential/issue", jsonBody, "Bearer "+jwt)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var issueResp IssueResponse
		err = json.NewDecoder(resp.Body).Decode(&issueResp)
		require.NoError(t, err)

		// Unblind
		unblindedHex := unblindSignature(t, engine, issueResp.BlindSignature, blindFactor)
		witnessHex := createWitness(t, engine, msgs[i], dst)

		// Consume with correct class
		consumeReq := ConsumeRequest{
			UnblindedSignature: unblindedHex,
			Witness:            witnessHex,
			CredentialClass:    class,
			KeyEpoch:           issueResp.KeyEpoch,
		}
		jsonBody, err = json.Marshal(consumeReq)
		require.NoError(t, err)

		resp, err = makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var consumeResp ConsumeResponse
		err = json.NewDecoder(resp.Body).Decode(&consumeResp)
		require.NoError(t, err)
		require.True(t, consumeResp.Valid, "consume for class %s should succeed", class)

		// Try to consume the same credential with the other class (should fail)
		otherClass := classes[1-i]
		consumeReqWrong := ConsumeRequest{
			UnblindedSignature: unblindedHex,
			Witness:            witnessHex,
			CredentialClass:    otherClass,
			KeyEpoch:           issueResp.KeyEpoch,
		}
		jsonBody, err = json.Marshal(consumeReqWrong)
		require.NoError(t, err)

		resp, err = makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
		require.NoError(t, err)
		defer resp.Body.Close()
		// It should fail with bad request (400) because verification fails
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "consume with wrong class should fail")
	}
}

// TestEpochRotation verifies that multiple epochs are supported and that credentials issued with one epoch cannot be consumed with a different epoch (if not supported).
// Our test uses supported epochs: 2026-01 and 2026-02.
func TestEpochRotation(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	msg := []byte("epoch test")
	dst := []byte(cfg.DST)

	// Issue with active epoch (2026-01)
	blindedHex, blindFactor := createBlindedMessage(t, engine, msg, dst)
	issueReq := IssueRequest{
		BlindedMessage:  blindedHex,
		CredentialClass: "epoch_class",
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
	require.Equal(t, cfg.ActiveEpoch, issueResp.KeyEpoch) // should be "2026-01"

	// Unblind
	unblindedHex := unblindSignature(t, engine, issueResp.BlindSignature, blindFactor)
	witnessHex := createWitness(t, engine, msg, dst)

	// 1. Consume with same epoch (should succeed)
	consumeReq := ConsumeRequest{
		UnblindedSignature: unblindedHex,
		Witness:            witnessHex,
		CredentialClass:    "epoch_class",
		KeyEpoch:           cfg.ActiveEpoch,
	}
	jsonBody, err = json.Marshal(consumeReq)
	require.NoError(t, err)
	resp, err = makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var consumeResp ConsumeResponse
	err = json.NewDecoder(resp.Body).Decode(&consumeResp)
	require.NoError(t, err)
	require.True(t, consumeResp.Valid)

	// 2. Consume with a different supported epoch (2026-02) – should fail because the signature was signed with epoch 2026-01.
	consumeReq2 := ConsumeRequest{
		UnblindedSignature: unblindedHex,
		Witness:            witnessHex,
		CredentialClass:    "epoch_class",
		KeyEpoch:           "2026-02",
	}
	jsonBody, err = json.Marshal(consumeReq2)
	require.NoError(t, err)
	resp, err = makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
	require.NoError(t, err)
	defer resp.Body.Close()
	// Should fail (400) because verification fails (key mismatch)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// 3. Consume with unsupported epoch (should be rejected at validation)
	consumeReq3 := ConsumeRequest{
		UnblindedSignature: unblindedHex,
		Witness:            witnessHex,
		CredentialClass:    "epoch_class",
		KeyEpoch:           "2025-12",
	}
	jsonBody, err = json.Marshal(consumeReq3)
	require.NoError(t, err)
	resp, err = makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
	require.NoError(t, err)
	defer resp.Body.Close()
	// Should be 400 because unsupported epoch
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestIssueRateLimit verifies that the rate limiter rejects requests after exceeding the limit.
func TestIssueRateLimit(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	msg := []byte("rate limit test")
	dst := []byte(cfg.DST)
	blindedHex, _ := createBlindedMessage(t, engine, msg, dst)

	reqBody := IssueRequest{
		BlindedMessage:  blindedHex,
		CredentialClass: "test_class",
	}
	jsonBody, err := json.Marshal(reqBody)
	require.NoError(t, err)

	jwt := generateJWT(cfg.AuthSecret)
	authHeader := "Bearer " + jwt

	const totalRequests = 101
	successCount := 0
	rateLimitCount := 0

	for i := 0; i < totalRequests; i++ {
		// Create request manually to set a fixed RemoteAddr for consistent rate limiting.
		req, err := http.NewRequest("POST", ts.URL+"/v1/credential/issue", bytes.NewReader(jsonBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("X-Forwarded-For", "192.168.1.100")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			successCount++
		} else if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitCount++
			t.Logf("Request %d rate limited", i+1)
		} else {
			t.Fatalf("unexpected status code %d on request %d", resp.StatusCode, i+1)
		}
	}

	// We expect at least one rate limit response (burst 20, then rate limit kicks in).
	if rateLimitCount == 0 {
		t.Error("rate limiter did not reject any requests, expected at least one 429")
	}
}

func TestAdminRevoke(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	// Create an admin JWT
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "admin",
		"admin": true,
		"exp":   jwt.NewNumericDate(time.Now().Add(15 * time.Second)),
		"roles": []string{"admin"},
	})
	adminTokenString, _ := adminToken.SignedString([]byte(cfg.AuthSecret))

	// Regular user token (should fail)
	userToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user",
		"exp": jwt.NewNumericDate(time.Now().Add(5 * time.Second)),
	})
	userTokenString, _ := userToken.SignedString([]byte(cfg.AuthSecret))

	t.Run("admin can revoke", func(t *testing.T) {
		revokeBody := map[string]string{
			"credential_class": "test_class",
			"reason":           "test revocation",
		}
		body, _ := json.Marshal(revokeBody)
		resp, err := makeRequest(ts, "POST", "/v1/admin/revoke", body, "Bearer "+adminTokenString)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify revocation worked by issuing and consuming
		engine := crypto.NewBLS12Engine()
		msg := []byte("test message")
		dst := []byte(cfg.DST)
		blindedHex, r := createBlindedMessage(t, engine, msg, dst)

		issueReq := IssueRequest{
			BlindedMessage:  blindedHex,
			CredentialClass: "test_class",
		}
		issueBody, _ := json.Marshal(issueReq)
		issueResp, err := makeRequest(ts, "POST", "/v1/credential/issue", issueBody, "Bearer "+adminTokenString)
		require.NoError(t, err)
		defer issueResp.Body.Close()
		require.Equal(t, http.StatusOK, issueResp.StatusCode)

		var issueData IssueResponse
		err = json.NewDecoder(issueResp.Body).Decode(&issueData)
		require.NoError(t, err)

		unblindedHex := unblindSignature(t, engine, issueData.BlindSignature, r)
		witnessHex := createWitness(t, engine, msg, dst)

		consumeReq := ConsumeRequest{
			UnblindedSignature: unblindedHex,
			Witness:            witnessHex,
			CredentialClass:    "test_class",
			KeyEpoch:           issueData.KeyEpoch,
		}
		consumeBody, _ := json.Marshal(consumeReq)
		resp, err = makeRequest(ts, "POST", "/v1/credential/consume", consumeBody, "")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should fail with conflict or bad request due to revocation
		require.Equal(t, http.StatusConflict, resp.StatusCode)
		var consumeResp ConsumeResponse
		err = json.NewDecoder(resp.Body).Decode(&consumeResp)
		require.NoError(t, err)
		require.False(t, consumeResp.Valid)
		require.Contains(t, consumeResp.Error, "revoked")
	})

	t.Run("user cannot revoke", func(t *testing.T) {
		revokeBody := map[string]string{
			"credential_class": "test_class",
			"reason":           "test revocation",
		}
		body, _ := json.Marshal(revokeBody)
		resp, err := makeRequest(ts, "POST", "/v1/admin/revoke", body, "Bearer "+userTokenString)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("unrevoke", func(t *testing.T) {
		// First revoke
		revokeBody := map[string]string{
			"credential_class": "unrevoke_test",
			"reason":           "to be unrevoked",
		}
		body, _ := json.Marshal(revokeBody)
		resp, err := makeRequest(ts, "POST", "/v1/admin/revoke", body, "Bearer "+adminTokenString)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Now unrevoke
		unrevokeBody := map[string]string{
			"credential_class": "unrevoke_test",
		}
		body, _ = json.Marshal(unrevokeBody)
		resp, err = makeRequest(ts, "DELETE", "/v1/admin/revoke", body, "Bearer "+adminTokenString)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify unrevoke worked by issuing and consuming
		engine := crypto.NewBLS12Engine()
		msg := []byte("test message")
		dst := []byte(cfg.DST)
		blindedHex, r := createBlindedMessage(t, engine, msg, dst)

		issueReq := IssueRequest{
			BlindedMessage:  blindedHex,
			CredentialClass: "unrevoke_test",
		}
		issueBody, _ := json.Marshal(issueReq)
		issueResp, err := makeRequest(ts, "POST", "/v1/credential/issue", issueBody, "Bearer "+adminTokenString)
		require.NoError(t, err)
		defer issueResp.Body.Close()
		require.Equal(t, http.StatusOK, issueResp.StatusCode)

		var issueData IssueResponse
		err = json.NewDecoder(issueResp.Body).Decode(&issueData)
		require.NoError(t, err)

		unblindedHex := unblindSignature(t, engine, issueData.BlindSignature, r)
		witnessHex := createWitness(t, engine, msg, dst)

		consumeReq := ConsumeRequest{
			UnblindedSignature: unblindedHex,
			Witness:            witnessHex,
			CredentialClass:    "unrevoke_test",
			KeyEpoch:           issueData.KeyEpoch,
		}
		consumeBody, _ := json.Marshal(consumeReq)
		resp, err = makeRequest(ts, "POST", "/v1/credential/consume", consumeBody, "")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("list revocations", func(t *testing.T) {
		resp, err := makeRequest(ts, "GET", "/v1/admin/revocations", nil, "Bearer "+adminTokenString)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		revocations, ok := result["revocations"]
		require.True(t, ok)
		require.NotNil(t, revocations)
	})
}
