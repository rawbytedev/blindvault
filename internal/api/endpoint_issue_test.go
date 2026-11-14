package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/rawbytedev/blindvault/v2/pkg/crypto"
	"github.com/stretchr/testify/require"
)

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
}

// TestIssueMissingFields verifies that the API rejects requests with missing fields.
func TestIssueMissingFields(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	jwt := generateJWT(cfg.AuthSecret)

	tests := []struct {
		name      string
		body      IssueRequest
		expectMsg string
	}{
		{
			name: "missing blinded_message",
			body: IssueRequest{
				BlindedMessage:  "",
				CredentialClass: "test_class",
			},
			expectMsg: "missing required fields",
		},
		{
			name: "missing credential_class",
			body: IssueRequest{
				BlindedMessage:  "0123456789abcdef", // dummy hex
				CredentialClass: "",
			},
			expectMsg: "missing required fields",
		},
		{
			name: "both missing",
			body: IssueRequest{
				BlindedMessage:  "",
				CredentialClass: "",
			},
			expectMsg: "missing required fields",
		},
		{
			name: "invalid blinded_message (not hex)",
			body: IssueRequest{
				BlindedMessage:  "not-hex-value",
				CredentialClass: "test_class",
			},
			expectMsg: "invalid request body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, err := json.Marshal(tt.body)
			require.NoError(t, err)

			resp, err := makeRequest(ts, "POST", "/v1/credential/issue", jsonBody, "Bearer "+jwt)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Expect 400 for missing fields, but for invalid hex we'll get 500.
			// validation errors should return 400 and include 'invalid request'
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected 400 for invalid input")
			var errResp ErrorResponse
			err = json.NewDecoder(resp.Body).Decode(&errResp)
			require.NoError(t, err)
			require.Contains(t, errResp.Error, "invalid request")
		})
	}
}

// TestIssueUnauthenticated verifies that the API rejects requests without a valid JWT.
func TestIssueUnauthenticated(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	// Generate a valid blinded message for the "valid token" subtest.
	engine := crypto.NewBLS12Engine()
	msg := []byte("auth test")
	dst := []byte(cfg.DST)
	blindedHex, _ := createBlindedMessage(t, engine, msg, dst)

	validBody := IssueRequest{
		BlindedMessage:  blindedHex,
		CredentialClass: "test_class",
	}
	validJSON, err := json.Marshal(validBody)
	require.NoError(t, err)

	// Dummy body for tests that don't care about content
	dummyBody := IssueRequest{
		BlindedMessage:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		CredentialClass: "test_class",
	}
	dummyJSON, err := json.Marshal(dummyBody)
	require.NoError(t, err)

	tests := []struct {
		name           string
		body           []byte
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "no authorization header",
			body:           dummyJSON,
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid scheme (basic instead of bearer)",
			body:           dummyJSON,
			authHeader:     "Basic dGVzdDp0ZXN0",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed token (not enough parts)",
			body:           dummyJSON,
			authHeader:     "Bearer",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid token (random string)",
			body:           dummyJSON,
			authHeader:     "Bearer invalid-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "valid token (should pass auth, but fail deserialization because dummy hex is invalid)",
			body:           dummyJSON, // dummy hex is invalid, so it will fail later with 500
			authHeader:     "Bearer " + generateJWT(cfg.AuthSecret),
			expectedStatus: http.StatusBadRequest, // auth passes, but deserialization fails
		},
		{
			name:           "valid token + valid blinded message (full success)",
			body:           validJSON,
			authHeader:     "Bearer " + generateJWT(cfg.AuthSecret),
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := makeRequest(ts, "POST", "/v1/credential/issue", tt.body, tt.authHeader)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, tt.expectedStatus, resp.StatusCode)
		})
	}
}

func TestHandleIssue(t *testing.T) {
	type BadIssueRequest struct {
		Blinded    string `json:"blinded"`
		Credential string `json:"credential"`
	}
	server, cfg := setupTestDummyServer(t)
	jwt := generateJWT(cfg.AuthSecret)
	// json should fail
	// bad json on purpose
	requestBody := []byte(`{"blinded_messagedummy_blinded_message", "credential_class dummy_credential_class"}`)
	resp, err := makeRequest(server, "POST", "/v1/credential/issue", requestBody, "Bearer "+jwt)
	require.NoError(t, err)
	require.Equal(t, 400, resp.StatusCode)

	resp, err = makeRequest(server, "POST", "/v1/credential/consume", requestBody, "Bearer "+jwt)
	require.NoError(t, err)
	require.Equal(t, 400, resp.StatusCode)

	//
}
