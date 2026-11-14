package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/rawbytedev/blindvault/v2/pkg/crypto"
	"github.com/stretchr/testify/require"
)

// TestConsumeValid tests a successful consume (redeem) flow.
func TestConsumeValid(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	msg := []byte("consume test")
	dst := []byte(cfg.DST)

	// 1. Issue a blinded credential.
	blindedHex, r := createBlindedMessage(t, engine, msg, dst)
	issueReq := IssueRequest{
		BlindedMessage:  blindedHex,
		CredentialClass: "consume_class",
	}
	issueJSON, err := json.Marshal(issueReq)
	require.NoError(t, err)

	jwt := generateJWT(cfg.AuthSecret)
	issueResp, err := makeRequest(ts, "POST", "/v1/credential/issue", issueJSON, "Bearer "+jwt)
	require.NoError(t, err)
	defer issueResp.Body.Close()
	require.Equal(t, http.StatusOK, issueResp.StatusCode)

	var issueBody IssueResponse
	err = json.NewDecoder(issueResp.Body).Decode(&issueBody)
	require.NoError(t, err)

	// 2. Unblind the signature.
	unblindedHex := unblindSignature(t, engine, issueBody.BlindSignature, r)

	// 3. Compute the witness (Y = H(msg)).
	point, err := engine.HashToCurve(msg, dst)
	require.NoError(t, err)
	witnessHex := hex.EncodeToString(point.Compress())

	// 4. Consume the credential.
	consumeReq := ConsumeRequest{
		UnblindedSignature: unblindedHex,
		Witness:            witnessHex,
		CredentialClass:    "consume_class",
		KeyEpoch:           issueBody.KeyEpoch,
	}
	consumeJSON, err := json.Marshal(consumeReq)
	require.NoError(t, err)

	consumeResp, err := makeRequest(ts, "POST", "/v1/credential/consume", consumeJSON, "") // No auth required
	require.NoError(t, err)
	defer consumeResp.Body.Close()

	require.Equal(t, http.StatusOK, consumeResp.StatusCode)
	var consumeBody ConsumeResponse
	err = json.NewDecoder(consumeResp.Body).Decode(&consumeBody)
	require.NoError(t, err)
	require.True(t, consumeBody.Valid, "consume response valid should be true")
}

// TestConsumeReplay verifies that consuming the same credential twice fails on the second attempt.
func TestConsumeReplay(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	msg := []byte("replay test")
	dst := []byte(cfg.DST)

	// 1. Issue
	blindedHex, blindFactor := createBlindedMessage(t, engine, msg, dst)
	issueReq := IssueRequest{
		BlindedMessage:  blindedHex,
		CredentialClass: "replay_class",
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

	// 2. Unblind
	unblindedHex := unblindSignature(t, engine, issueResp.BlindSignature, blindFactor)

	// 3. Witness
	witnessHex := createWitness(t, engine, msg, dst)

	// 4. First consume (should succeed)
	consumeReq := ConsumeRequest{
		UnblindedSignature: unblindedHex,
		Witness:            witnessHex,
		CredentialClass:    "replay_class",
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
	require.True(t, consumeResp.Valid, "first consume should succeed")

	// 5. Second consume (should fail with 409 Conflict)
	resp, err = makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)

	err = json.NewDecoder(resp.Body).Decode(&consumeResp)
	require.NoError(t, err)
	require.False(t, consumeResp.Valid, "second consume should be invalid")
	require.Contains(t, consumeResp.Error, "credential already redeemed")
}

// TestConsumeInvalidSignature verifies that a tampered signature is rejected.
func TestConsumeInvalidSignature(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	msg := []byte("tamper test")
	class := "tamper_class"

	// Get a valid credential
	_, witnessHex, epoch, _ := issueAndUnblind(t, ts, cfg, class, msg)

	tamperedBytes := make([]byte, 48)
	_, err := rand.Read(tamperedBytes)
	require.NoError(t, err)
	tamperedHex := hex.EncodeToString(tamperedBytes)

	consumeReq := ConsumeRequest{
		UnblindedSignature: tamperedHex,
		Witness:            witnessHex,
		CredentialClass:    class,
		KeyEpoch:           epoch,
	}
	jsonBody, err := json.Marshal(consumeReq)
	require.NoError(t, err)

	resp, err := makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// check error message
	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	require.NoError(t, err)
	require.Contains(t, errResp.Error, "invalid signature")
}

// TestConsumeWrongClass verifies that consuming a credential with the wrong class fails.
func TestConsumeWrongClass(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	msg := []byte("class test")
	issuedClass := "correct_class"
	wrongClass := "wrong_class"

	sigHex, witnessHex, epoch, _ := issueAndUnblind(t, ts, cfg, issuedClass, msg)

	consumeReq := ConsumeRequest{
		UnblindedSignature: sigHex,
		Witness:            witnessHex,
		CredentialClass:    wrongClass,
		KeyEpoch:           epoch,
	}
	jsonBody, err := json.Marshal(consumeReq)
	require.NoError(t, err)

	resp, err := makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail with 400 because verification fails.
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	require.NoError(t, err)
	require.Contains(t, errResp.Error, "invalid signature")
}

// TestConsumeWrongEpoch verifies that consuming with an unsupported epoch fails.
func TestConsumeWrongEpoch(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	msg := []byte("epoch test")
	class := "epoch_class"

	sigHex, witnessHex, _, _ := issueAndUnblind(t, ts, cfg, class, msg)
	// Our config supports "2026-01" and "2026-02". To test unsupported, we'll use "1970-01".
	wrongEpoch := "1970-01"

	consumeReq := ConsumeRequest{
		UnblindedSignature: sigHex,
		Witness:            witnessHex,
		CredentialClass:    class,
		KeyEpoch:           wrongEpoch,
	}
	jsonBody, err := json.Marshal(consumeReq)
	require.NoError(t, err)

	resp, err := makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Our config validation will reject unsupported epoch (should return 400).
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	require.NoError(t, err)
	require.Contains(t, errResp.Error, "unsupported key_epoch")
}

func TestConsumeMissingFields(t *testing.T) {
	ts, cfg := setupTestServer(t)
	defer ts.Close()

	jwt := generateJWT(cfg.AuthSecret)

	tests := []struct {
		name      string
		body      ConsumeRequest
		expectMsg string
	}{
		{
			name: "missing unblinded_signature",
			body: ConsumeRequest{
				UnblindedSignature: "",
				CredentialClass:    "test_class",
				Witness:            "10",
				KeyEpoch:           "10",
			},
			expectMsg: "missing required fields",
		},
		{
			name: "missing credential_class",
			body: ConsumeRequest{
				UnblindedSignature: "0123456789abcdef", // dummy hex
				CredentialClass:    "",
				Witness:            "10",
				KeyEpoch:           "10",
			},
			expectMsg: "missing required fields",
		},
		{
			name: "both missing",
			body: ConsumeRequest{
				UnblindedSignature: "",
				CredentialClass:    "",
				Witness:            "10",
				KeyEpoch:           "10",
			},
			expectMsg: "missing required fields",
		},
		{
			name: "invalid unblinded_signature (not hex)",
			body: ConsumeRequest{
				UnblindedSignature: "not-hex-value",
				CredentialClass:    "test_class",
				Witness:            "10",
				KeyEpoch:           "10",
			},
			expectMsg: "invalid request body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, err := json.Marshal(tt.body)
			require.NoError(t, err)

			resp, err := makeRequest(ts, "POST", "/v1/credential/consume", jsonBody, "Bearer "+jwt)
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
