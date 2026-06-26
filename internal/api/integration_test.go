package api

import (
	"bytes"
	"crypto/rand"
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

func unblindSignature(t *testing.T, engine *crypto.BLS12Engine, blindSigHex string, r crypto.Scalar) string {
	sigBytes, err := hex.DecodeString(blindSigHex)
	require.NoError(t, err)
	sig, err := crypto.DeserializeG1(sigBytes)
	require.NoError(t, err)

	unblinded, err := engine.UnblindSignature(sig, r)
	require.NoError(t, err)

	return hex.EncodeToString(unblinded.Compress())
}

// createWitness returns the G1 point H(msg) as hex.
func createWitness(t *testing.T, engine *crypto.BLS12Engine, msg []byte, dst []byte) string {
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

// verifyDLEQProof uses the crypto engine to verify the DLEQ proof.
func verifyDLEQProof(t *testing.T, engine *crypto.BLS12Engine, proof DLEQProof, blindedHex string, blindSigHex string, pkHex string) bool {
	// Deserialize blinded point, signature, and public key.
	blindedBytes, err := hex.DecodeString(blindedHex)
	require.NoError(t, err)
	blinded, err := crypto.DeserializeG1(blindedBytes)
	require.NoError(t, err)

	sigBytes, err := hex.DecodeString(blindSigHex)
	require.NoError(t, err)
	sig, err := crypto.DeserializeG1(sigBytes)
	require.NoError(t, err)

	pkBytes, err := hex.DecodeString(pkHex)
	require.NoError(t, err)
	pk, err := crypto.DeserializeG2(pkBytes)
	require.NoError(t, err)
	r1, err := hex.DecodeString(proof.R1)
	require.NoError(t, err)
	r2, err := hex.DecodeString(proof.R2)
	require.NoError(t, err)
	s, err := hex.DecodeString(proof.S)
	require.NoError(t, err)
	c, err := hex.DecodeString(proof.C)
	require.NoError(t, err)
	// Reconstruct DLEQProof struct
	R1, err := crypto.DeserializeG2(r1)
	require.NoError(t, err)
	R2, err := crypto.DeserializeG1(r2)
	require.NoError(t, err)
	S, err := crypto.NewBlstScalarFromBytes(s)
	require.NoError(t, err)
	C, err := crypto.NewBlstScalarFromBytes(c)
	require.NoError(t, err)

	dleqProof := &crypto.DLEQProof{
		R1: R1,
		R2: R2,
		S:  S,
		C:  C,
	}
	return engine.DLEQVerify(dleqProof, blinded, sig, pk)
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
			if tt.name == "invalid blinded_message (not hex)" {
				// the service will fail during deserialization and return 500,
				require.Equal(t, http.StatusInternalServerError, resp.StatusCode, "expected 500 for invalid hex")
				// check error message
				var errResp ErrorResponse
				err = json.NewDecoder(resp.Body).Decode(&errResp)
				require.NoError(t, err)
				require.Contains(t, errResp.Error, "issuance failed")
			} else {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected 400 for missing fields")
				// check error message
				var errResp ErrorResponse
				err = json.NewDecoder(resp.Body).Decode(&errResp)
				require.NoError(t, err)
				require.Contains(t, errResp.Error, "missing required fields")
			}
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
			expectedStatus: http.StatusInternalServerError, // auth passes, but deserialization fails
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

	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// check error message
	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	require.NoError(t, err)
	require.Contains(t, errResp.Error, "consumption failed")
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

	// Should fail with 500 because verification fails.
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	require.NoError(t, err)
	require.Contains(t, errResp.Error, "consumption failed")
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
		// It should fail with internal error (500) because verification fails
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode, "consume with wrong class should fail")
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
	// Should fail (500) because verification fails (key mismatch)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

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

	// The rate limiter allows 100 requests per minute with a burst of 20.
	// The first 100 should succeed, the 101st should be rate-limited.
	const totalRequests = 101
	successCount := 0
	for i := 0; i < totalRequests; i++ {
		resp, err := makeRequest(ts, "POST", "/v1/credential/issue", jsonBody, authHeader)
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			successCount++
		} else if resp.StatusCode == http.StatusTooManyRequests {
			t.Logf("Request %d rate limited", i+1)
		} else {
			t.Fatalf("unexpected status code %d on request %d", resp.StatusCode, i+1)
		}
	}

	if successCount == totalRequests {
		t.Error("rate limiter did not reject any requests, expected at least one 429")
	}
}
