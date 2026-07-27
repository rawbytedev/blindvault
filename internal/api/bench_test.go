package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rawbytedev/blindvault/internal/service"
	"github.com/rawbytedev/blindvault/pkg/crypto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

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

// ----- Benchmarks for /health (pure middleware baseline) -----

func BenchmarkHealthHandler(b *testing.B) {
	ts, _, _ := setupBenchServer(b)
	defer ts.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	}
}

// ----- Benchmarks for POST /v1/credential/issue -----

func BenchmarkIssueHandler(b *testing.B) {
	ts, _, authHeader := setupBenchServer(b)
	defer ts.Close()

	// Pre-generate a batch of blinded messages to avoid serialization overhead
	// inside the benchmark loop, keeping the test focused on the handler + service.
	type issueData struct {
		blindedHex string
		r          crypto.Scalar
	}

	// Generate enough for the benchmark
	const batchSize = 10000
	batch := make([]issueData, batchSize)
	for i := 0; i < batchSize && i < b.N; i++ {
		blindedHex, r := generateBenchBlindedMessage(b)
		batch[i] = issueData{blindedHex: blindedHex, r: r}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % batchSize
		reqBody := IssueRequest{
			BlindedMessage:  batch[idx].blindedHex,
			CredentialClass: "bench_class",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", ts.URL+"/v1/credential/issue", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", string(authHeader))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode != http.StatusTooManyRequests {
				b.Fatalf("expected 200, got %d", resp.StatusCode)
			}
		}
	}
}

// ----- Benchmarks for POST /v1/credential/consume -----

func BenchmarkConsumeHandler(b *testing.B) {
	ts, cfg, authHeader := setupBenchServer(b)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	dst := []byte(cfg.DST)

	// Pre-issue a batch of valid credentials (1 per iteration, capped at 10k).
	type consumeData struct {
		unblindedSigHex string
		witnessHex      string
		epoch           string
		class           string
	}

	const batchSize = 10000
	batch := make([]consumeData, batchSize)

	// create crendetials
	for i := 0; i < batchSize && i < b.N; i++ {
		msg := []byte(fmt.Sprintf("bench-consume-%d", i))
		point, _ := engine.HashToCurve(msg, dst)
		r, _ := crypto.NewRandomScalar()
		blinded, _ := engine.BlindMessage(point, r)

		// Issue via HTTP
		reqBody := IssueRequest{
			BlindedMessage:  hex.EncodeToString(blinded.Compress()),
			CredentialClass: "bench_consume_class",
		}
		jsonBody, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", ts.URL+"/v1/credential/issue", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", string(authHeader))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		var issueResp IssueResponse
		if err := json.NewDecoder(resp.Body).Decode(&issueResp); err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("issue failed: %d", resp.StatusCode)
		}

		// Unblind
		sigBytes, _ := hex.DecodeString(issueResp.BlindSignature)
		sig, _ := crypto.DeserializeG1(sigBytes)
		unblinded, _ := engine.UnblindSignature(sig, r)

		batch[i] = consumeData{
			unblindedSigHex: hex.EncodeToString(unblinded.Compress()),
			witnessHex:      hex.EncodeToString(point.Compress()),
			epoch:           issueResp.KeyEpoch,
			class:           "bench_consume_class",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % batchSize
		reqBody := ConsumeRequest{
			UnblindedSignature: batch[idx].unblindedSigHex,
			Witness:            batch[idx].witnessHex,
			CredentialClass:    batch[idx].class,
			KeyEpoch:           batch[idx].epoch,
		}
		jsonBody, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", ts.URL+"/v1/credential/consume", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	}
}

// ----- Benchmarks for the full end-to-end flow (issue + consume) -----

func BenchmarkFullHandlerFlow(b *testing.B) {
	ts, _, authHeader := setupBenchServer(b)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	dst := []byte("BCIS-TEST")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 1. Blind
		msg := []byte(fmt.Sprintf("bench-full-%d", i))
		point, _ := engine.HashToCurve(msg, dst)
		r, _ := crypto.NewRandomScalar()
		blinded, _ := engine.BlindMessage(point, r)

		// 2. Issue
		issueReq := IssueRequest{
			BlindedMessage:  hex.EncodeToString(blinded.Compress()),
			CredentialClass: "bench_full_class",
		}
		jsonBody, _ := json.Marshal(issueReq)
		req, _ := http.NewRequest("POST", ts.URL+"/v1/credential/issue", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", string(authHeader))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		var issueResp IssueResponse
		if err := json.NewDecoder(resp.Body).Decode(&issueResp); err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("issue failed: %d", resp.StatusCode)
		}

		// 3. Unblind
		sigBytes, _ := hex.DecodeString(issueResp.BlindSignature)
		sig, _ := crypto.DeserializeG1(sigBytes)
		unblinded, _ := engine.UnblindSignature(sig, r)

		// 4. Consume
		consumeReq := ConsumeRequest{
			UnblindedSignature: hex.EncodeToString(unblinded.Compress()),
			Witness:            hex.EncodeToString(point.Compress()),
			CredentialClass:    "bench_full_class",
			KeyEpoch:           issueResp.KeyEpoch,
		}
		jsonBody, _ = json.Marshal(consumeReq)
		req, _ = http.NewRequest("POST", ts.URL+"/v1/credential/consume", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("consume failed: %d", resp.StatusCode)
		}
	}
}

// ----- Benchmarks for replay detection (409 Conflict) -----

func BenchmarkConsumeReplayHandler(b *testing.B) {
	ts, cfg, authHeader := setupBenchServer(b)
	defer ts.Close()

	engine := crypto.NewBLS12Engine()
	dst := []byte(cfg.DST)

	// Pre-issue a single credential that we'll replay.
	msg := []byte("bench-replay")
	point, _ := engine.HashToCurve(msg, dst)
	r, _ := crypto.NewRandomScalar()
	blinded, _ := engine.BlindMessage(point, r)

	issueReq := IssueRequest{
		BlindedMessage:  hex.EncodeToString(blinded.Compress()),
		CredentialClass: "bench_replay_class",
	}
	jsonBody, _ := json.Marshal(issueReq)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/credential/issue", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", string(authHeader))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	var issueResp IssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&issueResp); err != nil {
		b.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("issue failed: %d", resp.StatusCode)
	}

	sigBytes, _ := hex.DecodeString(issueResp.BlindSignature)
	sig, _ := crypto.DeserializeG1(sigBytes)
	unblinded, _ := engine.UnblindSignature(sig, r)

	consumeReq := ConsumeRequest{
		UnblindedSignature: hex.EncodeToString(unblinded.Compress()),
		Witness:            hex.EncodeToString(point.Compress()),
		CredentialClass:    "bench_replay_class",
		KeyEpoch:           issueResp.KeyEpoch,
	}
	jsonBody, _ = json.Marshal(consumeReq)

	// First, consume it once (outside the benchmark loop) so we start in a "replay" state.
	req, _ = http.NewRequest("POST", ts.URL+"/v1/credential/consume", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("first consume failed: %d", resp.StatusCode)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/credential/consume", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		// We expect 409 Conflict on every subsequent attempt
		if resp.StatusCode != http.StatusConflict {
			b.Fatalf("expected 409, got %d", resp.StatusCode)
		}
	}
}
