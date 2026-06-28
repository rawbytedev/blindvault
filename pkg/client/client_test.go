package client_test

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"blindvault/pkg/client"
	"blindvault/pkg/crypto"

	"github.com/stretchr/testify/require"
)

func TestClient_Blind(t *testing.T) {
	// Use a temporary home for state
	home := t.TempDir()
	t.Setenv("HOME", home)

	cli, err := client.NewClient(&client.Config{
		ServerURL: "http://localhost:8080",
		DST:       []byte("BCIS-TEST"),
	})
	require.NoError(t, err)

	result, err := cli.Blind([]byte("test message"))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Blinded)
	require.NotNil(t, result.Witness)
	require.NotEmpty(t, result.RequestID)

	// Verify the state file was created
	statePath := filepath.Join(home, ".blindvault", "state.json")
	_, err = os.Stat(statePath)
	require.NoError(t, err)

	// Verify the request is stored
	req, err := cli.GetRequest(result.RequestID) // we need to expose this or test via unblind
	require.NoError(t, err)
	require.NotNil(t, req)
}

func TestClient_VerifyProof(t *testing.T) {
	// We need a full proof; we'll generate one using the engine
	engine := crypto.NewBLS12Engine()
	skBytes, _ := hex.DecodeString("4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123")
	sk, err := crypto.NewBlstScalarFromBytes(skBytes)
	require.NoError(t, err)
	pk := sk.PubKey()

	msg := []byte("test")
	dst := []byte("BCIS-TEST")
	point, err := engine.HashToCurve(msg, dst)
	require.NoError(t, err)

	r, err := crypto.NewRandomScalar()
	require.NoError(t, err)

	blinded, err := engine.BlindMessage(point, r)
	require.NoError(t, err)

	sig, err := engine.SignBlinded(blinded, sk)
	require.NoError(t, err)

	proof, err := engine.DLEQProve(sk, blinded, pk)
	require.NoError(t, err)

	// Now test the client's VerifyProof
	cli, err := client.NewClient(&client.Config{
		ServerURL: "http://localhost:8080",
		DST:       dst,
	})
	require.NoError(t, err)

	valid := cli.VerifyProof(proof, blinded, sig, pk)
	require.True(t, valid)

	// Tamper with the proof to ensure it fails
	badProof := &crypto.DLEQProof{
		R1: proof.R1,
		R2: proof.R2,
		S:  proof.S,
		C:  r, // wrong challenge
	}
	valid = cli.VerifyProof(badProof, blinded, sig, pk)
	require.False(t, valid)
}

func TestClient_Unblind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cli, err := client.NewClient(&client.Config{
		ServerURL: "http://localhost:8080",
		DST:       []byte("BCIS-TEST"),
	})
	require.NoError(t, err)

	// First blind a message to store the scalar
	result, err := cli.Blind([]byte("test unblind"))
	require.NoError(t, err)

	// Create a blind signature (simulate server response)
	// We'll generate a real signature using a fixed key for consistency.
	engine := crypto.NewBLS12Engine()
	skBytes, _ := hex.DecodeString("4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123")
	sk, _ := crypto.NewBlstScalarFromBytes(skBytes)
	blindSig, err := engine.SignBlinded(result.Blinded, sk)
	require.NoError(t, err)

	// Unblind
	unblinded, err := cli.Unblind(result.RequestID, blindSig)
	require.NoError(t, err)
	require.NotNil(t, unblinded)

	// Verify the state entry was deleted
	req, err := cli.GetRequest(result.RequestID)
	require.Error(t, err) // should be not found
	require.Nil(t, req)
}

func TestClient_Redeem(t *testing.T) {
	// Mock server that expects a consume request and returns success
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/credential/consume", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UnblindedSignature string `json:"unblinded_signature"`
			Witness            string `json:"witness"`
			CredentialClass    string `json:"credential_class"`
			KeyEpoch           string `json:"key_epoch"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.UnblindedSignature == "" || req.Witness == "" || req.CredentialClass == "" || req.KeyEpoch == "" {
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}
		err = json.NewEncoder(w).Encode(map[string]bool{"valid": true})
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := client.NewClient(&client.Config{
		ServerURL: ts.URL,
		DST:       []byte("BCIS-TEST"),
	})
	require.NoError(t, err)
	sk, err := crypto.NewRandomScalar()
	require.NoError(t, err, "Error while generating random scalar")
	// Create dummy points (only checks calls)
	engine := crypto.NewBLS12Engine()
	point, _ := engine.HashToCurve([]byte("test"), []byte("BCIS-TEST"))
	sig, _ := engine.SignBlinded(point, sk)

	valid, err := cli.Redeem(sig, point, "test_class", "2026-01")
	require.NoError(t, err)
	require.True(t, valid)
}

func TestClient_RedeemReplay(t *testing.T) {
	// Mock server returning 409 Conflict
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/credential/consume", func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]string{"error": "credential already redeemed"})
		w.WriteHeader(http.StatusConflict)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli, err := client.NewClient(&client.Config{
		ServerURL: ts.URL,
		DST:       []byte("BCIS-TEST"),
	})
	require.NoError(t, err)

	sk, err := crypto.NewRandomScalar()
	require.NoError(t, err, "Error while generating random scalar")
	// Create dummy points (only checks calls)
	engine := crypto.NewBLS12Engine()
	point, _ := engine.HashToCurve([]byte("test"), []byte("BCIS-TEST"))
	sig, _ := engine.SignBlinded(point, sk)

	valid, err := cli.Redeem(sig, point, "test_class", "2026-01")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already redeemed")
	require.False(t, valid)
}
