package main_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"blindvault/pkg/crypto"

	"github.com/stretchr/testify/require"
)

// TestCLIIntegration runs the full flow using the compiled binary.
// It requires the binary to be built first.
func TestCLIIntegration(t *testing.T) {
	// Build the CLI binary
	binary := buildCLI(t)

	// Set up a temporary home for state
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Start a mock server that handles issue and consume
	mux := http.NewServeMux()
	var lastIssueRequest struct {
		Blinded string `json:"blinded_message"`
		Class   string `json:"credential_class"`
	}
	mux.HandleFunc("/v1/credential/issue", func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		var req struct {
			BlindedMessage  string `json:"blinded_message"`
			CredentialClass string `json:"credential_class"`
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		lastIssueRequest.Blinded = req.BlindedMessage
		lastIssueRequest.Class = req.CredentialClass

		// Generate a dummy blind signature using a fixed key for reproducibility
		engine := crypto.NewBLS12Engine()
		skBytes, _ := hex.DecodeString("4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123")
		sk, _ := crypto.NewBlstScalarFromBytes(skBytes)
		blindedBytes, _ := hex.DecodeString(req.BlindedMessage)
		blinded, _ := crypto.DeserializeG1(blindedBytes)
		sig, _ := engine.SignBlinded(blinded, sk)
		pk := sk.PubKey()
		proof, _ := engine.DLEQProve(sk, blinded, pk)
		s := proof.S.Bytes()
		c := proof.C.Bytes()
		resp := map[string]interface{}{
			"blind_signature": hex.EncodeToString(sig.Compress()),
			"public_key":      hex.EncodeToString(pk.Compress()),
			"key_epoch":       "2026-01",
			"proof": map[string]string{
				"r1": hex.EncodeToString(proof.R1.Compress()),
				"r2": hex.EncodeToString(proof.R2.Compress()),
				"s":  hex.EncodeToString(s[:]),
				"c":  hex.EncodeToString(c[:]),
			},
		}
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/credential/consume", func(w http.ResponseWriter, r *http.Request) {
		// Accept any request and return valid
		json.NewEncoder(w).Encode(map[string]bool{"valid": true})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// --- Step 1: blind command ---
	t.Log("Running `bv blind`")
	out, err := runCommand(t, binary, "blind", "--message", "hello", "--server", ts.URL)
	require.NoError(t, err)
	var blindResult struct {
		Blinded   string `json:"blinded"`
		Witness   string `json:"witness"`
		RequestID string `json:"request_id"`
	}
	err = json.Unmarshal(out, &blindResult)
	require.NoError(t, err)
	require.NotEmpty(t, blindResult.Blinded)
	require.NotEmpty(t, blindResult.Witness)
	require.NotEmpty(t, blindResult.RequestID)

	// Get the proof data from the mock server by issuing directly via HTTP.
	issueReq := map[string]string{
		"blinded_message":  blindResult.Blinded,
		"credential_class": "test",
	}
	issueBody, _ := json.Marshal(issueReq)
	resp, err := http.Post(ts.URL+"/v1/credential/issue", "application/json", bytes.NewReader(issueBody))
	require.NoError(t, err)
	var issueResp struct {
		BlindSignature string `json:"blind_signature"`
		PublicKey      string `json:"public_key"`
		KeyEpoch       string `json:"key_epoch"`
		Proof          struct {
			R1 string `json:"r1"`
			R2 string `json:"r2"`
			S  string `json:"s"`
			C  string `json:"c"`
		} `json:"proof"`
	}
	json.NewDecoder(resp.Body).Decode(&issueResp)
	resp.Body.Close()

	// Now run verify command with the proof
	t.Log("Running `bv verify`")
	verifyArgs := []string{
		"verify",
		"--blinded", blindResult.Blinded,
		"--signature", issueResp.BlindSignature,
		"--public-key", issueResp.PublicKey,
		"--proof-r1", issueResp.Proof.R1,
		"--proof-r2", issueResp.Proof.R2,
		"--proof-s", issueResp.Proof.S,
		"--proof-c", issueResp.Proof.C,
		"--server", ts.URL,
	}
	outVerify, err := runCommand(t, binary, verifyArgs...)
	require.NoError(t, err)
	require.Contains(t, string(outVerify), "DLEQ proof is valid")

	// --- Step 3: unblind command ---
	t.Log("Running `bv unblind`")
	unblindArgs := []string{
		"unblind",
		"--signature", issueResp.BlindSignature,
		"--id", blindResult.RequestID,
		"--server", ts.URL,
	}
	outUnblind, err := runCommand(t, binary, unblindArgs...)
	require.NoError(t, err)
	// Output should be "Unblinded signature: <hex>"
	require.Contains(t, string(outUnblind), "Unblinded signature:")

	// Extract the unblinded signature from output
	unblindedHex := string(outUnblind)
	unblindedHex = unblindedHex[len("Unblinded signature: "):]
	unblindedHex = unblindedHex[:len(unblindedHex)-1] // remove newline

	// --- Step 4: redeem command ---
	t.Log("Running `bv redeem`")
	redeemArgs := []string{
		"redeem",
		"--signature", unblindedHex,
		"--witness", blindResult.Witness,
		"--class", "test",
		"--epoch", "2026-01",
		"--server", ts.URL,
	}
	outRedeem, err := runCommand(t, binary, redeemArgs...)
	require.NoError(t, err)
	require.Contains(t, string(outRedeem), "Credential redeemed successfully")
}

// buildCLI builds the CLI binary and returns its path.
func buildCLI(t *testing.T) string {
	dir := t.TempDir()
	binary := filepath.Join(dir, "bv")
	if testing.Short() {
		t.Skip("Skipping CLI build in short mode")
	}
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/bv")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	require.NoError(t, err, "failed to build CLI")
	return binary
}

// runCommand executes the binary with args and returns stdout and error.
func runCommand(t *testing.T, binary string, args ...string) ([]byte, error) {
	cmd := exec.Command(binary, args...)
	cmd.Env = os.Environ() // inherit environment, including HOME override
	out, err := cmd.Output()
	if err != nil {
		// If there was an error, include stderr in the error message
		if ee, ok := err.(*exec.ExitError); ok {
			return out, fmt.Errorf("command failed: %v, stderr: %s", err, ee.Stderr)
		}
		return out, err
	}
	return out, nil
}
