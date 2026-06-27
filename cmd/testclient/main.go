package main

import (
	"blindvault/pkg/crypto"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	baseURL := os.Getenv("BLINDVAULT_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "super-secret-token" // from default config
	}

	engine := crypto.NewBLS12Engine()
	dst := []byte("BCIS-V1-MESSAGE")
	msg := []byte("docker-e2e-test")

	// 1. Hash to curve
	point, err := engine.HashToCurve(msg, dst)
	if err != nil {
		panic(err)
	}

	// 2. Blind
	r, err := crypto.NewRandomScalar()
	if err != nil {
		panic(err)
	}
	blinded, err := engine.BlindMessage(point, r)
	if err != nil {
		panic(err)
	}
	blindedHex := hex.EncodeToString(blinded.Compress())

	// 3. Issue
	issueReq := map[string]string{
		"blinded_message":  blindedHex,
		"credential_class": "e2e_test",
	}
	issueBody, _ := json.Marshal(issueReq)

	req, _ := http.NewRequest("POST", baseURL+"/v1/credential/issue", bytes.NewReader(issueBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+generateJWT(secret))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		panic(fmt.Sprintf("issue failed: %d %s", resp.StatusCode, body))
	}

	var issueResp struct {
		BlindSignature string `json:"blind_signature"`
		PublicKey      string `json:"public_key"`
		KeyEpoch       string `json:"key_epoch"`
	}
	json.Unmarshal(body, &issueResp)

	// 4. Unblind
	sigBytes, _ := hex.DecodeString(issueResp.BlindSignature)
	sig, _ := crypto.DeserializeG1(sigBytes)
	unblinded, _ := engine.UnblindSignature(sig, r)
	unblindedHex := hex.EncodeToString(unblinded.Compress())

	// 5. Witness
	witness := hex.EncodeToString(point.Compress())

	// 6. Consume
	consumeReq := map[string]string{
		"unblinded_signature": unblindedHex,
		"witness":             witness,
		"credential_class":    "e2e_test",
		"key_epoch":           issueResp.KeyEpoch,
	}
	consumeBody, _ := json.Marshal(consumeReq)
	req2, _ := http.NewRequest("POST", baseURL+"/v1/credential/consume", bytes.NewReader(consumeBody))
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := http.DefaultClient.Do(req2)
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != 200 {
		panic(fmt.Sprintf("consume failed: %d %s", resp2.StatusCode, body2))
	}
	fmt.Println("✅ First consume successful")

	// 7. Replay (should fail)
	req3, _ := http.NewRequest("POST", baseURL+"/v1/credential/consume", bytes.NewReader(consumeBody))
	req3.Header.Set("Content-Type", "application/json")
	resp3, _ := http.DefaultClient.Do(req3)
	resp3.Body.Close()

	if resp3.StatusCode != 409 {
		panic(fmt.Sprintf("replay should fail with 409, got %d", resp3.StatusCode))
	}
	fmt.Println("✅ Replay rejected (409) - all good!")

	// 8. Print success
	fmt.Println("🎉 End-to-end test passed against Docker container!")
}

func generateJWT(secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-client",
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString

}
