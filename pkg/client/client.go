package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"blindvault/internal/api"
	"blindvault/pkg/crypto"
)

// Client provides high-level operations for BlindVault.
type Client struct {
	serverURL string
	dst       []byte
	engine    crypto.Engine
	state     *State
	http      *http.Client
}

// Config configures the client.
type Config struct {
	ServerURL string
	DST       []byte
}

// NewClient creates a new client.
func NewClient(cfg *Config) (*Client, error) {
	state, err := NewState()
	if err != nil {
		return nil, err
	}
	return &Client{
		serverURL: cfg.ServerURL,
		dst:       cfg.DST,
		engine:    crypto.NewBLS12Engine(),
		state:     state,
		http:      &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// BlindResult contains the blinded point, witness, and a local ID for later unblinding.
type BlindResult struct {
	Blinded   crypto.PointG1
	Witness   crypto.PointG1
	RequestID string // internal handle for the stored blinding factor
}

// Blind hashes the message, blinds it, and stores the blinding factor locally.
func (c *Client) Blind(msg []byte) (*BlindResult, error) {
	// 1. Hash to curve
	point, err := c.engine.HashToCurve(msg, c.dst)
	if err != nil {
		return nil, err
	}
	// 2. Generate blinding scalar
	r, err := crypto.NewRandomScalar()
	if err != nil {
		return nil, err
	}
	// 3. Blind
	blinded, err := c.engine.BlindMessage(point, r)
	if err != nil {
		return nil, err
	}
	// 4. Store scalar and witness locally
	id, err := c.state.Store(r, msg, point)
	if err != nil {
		return nil, err
	}
	return &BlindResult{
		Blinded:   blinded,
		Witness:   point,
		RequestID: id,
	}, nil
}

// VerifyProof validates the DLEQ proof.
func (c *Client) VerifyProof(proof *crypto.DLEQProof, blinded crypto.PointG1, sig crypto.PointG1, pk crypto.PointG2) bool {
	return c.engine.DLEQVerify(proof, blinded, sig, pk)
}

// Unblind retrieves the stored blinding factor and unblinds the signature.
func (c *Client) Unblind(requestID string, blindSig crypto.PointG1) (crypto.PointG1, error) {
	req, err := c.state.Get(requestID)
	if err != nil {
		return nil, err
	}
	// Reconstruct scalar from stored bytes
	r, err := crypto.NewBlstScalarFromBytes(req.BlindingFactor)
	if err != nil {
		return nil, err
	}
	unblinded, err := c.engine.UnblindSignature(blindSig, r)
	if err != nil {
		return nil, err
	}
	// Optionally delete the request to avoid reuse
	_ = c.state.Delete(requestID)
	return unblinded, nil
}

// Redeem sends the unblinded signature and witness for consumption.
func (c *Client) Redeem(sig crypto.PointG1, witness crypto.PointG1, class, epoch string) (bool, error) {
	req := api.ConsumeRequest{
		UnblindedSignature: hex.EncodeToString(sig.Compress()),
		Witness:            hex.EncodeToString(witness.Compress()),
		CredentialClass:    class,
		KeyEpoch:           epoch,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Post(c.serverURL+"/v1/credential/consume", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 409 {
		// Already redeemed
		var errResp struct {
			Error string `json:"error"`
		}
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		if err != nil {
			return false, fmt.Errorf("credential already redeemed: %s", errResp.Error)
		}
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Valid, nil
}

// GetRequest retrieves a pending request by ID (for debugging/testing).
func (c *Client) GetRequest(id string) (*PendingRequest, error) {
	return c.state.Get(id)
}
