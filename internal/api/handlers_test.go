package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/rawbytedev/blindvault/v2/internal/service"
	"github.com/stretchr/testify/require"
)

func setupTestDummyServer(t *testing.T) (*httptest.Server, *service.Config) {
	cfg := &service.Config{
		ListenAddr:      ":8080",
		MasterSeedHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		ActiveEpoch:     "2026-01",
		SupportedEpochs: []string{"2026-01", "2026-02"},
		DST:             "BCIS-TEST",
		AuthSecret:      "test-secret",
		UseMemoryStore:  true,
		RateLimitBurst:  20,
		RateLimit:       100,
	}
	server, err := NewServer(cfg)
	server.credentialService = &DummyCredentialService{}
	require.NoError(t, err)
	ts := httptest.NewServer(server.httpServer.Handler)
	return ts, cfg
}

type DummyCredentialService struct{}

func (d *DummyCredentialService) Issue(ctx context.Context, blindedMessage string, credentialClass string) (*service.IssueResult, error) {
	if blindedMessage == "error" {
		return nil, errors.New("dummy error")
	}
	return &service.IssueResult{
		BlindSignature: "dummy_blind_signature",
		PublicKey:      "dummy_public_key",
		KeyEpoch:       "dummy_key_epoch",
		Proof: &service.DLEQProofSerialized{
			R1: "dummy_r1",
			R2: "dummy_r2",
			S:  "dummy_s",
			C:  "dummy_c",
		},
	}, nil
}

func (d *DummyCredentialService) Consume(ctx context.Context, blindedSignature, witness, credentialClass, keyEpoch string) (*service.ConsumeResult, error) {
	if blindedSignature == "error" {
		return nil, errors.New("dummy error")
	}
	return &service.ConsumeResult{
		Status: "success",
		Error:  "",
	}, nil

}
func (d *DummyCredentialService) Ping(ctx context.Context) error {
	return nil
}
func (d *DummyCredentialService) Close() error {
	return nil
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
