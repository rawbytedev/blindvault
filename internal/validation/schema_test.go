package validation_test

import (
	"encoding/hex"
	"testing"

	"github.com/rawbytedev/blindvault/internal/api"
	"github.com/rawbytedev/blindvault/internal/validation"
)

func TestValidateIssueRequest(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		req := api.IssueRequest{
			BlindedMessage:  validHex48(),
			CredentialClass: "tier_gold",
		}
		if err := validation.ValidateIssueRequest(req); err != nil {
			t.Fatalf("ValidateIssueRequest() unexpected error: %v", err)
		}
	})

	t.Run("empty blinded message", func(t *testing.T) {
		req := api.IssueRequest{CredentialClass: "tier_gold"}
		if err := validation.ValidateIssueRequest(req); err == nil {
			t.Fatal("ValidateIssueRequest() expected error for empty blinded message")
		}
	})

	t.Run("oversized blinded message", func(t *testing.T) {
		req := api.IssueRequest{
			BlindedMessage:  "00" + makeHex(100),
			CredentialClass: "tier_gold",
		}
		if err := validation.ValidateIssueRequest(req); err == nil {
			t.Fatal("ValidateIssueRequest() expected error for oversized blinded message")
		}
	})

	t.Run("malformed blinded message", func(t *testing.T) {
		req := api.IssueRequest{
			BlindedMessage:  "zzzz",
			CredentialClass: "tier_gold",
		}
		if err := validation.ValidateIssueRequest(req); err == nil {
			t.Fatal("ValidateIssueRequest() expected error for malformed blinded message")
		}
	})
}

func TestValidateConsumeRequest(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		req := api.ConsumeRequest{
			UnblindedSignature: validHex48(),
			Witness:            validHex48(),
			CredentialClass:    "tier_gold",
			KeyEpoch:           "2026-01",
		}
		if err := validation.ValidateConsumeRequest(req); err != nil {
			t.Fatalf("ValidateConsumeRequest() unexpected error: %v", err)
		}
	})

	t.Run("empty witness", func(t *testing.T) {
		req := api.ConsumeRequest{
			UnblindedSignature: validHex48(),
			CredentialClass:    "tier_gold",
			KeyEpoch:           "2026-01",
		}
		if err := validation.ValidateConsumeRequest(req); err == nil {
			t.Fatal("ValidateConsumeRequest() expected error for empty witness")
		}
	})

	t.Run("oversized witness", func(t *testing.T) {
		req := api.ConsumeRequest{
			UnblindedSignature: validHex48(),
			Witness:            "00" + makeHex(100),
			CredentialClass:    "tier_gold",
			KeyEpoch:           "2026-01",
		}
		if err := validation.ValidateConsumeRequest(req); err == nil {
			t.Fatal("ValidateConsumeRequest() expected error for oversized witness")
		}
	})

	t.Run("malformed epoch", func(t *testing.T) {
		req := api.ConsumeRequest{
			UnblindedSignature: validHex48(),
			Witness:            validHex48(),
			CredentialClass:    "tier_gold",
			KeyEpoch:           "2026/01",
		}
		if err := validation.ValidateConsumeRequest(req); err == nil {
			t.Fatal("ValidateConsumeRequest() expected error for malformed epoch")
		}
	})
}

func validHex48() string {
	buf := make([]byte, 48)
	for i := range buf {
		buf[i] = byte(i + 1)
	}
	return hex.EncodeToString(buf)
}

func makeHex(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}
