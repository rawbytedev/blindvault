package api

import (
	"encoding/hex"
	"fmt"

	"github.com/rawbytedev/blindvault/internal/validation"
)

func ValidateHexLenght(s string, expectedBytes int) error {
	if s == "" {
		return fmt.Errorf("empty value")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != expectedBytes {
		return fmt.Errorf("invalid length: expected %d bytes, got %d", expectedBytes, len(b))
	}
	return nil
}

// ValidateIssueRequest performs basic sanity checks on an IssueRequest.
func ValidateIssueRequest(req *IssueRequest) error {
	if req == nil {
		return fmt.Errorf("request is nil")
	}
	if err := ValidateHexLenght(req.BlindedMessage, 48); err != nil {
		return fmt.Errorf("blinded_message: %w", err)
	}
	if !validation.Class(req.CredentialClass) {
		return fmt.Errorf("credential_class: must match %s", validation.ReClass.String())
	}
	return nil
} // ValidateConsumeRequest performs basic sanity checks on a ConsumeRequest.
func ValidateConsumeRequest(req *ConsumeRequest) error {
	if req == nil {
		return fmt.Errorf("request is nil")
	}
	if err := ValidateHexLenght(req.UnblindedSignature, 48); err != nil {
		return fmt.Errorf("unblinded_signature: %w", err)
	}
	if err := ValidateHexLenght(req.Witness, 48); err != nil {
		return fmt.Errorf("witness: %w", err)
	}
	if !validation.Class(req.CredentialClass) {
		return fmt.Errorf("credential_class: must match %s", validation.ReClass.String())
	}
	if !validation.Epoch(req.KeyEpoch) {
		return fmt.Errorf("key_epoch: must be YYYY-MM format")
	}
	return nil
}
