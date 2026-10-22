// Package api defines the HTTP request and response models for BlindVault.
package api

import "time"

// ----- Issue Request -----
type IssueRequest struct {
	BlindedMessage  string `json:"blinded_message" validate:"required,hex_len=48"` // hex-encoded compressed G1 point
	CredentialClass string `json:"credential_class" validate:"required,class"`     // e.g., "tier_gold"
}

type IssueResponse struct {
	BlindSignature string    `json:"blind_signature"` // hex-encoded compressed G1 point
	PublicKey      string    `json:"public_key"`      // hex-encoded compressed G2 point
	KeyEpoch       string    `json:"key_epoch"`       // e.g., "2026-01"
	Proof          DLEQProof `json:"proof"`
}

// ----- Consume Request -----
type ConsumeRequest struct {
	UnblindedSignature string `json:"unblinded_signature" validate:"required,hex_len=48"` // hex-encoded compressed G1 point (σ)
	Witness            string `json:"witness" validate:"required,hex_len=48"`             // hex-encoded compressed G1 point (Y = H(msg))
	CredentialClass    string `json:"credential_class" validate:"required,class"`         // must match issuance
	KeyEpoch           string `json:"key_epoch" validate:"required,epoch"`                // must match issuance
}

type ConsumeResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// ----- Error Response -----
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details,omitempty"`
}

type DLEQProof struct {
	R1 string `json:"r1"` // compressed G2 point
	R2 string `json:"r2"` // compressed G1 point
	S  string `json:"s"`  // hex-encoded scalar
	C  string `json:"c"`  // hex-encoded scalar
}

type AdminRevokeRequest struct {
	CredentialClass string     `json:"credential_class" validate:"required,class"`
	KeyEpoch        string     `json:"key_epoch"         validate:"omitempty,epoch"`
	Reason          string     `json:"reason"            validate:"required"`
	RevokedUntil    *time.Time `json:"revoked_until,omitempty" validate:"omitempty,gt"`
}

type AdminUnrevokeRequest struct {
	CredentialClass string `json:"credential_class" validate:"required,class"`
	KeyEpoch        string `json:"key_epoch" validate:"omitempty,epoch"`
}
