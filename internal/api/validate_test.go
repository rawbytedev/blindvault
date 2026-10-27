package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func makeHex(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}
func TestValidateIssueRequest(t *testing.T) {
	val := makeHex(96)
	tests := []struct {
		name    string
		request *IssueRequest
		wantErr bool
	}{
		{
			name: "Valid request",
			request: &IssueRequest{
				BlindedMessage:  val,
				CredentialClass: "gold",
			},
			wantErr: false,
		},
		{
			name: "Invalid request - empty blinded message",
			request: &IssueRequest{
				BlindedMessage:  "",
				CredentialClass: "This is a test message.",
			},
			wantErr: true,
		},
		{
			name: "Invalid request - empty credential class",
			request: &IssueRequest{
				BlindedMessage:  "2E1D1EC96CD81F0018A4194E4DFCE8130C246A3B7ACD4735",
				CredentialClass: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIssueRequest(*tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

		})
	}
}

func TestValidateConsumeRequest(t *testing.T) {
	val := makeHex(96)
	tests := []struct {
		name    string
		request *ConsumeRequest
		wantErr bool
	}{
		{
			name: "Valid request",
			request: &ConsumeRequest{
				UnblindedSignature: val,
				Witness:            val,
				CredentialClass:    "gold",
				KeyEpoch:           "2024-01",
			},
			wantErr: false,
		},
		{
			name: "Invalid request - empty unblinded signature",
			request: &ConsumeRequest{
				UnblindedSignature: "",
				Witness:            val,
				CredentialClass:    "gold",
				KeyEpoch:           "2024-01",
			},
			wantErr: true,
		},
		{
			name: "Invalid request - empty witness",
			request: &ConsumeRequest{
				UnblindedSignature: val,
				Witness:            "",
				CredentialClass:    "gold",
				KeyEpoch:           "2024-01",
			},
			wantErr: true,
		},
		{
			name: "Invalid request - empty credential class",
			request: &ConsumeRequest{
				UnblindedSignature: val,
				Witness:            val,
				CredentialClass:    "",
				KeyEpoch:           "2024-01",
			},
			wantErr: true,
		},
		{
			name: "Invalid request - empty key epoch",
			request: &ConsumeRequest{
				UnblindedSignature: val,
				Witness:            val,
				CredentialClass:    "gold",
				KeyEpoch:           "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConsumeRequest(*tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAdminRevokeRequest(t *testing.T) {
	val := "gold"
	now := time.Now().UTC()
	tests := []struct {
		name    string
		request *AdminRevokeRequest
		wantErr bool
	}{
		{
			name: "Valid request - nothing omitted",
			request: &AdminRevokeRequest{
				CredentialClass: val,
				KeyEpoch:        "2024-01",
				Reason:          "Test reason",
				//RevokedUntil:    &now,
			},
			wantErr: false,
		}, {
			name: "Valid request - key epoch omitted",
			request: &AdminRevokeRequest{
				CredentialClass: val,
				KeyEpoch:        "",
				Reason:          "Test reason",
				//RevokedUntil:    &now,
			},
			wantErr: false,
		},
		{
			name: "Valid request - revoked until omitted",
			request: &AdminRevokeRequest{
				CredentialClass: val,
				KeyEpoch:        "2024-01",
				Reason:          "Test reason",
				RevokedUntil:    nil,
			},
			wantErr: false,
		},
		{
			name: "Invalid request - CredentialClass empty",
			request: &AdminRevokeRequest{
				CredentialClass: "",
				KeyEpoch:        "2024-01",
				Reason:          "Test reason",
				RevokedUntil:    &now,
			},
			wantErr: true,
		},
		{
			name: "Invalid request - Reason empty",
			request: &AdminRevokeRequest{
				CredentialClass: val,
				KeyEpoch:        "2024-01",
				Reason:          "",
				RevokedUntil:    &now,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdminRevokeRequest(*tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAdminUnRevokeRequest(t *testing.T) {
	val := "gold"
	tests := []struct {
		name    string
		request *AdminUnrevokeRequest
		wantErr bool
	}{
		{
			name: "Valid request - nothing omitted",
			request: &AdminUnrevokeRequest{
				CredentialClass: val,
				KeyEpoch:        "2024-01",
			},
			wantErr: false,
		}, {
			name: "Valid request - key epoch omitted",
			request: &AdminUnrevokeRequest{
				CredentialClass: val,
				KeyEpoch:        "",
			},
			wantErr: false,
		},
		{
			name: "Invalid request - CredentialClass empty",
			request: &AdminUnrevokeRequest{
				CredentialClass: "",
				KeyEpoch:        "2024-01",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdminUnrevokeRequest(*tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
