package api

import "github.com/rawbytedev/blindvault/internal/validation"

func ValidateIssueRequest(req IssueRequest) error {
	return validation.ValidateIssueRequest(req)
}

func ValidateConsumeRequest(req ConsumeRequest) error {
	return validation.ValidateConsumeRequest(req)
}

func ValidateAdminRevokeRequest(req AdminRevokeRequest) error {
	return validation.ValidateAdminRevokeRequest(req)
}

func ValidateAdminUnrevokeRequest(req AdminUnrevokeRequest) error {
	return validation.ValidateAdminUnrevokeRequest(req)
}

func ValidateAdminListRevocationsRequest(req AdminListRevocationsRequest) error {
	return validation.ValidateAdminListRevocationsRequest(req)
}
