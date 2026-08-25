package service

import "context"

// CredentialIssuer interface allow the implementation of different Issuance behaviours
// this was specifically added to facilitate partial signing distributed signing
type CredentialIssuer interface {
	Issue(ctx context.Context, blindedHex, class string) (*IssueResult, error)
	Consume(ctx context.Context, sigHex, witnessHex, class, epoch string) (*ConsumeResult, error)
	Close() error
}
