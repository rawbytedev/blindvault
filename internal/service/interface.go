package service

import "context"

// CredentialIssuer interface allow the implementation of different Issuance behaviours
// this was specifically added to facilitate partial signing distributed signing
type CredentialIssuer interface {
	// Issue issues a blind credential for a given blinded message and credential class.
	Issue(ctx context.Context, blindedHex, class string) (*IssueResult, error)
	// Consume consumes a blind credential for a given signature, witness, credential class, and epoch.
	Consume(ctx context.Context, sigHex, witnessHex, class, epoch string) (*ConsumeResult, error)
	// Ping checks the health of the underlying stores (nullifier and revocation).
	Ping(ctx context.Context) error
	// Close closes the underlying stores (nullifier and revocation).
	Close() error
}
