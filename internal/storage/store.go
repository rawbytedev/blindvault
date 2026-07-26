package storage

import "time"

// NullifierStore defines the interface for replay protection.
type NullifierStore interface {
	// CheckAndStore atomically checks if the nullifier exists and stores it.
	// Returns:
	//   - (true, nil) if nullifier is new and stored successfully
	//   - (false, nil) if nullifier already exists (replay attempt)
	//   - (false, err) if an error occurred
	CheckAndStore(nullifier []byte) (bool, error)

	// Close closes the underlying connection.
	Close() error
}

// RevocationEntry represents a revocation rule.
type RevocationEntry struct {
	CredentialClass string     `json:"credential_class"`
	KeyEpoch        string     `json:"key_epoch,omitempty"` // empty means all epochs
	Reason          string     `json:"reason"`
	RevokedAt       time.Time  `json:"revoked_at"`
	RevokedUntil    *time.Time `json:"revoked_until,omitempty"`
	RevokedBy       string     `json:"revoked_by,omitempty"` // admin identity
}

type RevocationStore interface {
	// RevokeClass marks a credential class (and optionally epoch) as revoked.
	RevokeClass(class, epoch, reason, revokedBy string, revokedUntil *time.Time) error

	// IsRevoked checks if a credential is revoked.
	// Returns (isRevoked, entry, error).
	IsRevoked(class, epoch string) (bool, *RevocationEntry, error)

	// ListRevocations returns all active revocation entries.
	ListRevocations() ([]RevocationEntry, error)

	// UnrevokeClass removes a revocation.
	UnrevokeClass(class, epoch string) error

	// Close cleans up resources.
	Close() error
}
