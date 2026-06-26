package storage

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