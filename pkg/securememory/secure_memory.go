package securememory

import (
	"github.com/awnumar/memguard"
)

// LockedBuffer is a wrapper around memguard.LockedBuffer that provides secure memory handling.
type LockedBuffer struct {
	*memguard.LockedBuffer
}

// NewLocked creates a new LockedBuffer from a string.
func NewLocked(data string) (*LockedBuffer, error) {
	buf := memguard.NewBufferFromBytes([]byte(data))
	return &LockedBuffer{buf}, nil
}

// NewLockedFromBytes creates a new LockedBuffer from a byte slice.
func NewLockedFromBytes(data []byte) (*LockedBuffer, error) {
	buf := memguard.NewBufferFromBytes(data)
	return &LockedBuffer{buf}, nil
}

// Close securely destroys the LockedBuffer.
func (b *LockedBuffer) Close() {
	b.LockedBuffer.Destroy()
}

// Wipe securely wipes the contents of the LockedBuffer.
func (b *LockedBuffer) Wipe() {
	b.LockedBuffer.Wipe()
}

// Enclave is a secure memory enclave that can hold sensitive data.
type Enclave struct {
	*memguard.Enclave
}

// NewEnclave creates a new Enclave from a string.
func NewEnclave(data string) *Enclave {
	enclave := memguard.NewEnclave([]byte(data))
	return &Enclave{enclave}
}

// NewEnclaveFromBuffer creates a new Enclave from a LockedBuffer.
func NewEnclaveFromBuffer(buf *LockedBuffer) *Enclave {
	enclave := buf.Seal()
	return &Enclave{enclave}
}

// NewEnclaveFromBytes creates a new Enclave from a byte slice.
func NewEnclaveFromBytes(data []byte) *Enclave {
	enclave := memguard.NewEnclave(data)
	return &Enclave{enclave}
}

// Open opens the Enclave and returns a LockedBuffer. The caller is responsible for closing the LockedBuffer.
func (e *Enclave) Open() (*LockedBuffer, error) {
	buf, err := e.Enclave.Open()
	if err != nil {
		return nil, err
	}
	return &LockedBuffer{buf}, nil // manually destroy the buffer when done
}

// Size returns the size of the Enclave in bytes.
func (e *Enclave) Size() int {
	return e.Enclave.Size()
}
