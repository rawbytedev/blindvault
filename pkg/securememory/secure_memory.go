package securememory

import (
	"github.com/awnumar/memguard"
)

type LockedBuffer struct {
	*memguard.LockedBuffer
}

func NewLocked(data string) (*LockedBuffer, error) {
	buf := memguard.NewBufferFromBytes([]byte(data))
	return &LockedBuffer{buf}, nil
}

func NewLockedFromBytes(data []byte) (*LockedBuffer, error) {
	buf := memguard.NewBufferFromBytes(data)
	return &LockedBuffer{buf}, nil
}

// destroy the buffer when done to zero out the memory
func (b *LockedBuffer) Close() {
	b.LockedBuffer.Destroy()
}

func (b *LockedBuffer) Wipe() {
	b.LockedBuffer.Wipe()
}

type Enclave struct {
	*memguard.Enclave
}

func NewEnclave(data string) *Enclave {
	enclave := memguard.NewEnclave([]byte(data))
	return &Enclave{enclave}
}

func NewEnclaveFromBuffer(buf *LockedBuffer) *Enclave {
	enclave := buf.Seal()
	return &Enclave{enclave}
}

func NewEnclaveFromBytes(data []byte) *Enclave {
	enclave := memguard.NewEnclave(data)
	return &Enclave{enclave}
}

func (e *Enclave) Open() (*LockedBuffer, error) {
	buf, err := e.Enclave.Open()
	if err != nil {
		return nil, err
	}
	return &LockedBuffer{buf}, nil // manually destroy the buffer when done
}

func (e *Enclave) Size() int {
	return e.Enclave.Size()
}
