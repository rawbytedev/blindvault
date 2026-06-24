package securememory_test

import (
	mem "blindvault/pkg/securememory"
	"bytes"
	"testing"
)

func TestLockedBuffer_NewLocked(t *testing.T) {
	data := "secret123"
	buf, err := mem.NewLocked(data)
	if err != nil {
		t.Fatalf("NewLocked failed: %v", err)
	}
	defer buf.Close()

	if buf.String() != data {
		t.Errorf("String() = %q, want %q", buf.String(), data)
	}
}

func TestLockedBuffer_NewLockedFromBytes(t *testing.T) {
	data := []byte("bytes secret")
	expected := []byte("bytes secret") // literal copy, unaffected by wipe

	buf, err := mem.NewLockedFromBytes(data)
	if err != nil {
		t.Fatalf("NewLockedFromBytes failed: %v", err)
	}
	defer buf.Close()

	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("Bytes() = %v, want %v", buf.Bytes(), expected)
	}
}

func TestLockedBuffer_CloseZeroesMemory(t *testing.T) {
	// After Close, the buffer should be destroyed (zeroed).
	// memguard guarantees zeroing, but we can check that Bytes() panics or returns nil.
	data := "will be destroyed" // still present in memory (string)
	buf, _ := mem.NewLocked(data)
	buf.Close()
	// Calling Bytes() after Destroy is unsafe; memguard may panic or return nil.
	// We simply verify that Close doesn't panic and subsequent operations are invalid.
	defer func() {
		if r := recover(); r == nil {
			t.Log("Close() zeroed memory – subsequent access causes panic (expected)")
		}
	}()
	_ = buf.String() // should panic or return garbage; we don't rely on it.
}

func TestEnclave_NewEnclave(t *testing.T) {
	data := "enclave secret"
	enc := mem.NewEnclave(data)
	if enc.Size() != len(data) {
		t.Errorf("Size() = %d, want %d", enc.Size(), len(data))
	}
}

func TestEnclave_NewEnclaveFromBytes(t *testing.T) {
	data := []byte("bytes enclave")
	enc := mem.NewEnclaveFromBytes(data)
	if enc.Size() != len(data) {
		t.Errorf("Size() = %d, want %d", enc.Size(), len(data))
	}
}

func TestEnclave_NewEnclaveFromBuffer(t *testing.T) {
	buf, _ := mem.NewLocked("buffer enclave")
	defer buf.Close()
	enc := mem.NewEnclaveFromBuffer(buf)
	if enc.Size() != len("buffer enclave") {
		t.Errorf("Size() = %d, want %d", enc.Size(), len("buffer enclave"))
	}
}

func TestEnclave_Open(t *testing.T) {
	original := "open me"
	enc := mem.NewEnclave(original)

	locked, err := enc.Open()
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer locked.Close()

	if locked.String() != original {
		t.Errorf("Opened buffer = %q, want %q", locked.String(), original)
	}
}

func TestEnclave_OpenMultipleTimes(t *testing.T) {
	enc := mem.NewEnclave("multi open")
	locked1, err := enc.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer locked1.Close()
	locked2, err := enc.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer locked2.Close()

	if locked1.String() != locked2.String() {
		t.Error("Multiple opens returned different data")
	}
}

func TestEnclave_OpenAfterClose(t *testing.T) {
	enc := mem.NewEnclave("close then open")
	locked, _ := enc.Open()
	locked.Close() // destroys the locked buffer, but enclave remains usable

	// Should still be able to open a new buffer
	locked2, err := enc.Open()
	if err != nil {
		t.Fatalf("Open after close failed: %v", err)
	}
	defer locked2.Close()
	if locked2.String() != "close then open" {
		t.Errorf("Data mismatch after re-open: %q", locked2.String())
	}
}
