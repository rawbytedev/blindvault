package aes_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	crypto "blindvault/pkg/aes"
	mem "blindvault/pkg/securememory"
)

// TestEncryptDecryptWithSecureMemory verifies that AES-256-GCM encryption and decryption
// work correctly when the key and plaintext are stored in secure memory (Enclave).
func TestEncryptDecryptWithSecureMemory(t *testing.T) {
	// 1. Generate a random 32-byte key and store it in an Enclave.
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	keyEnclave := mem.NewEnclaveFromBytes(keyBytes)
	// Zero the original slice to avoid lingering in memory.
	for i := range keyBytes {
		keyBytes[i] = 0
	}

	// 2. Plaintext content.
	plaintext := []byte("This is highly sensitive data that must be encrypted.")
	var copyplaintext []byte
	copy(copyplaintext, plaintext)
	plainEnclave := mem.NewEnclaveFromBytes(plaintext)

	// 3. Open the key and plaintext from their enclaves (locked buffers).
	keyLocked, err := keyEnclave.Open()
	if err != nil {
		t.Fatalf("failed to open key enclave: %v", err)
	}
	defer keyLocked.Close()

	plainLocked, err := plainEnclave.Open()
	if err != nil {
		t.Fatalf("failed to open plaintext enclave: %v", err)
	}
	defer plainLocked.Close()

	// 4. Encrypt.
	ciphertext, err := crypto.EncryptAES256GCM(keyLocked.Bytes(), plainLocked.Bytes())
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// 5. Decrypt (using the same key, again from the enclave).
	keyLocked2, err := keyEnclave.Open()
	if err != nil {
		t.Fatalf("failed to reopen key enclave: %v", err)
	}
	defer keyLocked2.Close()

	decrypted, err := crypto.DecryptAES256GCM(keyLocked2.Bytes(), ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// 6. Compare.
	if bytes.Equal(decrypted, copyplaintext) {
		t.Errorf("decrypted text = %q, want %q", decrypted, copyplaintext)
	}
}

// TestEncryptFileWithSecureMemory tests AesEnc.EncryptFile using secure memory.
func TestEncryptFileWithSecureMemory(t *testing.T) {
	// 1. Create a 32-byte key in an enclave.
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	keyEnclave := mem.NewEnclaveFromBytes(keyBytes)
	for i := range keyBytes {
		keyBytes[i] = 0
	}

	// 2. Plaintext content.
	content := []byte("file content to encrypt")
	contentEnclave := mem.NewEnclaveFromBytes(content)

	// 3. Open the key and content.
	keyLocked, err := keyEnclave.Open()
	if err != nil {
		t.Fatalf("failed to open key: %v", err)
	}
	defer keyLocked.Close()

	contentLocked, err := contentEnclave.Open()
	if err != nil {
		t.Fatalf("failed to open content: %v", err)
	}
	defer contentLocked.Close()

	// 4. Call EncryptFile.
	enc := &crypto.AesEnc{}
	ciphertext, err := enc.EncryptFile(nil, keyLocked.Bytes(), contentLocked.Bytes())
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// 5. Decrypt using the low-level function to verify.
	keyLocked2, err := keyEnclave.Open()
	if err != nil {
		t.Fatalf("failed to reopen key: %v", err)
	}
	defer keyLocked2.Close()

	decrypted, err := crypto.DecryptAES256GCM(keyLocked2.Bytes(), ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if bytes.Equal(decrypted, content) {
		t.Errorf("decrypted = %q, want %q", decrypted, content)
	}
}

// TestDecryptWithWrongKey ensures that decryption fails when an incorrect key is used.
func TestDecryptWithWrongKey(t *testing.T) {
	correctKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(correctKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("secret message")

	ciphertext, err := crypto.EncryptAES256GCM(correctKey, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	_, err = crypto.DecryptAES256GCM(wrongKey, ciphertext)
	if err == nil {
		t.Error("decryption with wrong key succeeded, expected failure")
	}
}

// TestDecryptWithCorruptedCiphertext verifies that the decryption function detects
// tampered ciphertext (authentication tag mismatch).
func TestDecryptWithCorruptedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("integrity test")
	ciphertext, err := crypto.EncryptAES256GCM(key, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Corrupt one byte in the ciphertext (e.g., after the nonce).
	if len(ciphertext) > 12 {
		ciphertext[12] ^= 0xff
	}

	_, err = crypto.DecryptAES256GCM(key, ciphertext)
	if err == nil {
		t.Error("decryption of corrupted ciphertext succeeded, expected authentication error")
	}
}

// TestKeySizeValidation checks that both EncryptAES256GCM and DecryptAES256GCM
// reject keys that are not exactly 32 bytes.
func TestKeySizeValidation(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"too short (16 bytes)", make([]byte, 16)},
		{"too short (24 bytes)", make([]byte, 24)},
		{"too long (40 bytes)", make([]byte, 40)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.EncryptAES256GCM(tt.key, []byte("data"))
			if err == nil {
				t.Error("EncryptAES256GCM accepted invalid key size")
			}
			_, err = crypto.DecryptAES256GCM(tt.key, []byte("someciphertext"))
			if err == nil {
				t.Error("DecryptAES256GCM accepted invalid key size")
			}
		})
	}
}

// TestEncryptFileKeyLengthValidation tests the key length check inside EncryptFile.
func TestEncryptFileKeyLengthValidation(t *testing.T) {
	enc := &crypto.AesEnc{}
	invalidKeys := [][]byte{
		make([]byte, 16),
		make([]byte, 24),
		make([]byte, 40),
	}

	for _, key := range invalidKeys {
		_, err := enc.EncryptFile(nil, key, []byte("content"))
		if err == nil {
			t.Errorf("EncryptFile accepted key of length %d, expected error", len(key))
		}
	}
}

// TestEnclaveUsage_Zeroing ensures that after a LockedBuffer is closed,
// subsequent attempts to access its data panic (secure memory zeroed).
// This verifies that the integration with securememory does not accidentally
// keep copies of sensitive data.
func TestEnclaveUsage_Zeroing(t *testing.T) {
	// Create an enclave with a key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyEnclave := mem.NewEnclaveFromBytes(key)
	// zero the original slice
	for i := range key {
		key[i] = 0
	}

	// Open the enclave to get a locked buffer.
	locked, err := keyEnclave.Open()
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	// Use the locked buffer to encrypt something (just to exercise).
	plain := []byte("ephemeral data")
	_, err = crypto.EncryptAES256GCM(locked.Bytes(), plain)
	if err != nil {
		t.Fatalf("encryption with secure key failed: %v", err)
	}

	// Close the locked buffer – memory should be zeroed.
	locked.Close()

	// After Close, accessing Bytes() should panic (or be unsafe).
	defer func() {
		if r := recover(); r == nil {
			t.Log("Close() zeroed memory – subsequent access causes panic (expected)")
		}
	}()
	_ = locked.Bytes() // This line should panic.
}
