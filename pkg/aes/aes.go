package aes

import (
	"blindvault/pkg/errors"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AesEnc struct{}

func (s *AesEnc) EncryptFile(ctx context.Context, key, content []byte) ([]byte, error) {
	// 1. Validate key length (32 bytes)
	if len(key) != 32 {
		return nil, errors.New(ctx, "key must be 32 bytes")
	}
	// 2. Encrypt
	ciphertext, err := EncryptAES256GCM(key, content)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "Unable to encrypt")
	}

	return ciphertext, nil
}

func EncryptAES256GCM(key, content []byte) ([]byte, error) {
	// 1. Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 2. GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 3. Generate random nonce (12 bytes is standard for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// 4. Seal (encrypt) – ciphertext includes the authentication tag
	//    Go’s Seal prepends the ciphertext, then appends the tag.
	ciphertext := gcm.Seal(nil, nonce, content, nil)

	// 5. Final format: nonce (12 bytes) + ciphertext (which includes tag)
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

func DecryptAES256GCM(key, content []byte) ([]byte, error) {
	// 2. Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 3. GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 4. Generate retrieve nonce (12 bytes is standard for GCM)
	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, content[:gcm.NonceSize()])
	decrypted, err := gcm.Open(nil, nonce, content[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
