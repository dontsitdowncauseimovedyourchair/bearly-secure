package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	nonceSize   = 12
	authTagSize = 16
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("generate nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	tagStart := len(sealed) - gcm.Overhead()

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    append([]byte(nil), sealed[tagStart:]...),
		Ciphertext: append([]byte(nil), sealed[:tagStart]...),
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != nonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", nonceSize, len(payload.Nonce))
	}
	if len(payload.AuthTag) != authTagSize {
		return nil, fmt.Errorf("authentication tag must be %d bytes, got %d", authTagSize, len(payload.AuthTag))
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	sealed := make([]byte, len(payload.Ciphertext)+len(payload.AuthTag))
	copy(sealed, payload.Ciphertext)
	copy(sealed[len(payload.Ciphertext):], payload.AuthTag)

	plaintext, err := gcm.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}
