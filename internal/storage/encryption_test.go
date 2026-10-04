package storage

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	plaintext := []byte("Bearly Secure sensitive stored data")

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(encrypted.Nonce) != 12 {
		t.Errorf("expected 12-byte nonce, got %d", len(encrypted.Nonce))
	}
	if len(encrypted.AuthTag) != 16 {
		t.Errorf("expected 16-byte auth tag, got %d", len(encrypted.AuthTag))
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted %q does not match original plaintext %q", decrypted, plaintext)
	}
}

func TestEncryptFreshNonce(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("test")

	first, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Error("expected fresh nonces for each Encrypt call")
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Error("expected distinct ciphertexts for distinct nonces")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	encrypted, err := Encrypt([]byte("secret message"), key)
	if err != nil {
		t.Fatal(err)
	}

	encrypted.Ciphertext[0] ^= 0xff
	if _, err := Decrypt(encrypted, key); err == nil {
		t.Error("expected Decrypt to fail for tampered ciphertext")
	}
}

func TestDecryptRejectsTamperedTag(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	encrypted, err := Encrypt([]byte("secret message"), key)
	if err != nil {
		t.Fatal(err)
	}

	encrypted.AuthTag[0] ^= 0xff
	if _, err := Decrypt(encrypted, key); err == nil {
		t.Error("expected Decrypt to fail for tampered auth tag")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	wrongKey := [32]byte{9, 9, 9, 9}
	encrypted, err := Encrypt([]byte("secret message"), key)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Decrypt(encrypted, wrongKey); err == nil {
		t.Error("expected Decrypt to fail with wrong key")
	}
}

func TestDecryptRejectsMalformedLengths(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	encrypted, err := Encrypt([]byte("secret message"), key)
	if err != nil {
		t.Fatal(err)
	}

	shortNonce := encrypted
	shortNonce.Nonce = shortNonce.Nonce[:11]
	if _, err := Decrypt(shortNonce, key); err == nil {
		t.Error("expected Decrypt to reject short nonce")
	}

	shortTag := encrypted
	shortTag.AuthTag = shortTag.AuthTag[:15]
	if _, err := Decrypt(shortTag, key); err == nil {
		t.Error("expected Decrypt to reject short auth tag")
	}
}
