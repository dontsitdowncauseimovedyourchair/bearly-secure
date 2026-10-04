package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength = 128

	currentArgon2idVersion     = argon2.Version
	currentArgon2idMemoryKiB   = 19 * 1024
	currentArgon2idIterations  = 2
	currentArgon2idParallelism = 1
	currentArgon2idSaltLength  = 16
	currentArgon2idKeyLength   = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}

	salt := make([]byte, currentArgon2idSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		currentArgon2idIterations,
		currentArgon2idMemoryKiB,
		currentArgon2idParallelism,
		currentArgon2idKeyLength,
	)

	return encodeArgon2idHash(argon2idHash{
		version:     currentArgon2idVersion,
		memoryKiB:   currentArgon2idMemoryKiB,
		iterations:  currentArgon2idIterations,
		parallelism: currentArgon2idParallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if expectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}

	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok || parsedHash.version != currentArgon2idVersion {
		return false
	}

	candidateKey := argon2.IDKey(
		[]byte(password),
		parsedHash.salt,
		parsedHash.iterations,
		parsedHash.memoryKiB,
		parsedHash.parallelism,
		uint32(len(parsedHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(candidateKey, parsedHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	return parsedHash.version != currentArgon2idVersion ||
		parsedHash.memoryKiB != currentArgon2idMemoryKiB ||
		parsedHash.iterations != currentArgon2idIterations ||
		parsedHash.parallelism != currentArgon2idParallelism ||
		len(parsedHash.derivedKey) != currentArgon2idKeyLength
}
