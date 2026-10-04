package orders

import (
	"reflect"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/storage"
)

func TestEncryptAndDecryptShippingDetails(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("01234567890123456789012345678901"))
	keyring, err := storage.NewKeyring("v1", map[string][32]byte{"v1": key})
	if err != nil {
		t.Fatal(err)
	}

	details := ShippingDetails{
		Name:       "Cipher Bear",
		Address:    "12 Encryption Lane",
		City:       "Lockbox",
		Region:     "VA",
		PostalCode: "22030",
	}

	encrypted, err := EncryptShippingDetails(details, keyring)
	if err != nil {
		t.Fatalf("EncryptShippingDetails() failed: %v", err)
	}

	if strings.Contains(encrypted, "Cipher Bear") || strings.Contains(encrypted, "12 Encryption Lane") {
		t.Fatal("Encrypted shipping details contains plaintext")
	}

	decrypted, err := DecryptShippingDetails(encrypted, keyring)
	if err != nil {
		t.Fatalf("DecryptShippingDetails() failed: %v", err)
	}

	if !reflect.DeepEqual(details, decrypted) {
		t.Fatalf("Decrypted details %+v do not match original %+v", decrypted, details)
	}
}

func TestShippingDetailsValidation(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("01234567890123456789012345678901"))
	keyring, err := storage.NewKeyring("v1", map[string][32]byte{"v1": key})
	if err != nil {
		t.Fatal(err)
	}

	// Nil keyring checks
	if _, err := EncryptShippingDetails(ShippingDetails{}, nil); err == nil {
		t.Fatal("EncryptShippingDetails() accepted nil keyring")
	}
	if _, err := DecryptShippingDetails("encrypted", nil); err == nil {
		t.Fatal("DecryptShippingDetails() accepted nil keyring")
	}

	// Missing fields in encrypted JSON
	missingFieldJSON := `{"name":"Cipher Bear","address":"12 Encryption Lane"}`
	encryptedMissing, err := keyring.Encrypt([]byte(missingFieldJSON))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptShippingDetails(encryptedMissing, keyring); err == nil {
		t.Fatal("DecryptShippingDetails() accepted missing fields")
	}

	// Malformed JSON in encrypted payload
	malformedJSON := `not-json`
	encryptedMalformed, err := keyring.Encrypt([]byte(malformedJSON))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptShippingDetails(encryptedMalformed, keyring); err == nil {
		t.Fatal("DecryptShippingDetails() accepted malformed json")
	}
}
