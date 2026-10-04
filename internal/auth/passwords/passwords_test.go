package passwords

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	passwordHash, err := Hash("password123")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("password123", passwordHash) {
		t.Fatal("Verify() rejected the password used to create the hash")
	}
	if Verify("wrong-password", passwordHash) {
		t.Fatal("Verify() accepted the wrong password")
	}
}

func TestNeedsRehash(t *testing.T) {
	currentHash, err := Hash("password123")
	if err != nil {
		t.Fatal(err)
	}
	if NeedsRehash(currentHash) {
		t.Fatal("NeedsRehash() returned true for current hash")
	}

	legacyHash := "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
	if !NeedsRehash(legacyHash) {
		t.Fatal("NeedsRehash() returned false for legacy SHA-256 hash")
	}

	if NeedsRehash("not-a-hash") {
		t.Fatal("NeedsRehash() returned true for malformed hash")
	}
	if NeedsRehash("$argon2id$malformed") {
		t.Fatal("NeedsRehash() returned true for malformed argon2id hash")
	}

	staleMemory := "$argon2id$v=19$m=12288,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
	if !NeedsRehash(staleMemory) {
		t.Fatal("NeedsRehash() returned false for stale memory")
	}
}
