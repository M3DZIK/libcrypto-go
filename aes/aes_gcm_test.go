package aes_test

import (
	"testing"

	"github.com/M3DZIK/libcrypto-go/aes"
	"github.com/M3DZIK/libcrypto-go/hash"
)

func TestAesGcm(t *testing.T) {
	// Clear text to encrypt
	clearText := "hello world"

	// Passphrase salt
	salt := []byte("salt")

	// Compute a encryption key from a passphrase
	key := hash.Pbkdf2Hash256("secret passphrase", salt, 1000)

	// encrypt the clear text
	cipherText, err := aes.EncryptAesGcm(key, clearText)
	if err != nil {
		t.Errorf("Failed to encrypt using aes cbc: %v", err)
	}

	// decrypt the cipher text
	decryptedText, err := aes.DecryptAesGcm(key, cipherText)
	if err != nil {
		t.Errorf("Failed to decrypt using aes cbc: %v", err)
	}

	// compare the clear text with the decrypted text
	if decryptedText != clearText {
		t.Error("Decrypted text and input text aren't the same")
	}
}

func TestAesGcmDecrypt(t *testing.T) {
	// Clear text to encrypt
	clearText := "hello world"

	// Passphrase salt
	salt := []byte("salt")

	// Compute a encryption key from a passphrase
	key := hash.Pbkdf2Hash256("secret passphrase", salt, 1000)

	// input cipher text
	cipherText := "37667330b395b5b1c25d75461ccca0d762df0bd4234cf59d48fe2bd7b414b1beb6f1866814034e"

	// decrypt the cipher text
	decryptedText, err := aes.DecryptAesGcm(key, cipherText)
	if err != nil {
		t.Errorf("Failed to decrypt using aes cbc: %v", err)
	}

	// compare the clear text with the decrypted text
	if decryptedText != clearText {
		t.Error("Invalid decrypted text")
	}
}
