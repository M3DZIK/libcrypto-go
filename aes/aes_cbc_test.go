package aes_test

import (
	"testing"

	"github.com/M3DZIK/libcrypto-go/aes"
	"github.com/M3DZIK/libcrypto-go/hash"
)

func TestAesCbc(t *testing.T) {
	// Clear text to encrypt
	clearText := "hello world"

	// Passphrase salt
	salt := []byte("salt")

	// Compute a encryption key from a passphrase
	key := hash.Pbkdf2Hash256("secret passphrase", salt, 1000)

	// encrypt the clear text
	cipherText, err := aes.EncryptAesCbc(key, clearText)
	if err != nil {
		t.Errorf("Failed to encrypt using aes cbc: %v", err)
	}

	// decrypt the cipher text
	decryptedText, err := aes.DecryptAesCbc(key, cipherText)
	if err != nil {
		t.Errorf("Failed to decrypt using aes cbc: %v", err)
	}

	// compare the clear text with the decrypted text
	if decryptedText != clearText {
		t.Error("Decrypted text and input text aren't the same")
	}
}

func TestAesCbcDecrypt(t *testing.T) {
	// Clear text to encrypt
	clearText := "hello world"

	// Passphrase salt
	salt := []byte("salt")

	// Compute a encryption key from a passphrase
	key := hash.Pbkdf2Hash256("secret passphrase", salt, 1000)

	// input cipher text
	cipherText := "ceb5156163e045c920cea4748ae302c7e210b4d521925bc342c71145aef3952d"

	// decrypt the cipher text
	decryptedText, err := aes.DecryptAesCbc(key, cipherText)
	if err != nil {
		t.Errorf("Failed to decrypt using aes cbc: %v", err)
	}

	// compare the clear text with the decrypted text
	if decryptedText != clearText {
		t.Error("Invalid decrypted text")
	}
}
