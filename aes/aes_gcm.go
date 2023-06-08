package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

var AesGcmIVLength = 12

// EncryptAesGcm encrypts the given clear text using AES-GCM with the given key.
func EncryptAesGcm(key string, clearText string) (string, error) {
	// Decode the key from a hex string
	secretKey, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("error decoding key as hex string: %v", err)
	}

	// Create a new cipher block
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	// Encode the clear text into bytes
	clearTextBytes := []byte(clearText)

	// Allocate space in the heap for the cipher text
	cipherText := make([]byte, AesGcmIVLength+len(clearTextBytes))

	// Generate a random nonce
	nonce := cipherText[:AesGcmIVLength]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Create the GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the clear text
	cipherText = gcm.Seal(cipherText[:AesGcmIVLength], nonce, clearTextBytes, nil)

	// Return the cipher text as a hex string
	return hex.EncodeToString(cipherText), nil
}

// DecryptAesGcm decrypts the given cipher text using AES-GCM with the given key.
func DecryptAesGcm(key string, cipherText string) (string, error) {
	// Decode the key from a hex string
	secretKey, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("error decoding key as hex string: %v", err)
	}

	// Decode the cipher text from a hex string
	cipherTextBytes, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("error decoding cipher text as hex string: %v", err)
	}

	// Create a new cipher block
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	// Get the nonce from the cipher text
	nonce := cipherTextBytes[:AesGcmIVLength]
	// Get the cipher text without the nonce
	cipherTextBytes = cipherTextBytes[AesGcmIVLength:]

	// Create the GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt the cipher text
	plainText, err := gcm.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	// Return the plain text as a string
	return string(plainText), nil
}
