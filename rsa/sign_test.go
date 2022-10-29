package rsa_test

import (
	"testing"

	"github.com/MedzikUser/libcrypto-go/rsa"
)

func TestSign(t *testing.T) {
	privateKey, publicKey, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Errorf("Failed to generate an RSA keypair: %v", err)
	}

	message := "hello world"

	signature, err := rsa.SignRsa([]byte(message), privateKey)
	if err != nil {
		t.Errorf("Failed to sign message: %v", err)
	}

	err = rsa.ValidateSignRsa([]byte(message), signature, publicKey)
	if err != nil {
		t.Errorf("Failed to verify message: %v", err)
	}
}
