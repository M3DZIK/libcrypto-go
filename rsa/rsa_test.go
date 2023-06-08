package rsa_test

import (
	"testing"

	"github.com/M3DZIK/libcrypto-go/rsa"
)

func TestExportKey(t *testing.T) {
	// generate a new RSA keypair
	priv, pub, err := rsa.GenerateKey(1024)
	if err != nil {
		t.Errorf("Failed to generate an RSA keypair: %v", err)
	}

	// export the private key to bytes
	privateKeyBytes := rsa.PrivateKeyToBytes(priv)
	if privateKeyBytes == nil {
		t.Error("Exported private key is nil")
	}

	// export the private key to bytes
	publicKeyBytes, err := rsa.PublicKeyToBytes(pub)
	if err != nil {
		t.Errorf("Failed to export public key to bytes: %v", err)
	}
	if publicKeyBytes == nil {
		t.Error("Exported public key is nil")
	}
}

func TestImportKey(t *testing.T) {
	// example keypair to import
	privateKey := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC3o+hFOVDgNZK/oazl4+hJqzZL2izQlhkuH2XaY1jn7ZFuBxYK
/mBBarRpUe6rJ+gNkh8+k++jl1KpD8cuxE+GzvP2Mb3SuXKDVE1VnunhWIVXeBqt
j+vkvi1F9TGeHqXoGHqBJd1w/4UpR6G7io2vruktIoVKtbGGCK6xd13bzwIDAQAB
AoGAOAzUIQTMdZKEdu7+2bAFPy79xIsT8JpPly9IJC78fNWa9M0+4h4f/Pd3l0nF
ogHtJu85kB0RIIpYVXeWYOTULJmegSCqzA/PMQw878MvD0Hv64cdBcEXDRBEAfE0
MIyEwYz3VearOai5q/V66L5Aht24nOhhzJWGvc2ayn8s2uECQQDo04dfBnH/7NEq
UTxEZXCAkU01UbA3LzVU5d5ckbEbcYaR8GfRcUWgmr8zGXmmpW9YPP77K7By5eGM
a+RZkKQxAkEAyesbRml0K4Y49e9nQQNXReY5mb20E4B+bc78IMTdP7+Y+7HM372m
jYwy7mvXwPPEoQ/K4QqGD7bUINLoBLZ//wJAC7LdQXQUdFSU6fhs+87RCVTDuWMi
ZJN1rY9jTelwKb3ZkimvPcHgSsKbytiD2VDEuH1QHpTCZ/OPErw1HB79cQJBALXZ
TvwwFxbn0D72OIjdyGjEepXSuu5hZ/vfUUT158j09oOf0sKim/CZFnmRmINHR4xC
m9XnU2utnghdyeYMsuMCQQCir378iYMw1OAsVRXzPr5czZGx7wv7rTPAmXXwOfiI
eDv3XceZdqtxpOLgFk6bAgYdzNoB+r1zqASLi0CXnhxf
-----END RSA PRIVATE KEY-----`
	publicKey := `-----BEGIN RSA PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3o+hFOVDgNZK/oazl4+hJqzZL
2izQlhkuH2XaY1jn7ZFuBxYK/mBBarRpUe6rJ+gNkh8+k++jl1KpD8cuxE+GzvP2
Mb3SuXKDVE1VnunhWIVXeBqtj+vkvi1F9TGeHqXoGHqBJd1w/4UpR6G7io2vrukt
IoVKtbGGCK6xd13bzwIDAQAB
-----END RSA PUBLIC KEY-----`

	// import the private key from bytes
	priv, err := rsa.PrivateKeyFromBytes([]byte(privateKey))
	if err != nil {
		t.Errorf("Failed to import private key from bytes: %v", err)
	}
	if priv == nil {
		t.Errorf("Imported private key is nil")
	}

	// import the public key from bytes
	pub, err := rsa.PublicKeyFromBytes([]byte(publicKey))
	if err != nil {
		t.Errorf("Failed to import public key from bytes: %v", err)
	}
	if pub == nil {
		t.Errorf("Imported public key is nil")
	}
}
