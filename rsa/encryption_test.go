package rsa_test

import (
	"testing"

	"github.com/M3DZIK/libcrypto-go/rsa"
)

func TestEncryption(t *testing.T) {
	// clear text to encrypt
	clearText := "hello world"

	// label to use for encryption
	label := "some label"

	// kenerate a new RSA keypair
	privateKey, publicKey, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Errorf("Failed to generate an RSA keypair: %v", err)
	}

	// encrypt the clear text
	cipherText, err := rsa.Encrypt(publicKey, clearText, label)
	if err != nil {
		t.Errorf("Failed to encrypt message: %v", err)
	}

	// decrypt the cipher text
	decryptedText, err := rsa.Decrypt(privateKey, cipherText, label)
	if err != nil {
		t.Errorf("Failed to decrypt cipher text: %v", err)
	}

	// compare the clear text with the decrypted text
	if decryptedText != clearText {
		t.Errorf("Decrypted text does not match clear text")
	}
}

func TestDecrypt(t *testing.T) {
	expected := "hello world"
	cipherText := `805b92065b5c10fa2320d987e469488c4c6c3bff8591fdbe94b2f67d4ea80041d9cf9e3318689b0ff87be0e9f1657351c664b3d8925df541c4b8a52327c9ec6afce30fd2b6aed8b904552653cbb5210c905f9411d6c67f9e90f9071171233cd14ec1fe00f3bfb54042679e4a08eeff2ab7dc75173d942e79bb43795131e1484aa372ecd02114464d1302d375b3f86c22b26d1cc1608a901dbc33795c19901f61e7824c3e888e77a5f6d61460e50c14156c232bfb382b681dc4e34d5376c214388cde9d94f91e90fe47fbd94c2e405eb401c02e53880b19084d1e4cb11aa8008a48b674a3fe6e39a3d23667717589b3751e9d866754072b7d65bd2b740b84cdcc`
	privateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAryGMf5L0GfLV4POdVQPnCMaXEYcEWoN8Q915B7cihuFfWnMN
TVrQOuq9BF+hm3Id/BgTJXwty/MPIRKS+ua9EF4uEX4o0fpMe/65BovneT29X9r6
GMw70kiUmjA1HopBRpjwxTID5Ksi/ijlMnjGWt12ATDZ/looL/ZLCGQx26abtqNA
k/z9eFKL/khkdrC5XBVk6zUWtJ2aKpb1/eEXJbeS84ft+R4GFJg6MZp9lFkz5mNK
lRSSxCG6cux+DfV6HZBrWUDFoohf8QVxK53HAqHGk4PWrk/zWL6KMcTtSM/5AQH7
VyXIUQ6hskVfCweNC/6tKXm7X4XctQungQZW9QIDAQABAoIBAEYxIRnEsXdw/84g
dg+r975psgTBY7pPds/QhYDVIs6Cp/Adqtg1LL5gdQ+6sJAYBfKTR6E/iy9yJL8x
rZ1IO8DCrp4uPXgjZOJRrqD0E/thBnTT1Gd5/AQFOSIvbirmaNE93Up8CFlvSiAq
DerTw1SJ7JD/nm+2fOL0SRB88ArDq1nctYgq6fvk7P8mE+x2+lOvqSct/ODs58QX
Y2PGGCWIc5bfLkkDw/k/yn3NYrTfWjyRxVTz3DRZ3NUjelLpWrTUMZUiRAck+YPz
sCfsvvJ2MjfbtmZWmlKHHkVIK/tFZGXqKJTu3/GhIj/aaIHDbqcGpppQh4DdqgOG
xoNpIwECgYEA2fj4W3+oujsPY3Ss+L6LVdL45ezgPYGm0HIC3JOlLde9VZzlNeT9
YqLR3ho8cbKB8gMm/rVTUReA/9sTOqgrhKHD4kQSFbOoptZa1ZW90hLIRNRAo+eW
FvnguU/bKiQFYusgcVc4QmxASnVtnU1a2GbG2vCmP5x6AJ0jAszlJ0ECgYEAza80
LJPpHOZvfAqHAwWR3VXi1wMElsfMYEc/7XLpvjYLiaWhN3U1JPC4PX4aFQWASslc
EczHBlGW0zix3XqrCdJkzdaLvbrC/DdgWfWNjhWpuZdw07FwycEaQNdnDiArBt+t
fX6fTWGTDn4+BM/LDQSthy/0taZSsgIM5fsiFrUCgYEAhvJq4EryrQlvh4VuqTle
ji3lRoQWeD3Shu5u8xy9gNo2L9DI30r7zJs9DyJzFXkMlkZ5V+vuvx+sD7sT9paz
CpQT7/twrtrhqRjAd8cTFAHo1yQJOPBhravaAyB7cWWHqCwlk8YJ4KWgT/jPejmv
6pYGuvmOE4fOyJ6AVHWB0YECgYEAjoXs/UawrVnvvl/9FdbyMBCnUp3AvEpOEBjO
71ZFKYyBiiu+/pK09Jfo0pNit1ZMg4Xrylm/P12hyVLrzLCHfBLRzt/vjNSw79vf
Y/aG1AGmzfdmMwotQWARNQUNX/hiWCz+JotrD0+hetV3XBYweSDYrWhJhOVvP/Gz
xliyUlECgYACVms/v4e/m2tTl2jHhrKicDuaauBtboRi+5bwXHJWpM6nQ6wDnH+F
QuFXuOWNVbgxZzGE2XbgS318MpWadIFPwndOCxl9nUpDNlAG4VYNOhyKkUScCGkB
LYr5QptMo0eNbEtjBs2nMc7VRtP9CY+R5xo6PEJx5QAwvus3MsoGvw==
-----END RSA PRIVATE KEY-----`

	// parse the private key
	rsaPrivateKey, err := rsa.PrivateKeyFromBytes([]byte(privateKey))
	if err != nil {
		t.Error(err)
	}

	// decrypt the cipher text
	decryptedText, err := rsa.Decrypt(rsaPrivateKey, cipherText, "some label")
	if err != nil {
		t.Errorf("Failed to decrypt cipher text: %v", err)
	}

	// compare the expected text with the decrypted text
	if decryptedText != expected {
		t.Errorf("Decrypted text does not match clear text")
	}
}
