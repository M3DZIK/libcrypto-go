package hash_test

import (
	"testing"

	"github.com/M3DZIK/libcrypto-go/hash"
)

func TestPbkdf2Hash256(t *testing.T) {
	salt := []byte("salt")

	// compute a 256-bit password hash with salt and 1000 iterations
	hash := hash.Pbkdf2Hash256("hello world", salt, 1000)

	// compare the hash with the expected hash
	if hash != "27426946a796b9a62bc53fba7157961905e4bdd0af2203d6eaf6dd4b64942def" {
		t.Error("hash mismatch")
	}

}

func TestPbkdf2Hash512(t *testing.T) {
	salt := []byte("salt")

	// compute a 512-bit password hash with salt and 1000 iterations
	hash := hash.Pbkdf2Hash512("hello world", salt, 1000)

	// compare the hash with the expected hash
	if hash != "883f5fb301ff684a2e92fdfc1754241bb2dd3eb6af53e5bd7e6c9eb2df7ccb7783f40872b5d3dd5c2915a519f008a92c4c2093e8a589e59962cf1e33c8706ca9" {
		t.Error("hash mismatch")
	}
}
