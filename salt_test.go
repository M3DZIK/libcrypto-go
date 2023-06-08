package libcrypto_test

import (
	"testing"

	"github.com/M3DZIK/libcrypto-go"
)

func TestGenerateSalt(t *testing.T) {
	saltSize := 16

	salt, err := libcrypto.GenerateSalt(saltSize)
	if err != nil {
		t.Error(err)
	}

	if len(salt) != saltSize {
		t.Errorf("Salt length is not %d", saltSize)
	}
}
