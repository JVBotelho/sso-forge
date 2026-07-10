package parse

import (
	"encoding/hex"
	"testing"
)

func FuzzParseHashInput(f *testing.F) {
	// Seed with known-valid inputs
	hash, _ := hex.DecodeString("61bb7f03790448210063f5fe4cf1ca50")
	f.Add(hex.EncodeToString(hash))
	f.Add("DOMAIN\\AZUREADSSOACC$:aad_00000000000000000000000000000000:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::")
	f.Add("")
	f.Add("nothex")
	f.Add("a")
	f.Add("00000000000000000000000000000000")

	f.Fuzz(func(t *testing.T, input string) {
		keys, err := ParseHashInput(input)
		if err != nil && keys != nil {
			t.Errorf("ParseHashInput returned both error and keys")
		}
		if err == nil && keys == nil {
			t.Errorf("ParseHashInput returned nil keys without error")
		}
		if err == nil {
			if keys.RC4 != nil && len(keys.RC4) != 16 {
				t.Errorf("RC4 key wrong size: %d", len(keys.RC4))
			}
			if keys.AES128 != nil && len(keys.AES128) != 16 {
				t.Errorf("AES128 key wrong size: %d", len(keys.AES128))
			}
			if keys.AES256 != nil && len(keys.AES256) != 32 {
				t.Errorf("AES256 key wrong size: %d", len(keys.AES256))
			}
		}
	})
}
