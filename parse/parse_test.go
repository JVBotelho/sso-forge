package parse

import (
	"encoding/hex"
	"testing"
)

func TestParseHashInput_RC4Hex(t *testing.T) {
	keys, err := ParseHashInput("61bb7f03790448210063f5fe4cf1ca50")
	if err != nil {
		t.Fatalf("ParseHashInput failed: %v", err)
	}
	if keys.RC4 == nil {
		t.Fatal("expected RC4 key, got nil")
	}
	if len(keys.RC4) != 16 {
		t.Errorf("RC4 key len = %d, want 16", len(keys.RC4))
	}
	want, _ := hex.DecodeString("61bb7f03790448210063f5fe4cf1ca50")
	if hex.EncodeToString(keys.RC4) != hex.EncodeToString(want) {
		t.Errorf("RC4 key mismatch")
	}
}

func TestParseHashInput_AES256Hex(t *testing.T) {
	aes256 := "0000000000000000000000000000000000000000000000000000000000000000"
	keys, err := ParseHashInput(aes256)
	if err != nil {
		t.Fatalf("ParseHashInput failed: %v", err)
	}
	if keys.AES256 == nil {
		t.Fatal("expected AES256 key, got nil")
	}
	if len(keys.AES256) != 32 {
		t.Errorf("AES256 key len = %d, want 32", len(keys.AES256))
	}
}

func TestParseHashInput_SecretsdumpFormat(t *testing.T) {
	input := "DOMAIN\\AZUREADSSOACC$:aad_00000000000000000000000000000000:61bb7f03790448210063f5fe4cf1ca50:61bb7f03790448210063f5fe4cf1ca50:::"
	keys, err := ParseHashInput(input)
	if err != nil {
		t.Fatalf("ParseHashInput failed: %v", err)
	}
	if keys.RC4 == nil {
		t.Fatal("expected RC4 key from secretsdump, got nil")
	}
	want, _ := hex.DecodeString("61bb7f03790448210063f5fe4cf1ca50")
	if hex.EncodeToString(keys.RC4) != hex.EncodeToString(want) {
		t.Errorf("RC4 key mismatch from secretsdump")
	}
}

func TestParseHashInput_Invalid(t *testing.T) {
	tests := []string{
		"",
		"nothex",
		"1234567890123456789012345678", // 28 chars, invalid
		":",
	}
	for _, input := range tests {
		_, err := ParseHashInput(input)
		if err == nil {
			t.Errorf("ParseHashInput(%q) should fail", input)
		}
	}
}

func TestParseHashInput_TrimSpace(t *testing.T) {
	input := "  61bb7f03790448210063f5fe4cf1ca50  \n"
	keys, err := ParseHashInput(input)
	if err != nil {
		t.Fatalf("ParseHashInput with whitespace failed: %v", err)
	}
	if keys.RC4 == nil {
		t.Fatal("expected RC4 key")
	}
}

func TestKeys_KeyByEType(t *testing.T) {
	k := &Keys{
		RC4:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		AES256: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	if k.KeyByEType(23) == nil {
		t.Error("KeyByEType(23) should return RC4 key")
	}
	if k.KeyByEType(18) == nil {
		t.Error("KeyByEType(18) should return AES256 key")
	}
	if k.KeyByEType(17) != nil {
		t.Error("KeyByEType(17) should return nil (no AES128)")
	}
	if k.KeyByEType(99) != nil {
		t.Error("KeyByEType(99) should return nil (unknown)")
	}
}

func TestParseHashInput_AES128_NotYetSupported(t *testing.T) {
	// 32-char hex = 16 bytes = could be AES128 or RC4
	// ParseHashInput treats 16 bytes as RC4
	input := "00000000000000000000000000000000"
	keys, err := ParseHashInput(input)
	if err != nil {
		t.Fatalf("ParseHashInput failed: %v", err)
	}
	if keys.AES128 != nil {
		t.Error("16-byte hex should be treated as RC4, not AES128")
	}
}

func TestParseHashInput_54CharInvalid(t *testing.T) {
	// 54 chars is not 32 or 64 - should fail
	_, err := ParseHashInput("123456789012345678901234567890123456789012345678901234")
	if err == nil {
		t.Error("54-char input should fail")
	}
}
