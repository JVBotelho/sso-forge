// Package parse extracts Kerberos keys from hash input formats.
package parse

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Keys contains extracted Kerberos encryption keys.
type Keys struct {
	RC4    []byte // NT hash, 16 bytes (etype 23, RC4-HMAC)
	AES128 []byte // 16 bytes (etype 17, AES128-CTS-HMAC-SHA1-96)
	AES256 []byte // 32 bytes (etype 18, AES256-CTS-HMAC-SHA1-96)
}

// KeyByEType returns the key for the given encryption type, or nil if unavailable.
func (k *Keys) KeyByEType(etype int32) []byte {
	switch etype {
	case 23:
		return k.RC4
	case 17:
		return k.AES128
	case 18:
		return k.AES256
	}
	return nil
}

// ParseHashInput parses a hash string in common formats and returns a Keys struct.
//
// Supported formats:
//   - Raw hex 32 chars (RC4 NT hash, 16 bytes) → Keys{RC4: hash}
//   - Raw hex 64 chars (AES256 key, 32 bytes) → Keys{AES256: hash}
//   - Impacket secretsdump: DOMAIN\User:UID:LM:NT::: → Keys{RC4: NT hash}
func ParseHashInput(input string) (*Keys, error) {
	input = strings.TrimSpace(input)

	// Try raw hex: 32 chars = NT hash (RC4), 64 chars = AES256
	if len(input) == 32 || len(input) == 64 {
		if bytes, err := hex.DecodeString(input); err == nil {
			switch len(bytes) {
			case 16:
				return &Keys{RC4: bytes}, nil
			case 32:
				return &Keys{AES256: bytes}, nil
			}
		}
	}

	// Try Impacket secretsdump format: DOMAIN\User:UID:LM:NT:::
	if parts := strings.Split(input, ":"); len(parts) >= 4 {
		ntPart := parts[3]
		if len(ntPart) == 32 {
			if bytes, err := hex.DecodeString(ntPart); err == nil {
				return &Keys{RC4: bytes}, nil
			}
		}
	}

	return nil, fmt.Errorf("unrecognized hash format: expected 32-char NT hash, 64-char AES256 key, or Impacket secretsdump line")
}
