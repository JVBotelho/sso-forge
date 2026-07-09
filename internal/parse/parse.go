// Package parse extracts Kerberos keys from supplementalCredentials blobs
// and common hash input formats.
//
// Reference: [MS-SAMR] §2.2.10 USER_PROPERTIES → KERB_STORED_CREDENTIAL
package parse

import (
	"encoding/binary"
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

// KERB_STORED_CREDENTIAL structure constants
const (
	kerbStoredCredentialSignature = 0x4B455242 // "KERB" in little-endian
	kerbKeyTypeRC4               uint32 = 0xFFFFFF83 // -125 as unsigned
	kerbKeyTypeAES128            uint32 = 0xFFFFFF88 // -120 as unsigned
	kerbKeyTypeAES256            uint32 = 0xFFFFFF8D // -115 as unsigned
)

// SupplementalCredentials parses a raw supplementalCredentials blob
// and extracts Kerberos keys for all available encryption types.
//
// The blob is the aggregate value of the supplementalCredentials attribute
// as returned by DRSGetNCChanges (DCSync). It contains one or more
// USER_PROPERTY structures, each containing a property name and value.
//
// We look for the "Primary:Kerberos-Newer-Keys" property, which has a
// KERB_STORED_CREDENTIAL containing a KEY_LIST with KERB_KEY_DATA entries.
func SupplementalCredentials(blob []byte) (*Keys, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("blob too short: %d bytes", len(blob))
	}

	keys := &Keys{}

	// The blob is a sequence of USER_PROPERTY entries.
	// Each entry: NameLength(2) + Name(NameLength bytes) + ValueLength(2) + Value(ValueLength bytes)
	offset := 0
	for offset+4 <= len(blob) {
		if offset+2 > len(blob) {
			break
		}
		nameLen := int(binary.LittleEndian.Uint16(blob[offset:]))
		offset += 2
		if offset+nameLen > len(blob) {
			break
		}
		name := string(blob[offset : offset+nameLen])
		offset += nameLen

		if offset+2 > len(blob) {
			break
		}
		valLen := int(binary.LittleEndian.Uint16(blob[offset:]))
		offset += 2
		if offset+valLen > len(blob) {
			break
		}
		value := blob[offset : offset+valLen]
		offset += valLen

		// Look for Kerberos key properties
		switch name {
		case "Primary:Kerberos-Newer-Keys":
			parseKerbStoredCredential(value, keys)
		case "Primary:Kerberos":
			parseKerbStoredCredential(value, keys)
		}
	}

	if keys.RC4 == nil && keys.AES128 == nil && keys.AES256 == nil {
		return nil, fmt.Errorf("no Kerberos keys found in supplementalCredentials")
	}

	return keys, nil
}

// parseKerbStoredCredential extracts keys from a KERB_STORED_CREDENTIAL blob.
//
// Structure:
//
//	Revision(2) | Flags(2) | CredentialCount(4) | ServiceCredentialCount(4) |
//	DomainControllerCount(4) | DefaultSaltLength(2) | DefaultSaltMaximumLength(2) |
//	DefaultSaltOffset(4) | ...
//	Credentials: KEY_LIST with KERB_KEY_DATA entries
func parseKerbStoredCredential(data []byte, keys *Keys) {
	if len(data) < 4 {
		return
	}

	// Parse the fixed header to find the salt and key list
	// We need Revision(2) | Flags(2) to get started
	// Then we scan for known key sizes to extract keys

	offset := 0
	if offset+2 > len(data) {
		return
	}
	// We don't need the actual header structure — we scan for key lengths
	// by looking for the RC4 key (always 16 bytes + header) and AES keys

	// Simple heuristic: look for key surrounded by known structure markers.
	// RC4 key is preceded by: KeyType(4) + Reserved(4) + KeyLength(4) + ... + KeyOffset(4)
	// We search for KeyType = -125 (0xFFFFFF83 for RC4)
	extractKeyByType(data, kerbKeyTypeRC4, 16, &keys.RC4)
	extractKeyByType(data, kerbKeyTypeAES128, 16, &keys.AES128)
	extractKeyByType(data, kerbKeyTypeAES256, 32, &keys.AES256)

	_ = offset
}

// extractKeyByType searches a blob for a key of the given type and extracts it.
func extractKeyByType(data []byte, keyType uint32, keySize int, target *[]byte) {
	if *target != nil {
		return // already found
	}

	typeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(typeBytes, keyType)

	for i := 0; i < len(data)-12-keySize; i++ {
		if binary.LittleEndian.Uint32(data[i:i+4]) != keyType {
			continue
		}
		// Found key type marker. Look for the key length at offset + 8 (after Reserved(4))
		if i+12+keySize > len(data) {
			continue
		}
		keyLen := binary.LittleEndian.Uint32(data[i+8 : i+12])
		if int(keyLen) == keySize {
			// Key offset is at i+12, key data at that offset
			keyOffset := binary.LittleEndian.Uint32(data[i+12 : i+16])
			if int(keyOffset)+keySize <= len(data) {
				k := make([]byte, keySize)
				copy(k, data[keyOffset:keyOffset+uint32(keySize)])
				*target = k
				return
			}
		}
	}
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

// MustParseHashInput is like ParseHashInput but panics on error.
func MustParseHashInput(input string) *Keys {
	k, err := ParseHashInput(input)
	if err != nil {
		panic(err)
	}
	return k
}
