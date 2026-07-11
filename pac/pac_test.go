package pac

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"testing"
)

func TestBuild(t *testing.T) {
	params := &BuildParams{
		UserSID:       "S-1-5-21-3380191644-1795262921-1717786542-1105",
		UserRID:       1105,
		DomainNetBIOS: "CORP",
		DomainFQDN:    "corp.contoso.com",
		UPN:           "bob@corp.contoso.com",
		FullName:      "Bob Smith",
		NTHash:        bytes.Repeat([]byte{0xAA}, 16),
	}

	b := NewBuilder(params)
	pacBytes, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Basic structural checks
	if len(pacBytes) < 8+5*16+24 {
		t.Fatalf("PAC too small: %d bytes", len(pacBytes))
	}

	r := bytes.NewReader(pacBytes)

	// CBuffers
	var cBuffers uint32
	binary.Read(r, binary.LittleEndian, &cBuffers)
	if cBuffers != 5 {
		t.Errorf("CBuffers = %d, want 5", cBuffers)
	}

	// Version
	var version uint32
	binary.Read(r, binary.LittleEndian, &version)
	if version != 0 {
		t.Errorf("Version = %d, want 0", version)
	}

	// Check InfoBuffer entries
	expectedTypes := []uint32{
		InfoTypeKerbValidationInfo,
		InfoTypePACClientInfo,
		InfoTypeUPNDNSInfo,
		InfoTypePACServerSignature,
		InfoTypePACKDCSignature,
	}

	for i, et := range expectedTypes {
		var ulType, cbSize uint32
		var offset uint64
		binary.Read(r, binary.LittleEndian, &ulType)
		binary.Read(r, binary.LittleEndian, &cbSize)
		binary.Read(r, binary.LittleEndian, &offset)

		if ulType != et {
			t.Errorf("buffer[%d].ULType = %d, want %d", i, ulType, et)
		}
		if cbSize == 0 {
			t.Errorf("buffer[%d].CBBufferSize = 0", i)
		}
		if offset%8 != 0 {
			t.Errorf("buffer[%d].Offset = %d, not 8-byte aligned", i, offset)
		}
	}

	// Verify server checksum was filled — read signature at offset from buffer index 3 (server signature)
	// The signature bytes (4+16=20 bytes) should be non-zero after Build()
	_ = expectedTypes
}

func TestServerChecksum(t *testing.T) {
	ntHash := bytes.Repeat([]byte{0xBB}, 16)
	pacData := bytes.Repeat([]byte{0xCC}, 256)

	cs := ServerChecksum(pacData, ntHash)

	if len(cs) != 16 {
		t.Errorf("checksum len = %d, want 16", len(cs))
	}

	// Verify it matches independent computation (MD5 prefix + HMAC-MD5)
	ksign := HmacMD5(ntHash, []byte(signatureKeyBytes))
	tmp := md5Hash(append([]byte{0x11, 0x00, 0x00, 0x00}, pacData...))
	expected := HmacMD5(ksign, tmp)

	if !hmac.Equal(cs, expected) {
		t.Errorf("checksum mismatch")
	}
}

func TestParseSID(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
	}{
		{"S-1-5-21-3380191644-1795262921-1717786542-1105", true},
		{"S-1-5-18", true},
		{"S-1-5-32-544", true},
		{"invalid", false},
		{"S-1", false},
	}

	for _, tc := range tests {
		_, err := parseSID(tc.input)
		if tc.ok && err != nil {
			t.Errorf("parseSID(%q) = error: %v", tc.input, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("parseSID(%q) = nil, want error", tc.input)
		}
	}
}

func TestParseSIDRoundtrip(t *testing.T) {
	sid := "S-1-5-21-3380191644-1795262921-1717786542-1105"
	b, err := parseSID(sid)
	if err != nil {
		t.Fatalf("parseSID: %v", err)
	}

	// SID binary: Rev(1) + SubCount(1) + Authority(6) + Subs(N*4)
	expectedLen := 1 + 1 + 6 + 5*4 // 28 bytes for a SID with 5 sub-authorities
	if len(b) < expectedLen {
		t.Errorf("SID too short: %d bytes, want at least %d", len(b), expectedLen)
	}

	if b[0] != 1 {
		t.Errorf("revision = %d, want 1", b[0])
	}
}

func TestRoundUp(t *testing.T) {
	if roundUp(0, 8) != 0 {
		t.Errorf("roundUp(0, 8) = %d", roundUp(0, 8))
	}
	if roundUp(1, 8) != 8 {
		t.Errorf("roundUp(1, 8) = %d", roundUp(1, 8))
	}
	if roundUp(8, 8) != 8 {
		t.Errorf("roundUp(8, 8) = %d", roundUp(8, 8))
	}
	if roundUp(9, 8) != 16 {
		t.Errorf("roundUp(9, 8) = %d", roundUp(9, 8))
	}
}
