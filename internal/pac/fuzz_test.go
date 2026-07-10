package pac

import (
	"encoding/hex"
	"testing"
)

func FuzzServerChecksum(f *testing.F) {
	hash, _ := hex.DecodeString("61bb7f03790448210063f5fe4cf1ca50")

	// Seed corpus with valid-looking data
	f.Add(make([]byte, 784))
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		cs := ServerChecksum(data, hash)
		if len(cs) != ChecksumHMACMD5Size {
			t.Errorf("ServerChecksum returned %d bytes, expected %d", len(cs), ChecksumHMACMD5Size)
		}
	})
}

func FuzzBuild(f *testing.F) {
	hash, _ := hex.DecodeString("61bb7f03790448210063f5fe4cf1ca50")
	params := &BuildParams{
		UserSID:       "S-1-5-21-2653903403-2779602846-1005841238-1110",
		UserRID:       1110,
		DomainNetBIOS: "WINDOMAIN",
		DomainFQDN:    "ssolabs830.onmicrosoft.com",
		Realm:         "WINDOMAIN.LOCAL",
		UPN:           "testuser@ssolabs830.onmicrosoft.com",
		FullName:      "DisplayName",
		ServerName:    "DC1.company.com",
		NTHash:        hash,
	}
	b := NewBuilder(params)

	// Seed with valid auth times
	f.Add(uint64(134281717310000000))
	f.Add(uint64(1))
	f.Add(uint64(0))
	f.Add(uint64(0x7fffffffffffffff))

	f.Fuzz(func(t *testing.T, authTime uint64) {
		b.SetAuthTime(authTime)
		pac, err := b.Build()
		if err != nil {
			return // Invalid inputs are expected
		}
		// Basic sanity
		if len(pac) < 88 {
			t.Errorf("PAC too small: %d bytes", len(pac))
		}
		// Verify checksum self-consistency
		cs := ServerChecksum(pac, hash)
		if len(cs) != ChecksumHMACMD5Size {
			t.Errorf("self-consistency checksum wrong size: %d", len(cs))
		}
	})
}

func FuzzParseSID(f *testing.F) {
	f.Add("S-1-5-21-2653903403-2779602846-1005841238-1110")
	f.Add("S-1-5-18")
	f.Add("")
	f.Add("S-1-5-21-0-0-0-0")
	f.Add("invalid")
	f.Add("S-1-5-21-99999999999999999999")

	f.Fuzz(func(t *testing.T, sid string) {
		b, err := parseSID(sid)
		if err != nil && b != nil {
			t.Errorf("parseSID returned both error and data")
		}
		if err == nil && b == nil {
			t.Errorf("parseSID returned nil data without error")
		}
		// Validate SID structure if parsed successfully
		if err == nil && len(b) > 0 {
			if len(b) < 8 {
				t.Errorf("SID too short: %d bytes", len(b))
			}
			if b[0] > 16 {
				t.Errorf("impossible SID revision: %d", b[0])
			}
		}
	})
}
