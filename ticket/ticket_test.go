package ticket

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestDerLen(t *testing.T) {
	tests := []struct {
		n    int
		hex  string
	}{
		{0, "00"},
		{1, "01"},
		{127, "7f"},
		{128, "8180"},
		{255, "81ff"},
		{256, "820100"},
		{65535, "82ffff"},
	}
	for _, tt := range tests {
		got := hex.EncodeToString(derLen(tt.n))
		if got != tt.hex {
			t.Errorf("derLen(%d) = %s, want %s", tt.n, got, tt.hex)
		}
	}
}

func TestDerInt1(t *testing.T) {
	got := derInt1(5)
	want := []byte{0x02, 0x01, 0x05}
	if !bytes.Equal(got, want) {
		t.Errorf("derInt1(5) = %x, want %x", got, want)
	}
}

func TestDerInt2(t *testing.T) {
	got := derInt2(0x00, 0x80)
	want := []byte{0x02, 0x02, 0x00, 0x80}
	if !bytes.Equal(got, want) {
		t.Errorf("derInt2(0x00,0x80) = %x, want %x", got, want)
	}
}

func TestDerInt2_SmallValue(t *testing.T) {
	got := derInt2(0x00, 0x01)
	want := []byte{0x02, 0x01, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("derInt2(0x00,0x01) = %x, want %x", got, want)
	}
}

func TestDerInt3(t *testing.T) {
	got := derInt3(0x00, 0x80, 0x03)
	want := []byte{0x02, 0x03, 0x00, 0x80, 0x03}
	if !bytes.Equal(got, want) {
		t.Errorf("derInt3(0x00,0x80,0x03) = %x, want %x", got, want)
	}
}

func TestDerIntBytes(t *testing.T) {
	got := derIntBytes([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	want := []byte{0x02, 0x04, 0xAA, 0xBB, 0xCC, 0xDD}
	if !bytes.Equal(got, want) {
		t.Errorf("derIntBytes = %x, want %x", got, want)
	}
}

func TestDerOctet(t *testing.T) {
	data := []byte{0x01, 0x02}
	got := derOctet(data)
	want := []byte{0x04, 0x02, 0x01, 0x02}
	if !bytes.Equal(got, want) {
		t.Errorf("derOctet = %x, want %x", got, want)
	}
}

func TestDerBitString(t *testing.T) {
	got := derBitString([]byte{0x20, 0x00, 0x00, 0x00})
	// BIT STRING tag(03), length=5(1 unused+4 data), 0 unused bits, data
	want := []byte{0x03, 0x05, 0x00, 0x20, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("derBitString = %x, want %x", got, want)
	}
}

func TestDerGenStr(t *testing.T) {
	got := derGenStr("HTTP")
	// UTF8String tag 1B, length 4, "HTTP"
	want := []byte{0x1B, 0x04, 'H', 'T', 'T', 'P'}
	if !bytes.Equal(got, want) {
		t.Errorf("derGenStr = %x, want %x", got, want)
	}
}

func TestDerTime(t *testing.T) {
	tm, _ := time.Parse("20060102150405Z", "20260710120000Z")
	got := derTime(tm)
	// GeneralizedTime 18, length 15, "20260710120000Z"
	want := append([]byte{0x18, 0x0F}, []byte("20260710120000Z")...)
	if !bytes.Equal(got, want) {
		t.Errorf("derTime = %x, want %x", got, want)
	}
}

func TestDerUnicodeStr(t *testing.T) {
	got := derUnicodeStr("test")
	// OCTET STRING 04, length 8 (4 chars * 2 bytes UTF16LE)
	want := []byte{0x04, 0x08, 't', 0x00, 'e', 0x00, 's', 0x00, 't', 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("derUnicodeStr = %x, want %x", got, want)
	}
}

func TestDer(t *testing.T) {
	got := der(0x30, derInt1(5), derInt1(14))
	// SEQUENCE { INTEGER 5, INTEGER 14 }
	want := []byte{0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0E}
	if !bytes.Equal(got, want) {
		t.Errorf("der(0x30,...) = %x, want %x", got, want)
	}
}

func TestDerTag(t *testing.T) {
	got := derTag(0xA0, derInt1(5))
	want := []byte{0xA0, 0x03, 0x02, 0x01, 0x05}
	if !bytes.Equal(got, want) {
		t.Errorf("derTag = %x, want %x", got, want)
	}
}

func TestDerSeq(t *testing.T) {
	got := derSeq(derInt1(1), derInt1(2))
	want := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}
	if !bytes.Equal(got, want) {
		t.Errorf("derSeq = %x, want %x", got, want)
	}
}

func TestHmacMD5(t *testing.T) {
	key := []byte{0x61, 0x62, 0x63} // "abc"
	data := []byte{0x64, 0x65, 0x66} // "def"
	got := hmacMD5(key, data)
	if len(got) != 16 {
		t.Errorf("hmacMD5 len = %d, want 16", len(got))
	}
	// Verify deterministic
	got2 := hmacMD5(key, data)
	if hex.EncodeToString(got) != hex.EncodeToString(got2) {
		t.Errorf("hmacMD5 not deterministic")
	}
}

func TestRC4Crypt(t *testing.T) {
	key := []byte("Key")
	plain := []byte("Plaintext")
	c1 := rc4Crypt(key, plain)
	c2 := rc4Crypt(key, c1)
	if !bytes.Equal(c2, plain) {
		t.Errorf("RC4 roundtrip failed")
	}
}

func TestEncryptRC4_Roundtrip(t *testing.T) {
	key := make([]byte, 16)
	key[0] = 0xAA
	data := []byte{1, 2, 3, 4, 5}
	usage := 2

	ct := encryptRC4(key, data, usage)
	if len(ct) != 16+8+len(data) {
		t.Errorf("encryptRC4 len = %d, want %d", len(ct), 16+8+len(data))
	}

	// Manual decrypt to verify
	cs := ct[:16]
	ciphertext := ct[16:]
	k2 := hmacMD5(key, []byte{byte(usage), 0, 0, 0})
	k3 := hmacMD5(k2, cs)
	pt := rc4Crypt(k3, ciphertext)
	conf := pt[:8]
	plain := pt[8:]

	if !bytes.Equal(plain, data) {
		t.Errorf("encryptRC4 roundtrip: got %x, want %x", plain, data)
	}
	_ = conf
}

func TestGssChecksumData(t *testing.T) {
	d := gssChecksumData()
	if len(d) != 24 {
		t.Errorf("gssChecksumData len = %d, want 24", len(d))
	}
	if d[0] != 0x10 || d[1] != 0x00 || d[20] != 0x3E || d[21] != 0x20 {
		t.Errorf("gssChecksumData has wrong fixed bytes: %x", d)
	}
}

func TestTokenRestrictionData(t *testing.T) {
	mid := make([]byte, 32)
	for i := range mid { mid[i] = byte(i) }
	got := tokenRestrictionData(mid)
	if len(got) != 40 {
		t.Errorf("tokenRestrictionData len = %d, want 40", len(got))
	}
	if got[4] != 0x00 || got[5] != 0x20 {
		t.Errorf("IntegrityLevel = %02x %02x, want 00 20 (Medium)", got[4], got[5])
	}
	if !bytes.Equal(got[8:40], mid) {
		t.Errorf("MachineID copy mismatch")
	}
}

func TestUtf16LE(t *testing.T) {
	got := utf16LE("AB")
	want := []byte{'A', 0x00, 'B', 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16LE = %x, want %x", got, want)
	}
}

func TestRandomBytes(t *testing.T) {
	a := randomBytes(16)
	b := randomBytes(16)
	if len(a) != 16 || len(b) != 16 {
		t.Errorf("randomBytes wrong length")
	}
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Errorf("randomBytes not random enough")
	}
}

func TestBuildTicketBodyDER_Structure(t *testing.T) {
	authTime := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	endTime := authTime.Add(10 * time.Hour)
	renewTime := authTime.Add(7 * 24 * time.Hour)
	sessKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	params := &ForgeParams{
		Key:           make([]byte, 16),
		EType:         23,
		UserPrincipal: "testuser@domain.com",
		Realm:         "DOMAIN.LOCAL",
		PAC:           make([]byte, 784),
		UserName:      "testuser",
		MachineID:     make([]byte, 32),
		KerbLocal2:    make([]byte, 16),
	}

	body := buildTicketBodyDER(authTime, endTime, renewTime, sessKey, params)
	if len(body) < 200 {
		t.Errorf("buildTicketBodyDER too small: %d bytes", len(body))
	}
	// Should start with 63 (APPLICATION 3)
	if body[0] != 0x63 {
		t.Errorf("buildTicketBodyDER first byte = %x, want 0x63", body[0])
	}
}

func TestBuildAuthenticatorDER_Structure(t *testing.T) {
	ctime := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	sessKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	seqNumber := []byte{0, 1, 2, 3}
	mid := make([]byte, 32)
	kl := make([]byte, 16)
	params := &ForgeParams{
		Realm:    "DOMAIN.LOCAL",
		UserName: "testuser",
		EType:    23,
	}

	body := buildAuthenticatorDER(ctime, sessKey, seqNumber, mid, kl, params)
	if len(body) < 100 {
		t.Errorf("buildAuthenticatorDER too small: %d bytes", len(body))
	}
	if body[0] != 0x62 {
		t.Errorf("buildAuthenticatorDER first byte = %x, want 0x62", body[0])
	}
}

func TestBuildAPREQDER_Structure(t *testing.T) {
	encTicket := make([]byte, 1138)
	encAuth := make([]byte, 453)
	params := &ForgeParams{
		Realm: "DOMAIN.LOCAL",
		EType: 23,
	}

	body := buildAPREQDER(encTicket, encAuth, params)
	if len(body) < 500 {
		t.Errorf("buildAPREQDER too small: %d bytes", len(body))
	}
	if body[0] != 0x6E {
		t.Errorf("buildAPREQDER first byte = %x, want 0x6E", body[0])
	}
}

func TestBuildSPNEGO_ContainsOIDs(t *testing.T) {
	apreq := make([]byte, 100)
	spnego := buildSPNEGO(apreq)
	// SPNEGO OID: 1.3.6.1.5.5.2 = 06 06 2b 06 01 05 05 02
	oid := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	if !bytes.Contains(spnego, oid) {
		t.Errorf("SPNEGO missing OID 1.3.6.1.5.5.2")
	}
	// Should start with 60 (APPLICATION 0)
	if spnego[0] != 0x60 {
		t.Errorf("SPNEGO first byte = %x, want 0x60", spnego[0])
	}
}

func TestDerLen_LongForms(t *testing.T) {
	// Test 3-byte long form
	got := hex.EncodeToString(derLen(65536))
	want := "83010000"
	if got != want {
		t.Errorf("derLen(65536) = %s, want %s", got, want)
	}
}

func TestDerBitString_Empty(t *testing.T) {
	got := derBitString([]byte{})
	want := []byte{0x03, 0x01, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("derBitString empty = %x, want %x", got, want)
	}
}

func TestBuildAuthAuthDataDER_ContainsServiceName(t *testing.T) {
	params := &ForgeParams{
		Realm: "DOMAIN.LOCAL",
		EType: 23,
	}
	mid := make([]byte, 32)
	kl := make([]byte, 16)
	body := buildAuthAuthDataDER(mid, kl, params)
	// Should contain the service name in UTF16LE
	svc := utf16LE("HTTP/autologon.microsoftazuread-sso.com@DOMAIN.LOCAL")
	if !bytes.Contains(body, svc) {
		t.Errorf("buildAuthAuthDataDER missing service name")
	}
}

func TestBuildTicketAuthDataDER_EmbedsPAC(t *testing.T) {
	pacBytes := []byte("TEST_PAC_DATA_784_BYTES_PADDED_TO_MATCH")
	params := &ForgeParams{PAC: pacBytes, MachineID: make([]byte, 32), KerbLocal2: make([]byte, 16)}
	body := buildTicketAuthDataDER(params)
	if !bytes.Contains(body, pacBytes) {
		t.Errorf("buildTicketAuthDataDER does not contain PAC bytes")
	}
}

func TestEncrypt_RC4_Smoke(t *testing.T) {
	key := make([]byte, 16)
	data := []byte{1, 2, 3}
	ct, err := encrypt(key, data, 2, 23)
	if err != nil {
		t.Fatalf("encrypt RC4 failed: %v", err)
	}
	if len(ct) != 16+8+3 {
		t.Errorf("encrypt RC4 output len = %d, want 27", len(ct))
	}
}

func TestForgeParams_Mutation(t *testing.T) {
	empty := &ForgeParams{
		Key: make([]byte, 16), EType: 23, UserPrincipal: "x@x",
		Realm: "X", PAC: make([]byte, 784), UserName: "x",
	}
	forged, err := Forge(empty)
	if err != nil {
		t.Fatalf("Forge failed: %v", err)
	}
	if len(forged.SPNEGOBytes) < 500 {
		t.Errorf("SPNEGO too small: %d bytes", len(forged.SPNEGOBytes))
	}
	// Verify params was mutated (MachineID and KerbLocal2 set)
	if empty.MachineID == nil || len(empty.MachineID) != 32 {
		t.Errorf("ForgeParams.MachineID not auto-generated")
	}
	if empty.KerbLocal2 == nil || len(empty.KerbLocal2) != 16 {
		t.Errorf("ForgeParams.KerbLocal2 not auto-generated")
	}
}

func TestDerTime_UTC(t *testing.T) {
	// derTime should always output UTC regardless of input timezone
	loc, _ := time.LoadLocation("America/New_York")
	tm := time.Date(2026, 7, 10, 12, 0, 0, 0, loc)
	got := derTime(tm)
	s := string(got[2 : 2+got[1]]) // skip tag 18 + length
	if !strings.HasSuffix(s, "Z") {
		t.Errorf("derTime should end with Z (UTC), got %s", s)
	}
}
