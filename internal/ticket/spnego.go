package ticket

import (
	"encoding/asn1"
)

// SPNEGO OIDs for mechanism negotiation.
var (
	oidMSKerberos = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
	oidKerberosV5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
	oidNegoEx     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 30}
	oidNTLM       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	oidSPNEGO     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
)

type negTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"optional,explicit,tag:1"`
	MechToken   []byte                  `asn1:"optional,explicit,tag:2"`
	MechListMIC []byte                  `asn1:"optional,explicit,tag:3"`
}

// BuildSPNEGO wraps KRB_AP_REQ in SPNEGO NegTokenInit with GSS-API wrapping.
//
// Full structure (matching AADInternals):
//
//	[0x60] SPNEGO mechanism token
//	  OID 1.3.6.1.5.5.2 (SPNEGO)
//	  [0xA0] NegotiationToken = NegTokenInit SEQUENCE
//	    [0] mechTypes: OIDs
//	    [2] mechToken:
//	      [0x60] GSS-API Kerberos mechanism token
//	        OID 1.2.840.113554.1.2.2 (Kerberos V5)
//	        0 (GSS-API flags)
//	        [0x6E] KRB_AP_REQ
func BuildSPNEGO(apReqBytes []byte) ([]byte, error) {
	return buildSPNEGO(apReqBytes, false)
}

func BuildSPNEGOFull(apReqBytes []byte) ([]byte, error) {
	return buildSPNEGO(apReqBytes, true)
}

func buildSPNEGO(apReqBytes []byte, full bool) ([]byte, error) {
	gssToken := gssapiKerberosToken(apReqBytes)

	mechTypes := []asn1.ObjectIdentifier{oidMSKerberos, oidKerberosV5}
	if full {
		mechTypes = append(mechTypes, oidNegoEx, oidNTLM)
	}

	nti := negTokenInit{
		MechTypes: mechTypes,
		MechToken: gssToken,
	}

	return spnegoMechToken(nti)
}

// gssapiKerberosToken wraps AP_REQ in GSS-API Kerberos mechanism token.
//
//	[0x60] APPLICATION constructed
//	  OID 1.2.840.113554.1.2.2 (Kerberos V5)
//	  BOOLEAN FALSE (GSS-API flags — not used)
//	  KRB_AP_REQ bytes (already APPLICATION-tagged by gokrb5)
func gssapiKerberosToken(apReq []byte) []byte {
	oidDER, _ := asn1.Marshal(oidKerberosV5)

	// [0x60] APPLICATION { OID, BOOLEAN FALSE, KRB_AP_REQ }
	// apReq already has APPLICATION tag from APReq.Marshal() — do NOT wrap again
	inner := make([]byte, 0)
	inner = append(inner, oidDER...)
	inner = append(inner, 0x01, 0x00) // BOOLEAN FALSE
	inner = append(inner, apReq...)   // already tagged by gokrb5

	result := make([]byte, 0)
	result = append(result, 0x60)
	result = append(result, derLen(len(inner))...)
	result = append(result, inner...)

	return result
}

// spnegoMechToken wraps NegTokenInit in SPNEGO mechanism token.
//
//	[0x60] APPLICATION constructed
//	  OID 1.3.6.1.5.5.2 (SPNEGO)
//	  [0xA0] NegTokenInit SEQUENCE
func spnegoMechToken(nti negTokenInit) ([]byte, error) {
	oidDER, err := asn1.Marshal(oidSPNEGO)
	if err != nil {
		return nil, err
	}

	ntiDER, err := asn1.Marshal(nti)
	if err != nil {
		return nil, err
	}

	tagged := make([]byte, 0, 4+len(ntiDER))
	tagged = append(tagged, 0xA0)
	tagged = append(tagged, derLen(len(ntiDER))...)
	tagged = append(tagged, ntiDER...)

	// [0x60] APPLICATION { OID, [0xA0] NegTokenInit } — NO extra SEQUENCE
	inner := make([]byte, 0)
	inner = append(inner, oidDER...)
	inner = append(inner, tagged...)

	result := make([]byte, 0)
	result = append(result, 0x60)
	result = append(result, derLen(len(inner))...)
	result = append(result, inner...)

	return result, nil
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
