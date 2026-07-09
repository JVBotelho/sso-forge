# ADR 006: Crypto Strategy — gokrb5 v8

- **Status:** accepted
- **Date:** 2026-07-09
- **Deciders:** skewrun
- **Supersedes:** previous kerlab fork decision (2026-07-09)

## Context

gokrb5 v8.4.4 (github.com/jcmturner/gokrb5/v8) provides all crypto primitives needed:

| Component | gokrb5 module | Status |
|---|---|---|
| RC4-HMAC encrypt/decrypt | `gokrb5/v8/crypto` | Production-tested against AD KDC |
| AES-CTS-CBC encrypt/decrypt | `gokrb5/v8/crypto` | RFC 3962 compliant |
| DK() key derivation | `gokrb5/v8/crypto` | RFC 3961 compliant |
| MD4 hash (NT hash) | `gokrb5/v8/crypto` | Standard |
| HMAC-MD5 checksums | `gokrb5/v8/crypto` | Used for PAC |
| Kerberos ASN.1 types | `gokrb5/v8/types` | Ticket, EncTicketPart, Authenticator, etc. |
| PAC types | `gokrb5/v8/pac` | KerbValidationInfo, PacType, SignatureData |
| SPNEGO types | `gokrb5/v8/spnego` | NegTokenInit, NegTokenResp |
| KRB_AP_REQ | `gokrb5/v8/messages` | Marshal/Unmarshal |

No crypto needs to be written from scratch. gokrb5 is Apache-2.0 licensed, compatible with this project.

## Known gokrb5 limitations

- **`encoding/asn1` bugs:** Go stdlib has known Kerberos ASN.1 issues (GeneralString, app tags, slice-of-RawValue). gokrb5 ships custom forks to work around these. External code using gokrb5 types must use gokrb5's encoding/decoding, not stdlib directly.
- **PAC construction:** gokrb5 has PAC *parsing* (decode KerbValidationInfo from bytes) but not PAC *construction* (build KerbValidationInfo struct and serialize to NDR). This is what `internal/pac` must implement.
- **No MS-KILE auth-data types:** gokrb5 doesn't define KERB_AUTH_DATA_TOKEN_RESTRICTIONS, KerbLocal, etc. These must be defined in `internal/ticket` as simple structs.

## Decision

**Use gokrb5 v8 as the sole crypto and Kerberos types dependency.** Fork or replace only the packages needed (PAC construction, MS-KILE types) — never fork gokrb5 itself.

## Consequences

- Zero crypto code to write — gokrb5 is complete
- `go.mod` has one primary dependency: `github.com/jcmturner/gokrb5/v8`
- Test vectors: gokrb5 crypto is already tested against MIT KDC and AD. Only PAC construction needs cross-validation against AADInternals output
- Risk: gokrb5's `encoding/asn1` forks may break on future Go versions. Mitigated by pinning dependency versions
