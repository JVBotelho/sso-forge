# ADR 005: Reference Oracle — AADInternals + gokrb5 for Cross-Validation

- **Status:** accepted
- **Date:** 2026-07-09
- **Deciders:** skewrun

## Context

Kerberos crypto has no official test vectors for the complete pipeline (password → encrypt → ticket). The RFCs describe algorithms but don't provide byte-level examples. Implementing from RFC alone risks subtle errors that produce rejected tickets with no useful error from the WS-Trust endpoint.

We have three working implementations of Kerberos crypto to use as oracles:
1. **AADInternals** (PowerShell) — the reference for Azure SSO specifically. Works against real WS-Trust endpoints.
2. **gokrb5** (Go) — battle-tested against MIT KDC and Microsoft AD. Pure Go, easy to instrument.
3. **kerlab** (Rust) — the crypto base we're forking. Already working for AS-REQ/TGS-REQ.

## Decision

**Generate test vectors by instrumenting gokrb5 and cross-validate kerberos-crypto output byte-for-byte.**

For each crypto operation:
1. Feed known inputs (key, plaintext, salt, usage) to gokrb5
2. Capture raw output bytes
3. Feed same inputs to kerberos-crypto
4. Assert byte-identical output

Operations requiring test vectors:
- `RC4-HMAC encrypt(password, plaintext, usage) → ciphertext`
- `RC4-HMAC decrypt(password, ciphertext, usage) → plaintext`
- `AES-CTS encrypt(key, plaintext, usage) → ciphertext`
- `AES-CTS decrypt(key, ciphertext, usage) → plaintext`
- `DK(base_key, usage, mode) → derived_key`
- `HMAC-MD5 checksum(key, data) → signature`
- `MD4(password) → hash`
- `PBKDF2(password, salt, iterations) → key`

Additionally, generate end-to-end test vectors using AADInternals:
- Given AZUREADSSOACC NT hash + target user SID → forged KRB_AP_REQ bytes
- Cross-validate the full DER-encoded ticket structure (not just crypto — also ASN.1 structure)

## Consequences

- Test suite can run entirely offline (no Entra ID tenant needed for CI)
- Byte-identical output against gokrb5 means crypto is correct — WS-Trust rejection can only be caused by PAC structure or ASN.1 encoding, not crypto
- Test vector generation is one-time cost (~1 day of scripting gokrb5 test harness)
- gokrb5 is Go, so test generation requires `go run` in CI or pre-generated fixture files
- Pre-generated fixtures (binary `.bin` files checked into repo) are preferred over runtime dependency on Go
