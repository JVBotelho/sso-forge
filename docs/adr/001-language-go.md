# ADR 001: Language — Go

- **Status:** accepted
- **Date:** 2026-07-09
- **Deciders:** skewrun
- **Supersedes:** previous Rust decision (2026-07-09)

## Context

Evaluated Rust (kerlab + rskrb5 + rasn-kerberos) vs Go (gokrb5). The Rust ecosystem is promising but immature for this use case: rskrb5 v0.2.0 was released 2 weeks ago by a single developer. gokrb5 v8.4.4 has 8+ years of maturity, 1120+ importers, and battle-tested crypto against Microsoft Active Directory KDCs.

No capability dev argument remains for Rust: crypto exists in both ecosystems, PAC types exist in both (ms_pac in Rust, gokrb5/pac in Go), SPNEGO exists in both. The remaining work (~850 lines of glue + PAC construction + WS-Trust/OAuth2) is equally novel in both languages — neither ecosystem has it.

The Rust ecosystem (rskrb5) is worth watching and contributing to (PAC builder) but not betting v1 delivery on.

## Decision

**Go with gokrb5 v8.**

```
sso-forge/
├── go.mod
├── main.go                  # CLI entry point
├── internal/
│   ├── pac/                 # PAC construction (LOGON_INFO, CLIENT_NAME, UPN_DOMAIN, checksums)
│   ├── ticket/              # EncTicketPart + Authenticator assembly using gokrb5 types
│   ├── spnego/              # NegTokenInit wrapper (thin — gokrb5 has spnego)
│   ├── exchange/            # WS-Trust SOAP client, SAML assertion, OAuth2 exchange
│   ├── parse/               # supplementalCredentials blob parser
│   └── discovery/           # Tenant ID, realm resolution
├── cmd/
│   └── sso-forge/           # main package (or just main.go at root)
└── Makefile                 # Build + cross-compile
```

gokrb5 provides:
- `gokrb5/v8/crypto` — RC4-HMAC, AES-CTS, DK(), checksums (tested against KDC)
- `gokrb5/v8/types` — Ticket, EncTicketPart, Authenticator, EncryptedData, PrincipalName
- `gokrb5/v8/pac` — PAC parsing types (KerbValidationInfo, PacType, SignatureData)
- `gokrb5/v8/spnego` — SPNEGO types
- `gokrb5/v8/messages` — KRB_AP_REQ encoding

## Consequences

- v1 ships in 2-3 weeks (vs 3-4 in Rust)
- Stable toolchain, no nightly compiler needed
- Cross-compile: `GOOS=linux GOARCH=amd64 go build` — trivial
- Single maintainer risk replaced with 778-star community project
- rskrb5 added to watchlist for potential v2 rewrite or PAC builder contribution
- Go `encoding/asn1` has known Kerberos bugs — gokrb5 already ships workarounds
