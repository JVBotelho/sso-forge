# ADR 002: Repository Structure — Go Module, Flat Internal Packages

- **Status:** accepted
- **Date:** 2026-07-09
- **Deciders:** skewrun

## Context

Go projects have two common layouts: flat (everything in root or `internal/`) vs cmd-based (each binary in `cmd/`). This project has a single binary and ~6 internal packages.

## Decision

**Flat with `internal/` for private packages.** Single Go module at root.

```
sso-forge/
├── go.mod                    # module github.com/JVBotelho/sso-forge
├── go.sum
├── main.go                   # CLI entry point
├── internal/
│   ├── pac/                  # pac.go — PAC construction
│   ├── ticket/               # ticket.go — EncTicketPart + Authenticator assembly
│   ├── exchange/             # wstrust.go, saml.go, oauth2.go
│   ├── parse/                # parse.go — supplementalCredentials blob parser
│   └── discovery/            # tenant.go — Tenant ID, realm resolution
├── docs/
│   └── adr/                  # Architecture decision records
├── README.md
└── Makefile
```

### Package responsibilities (mirrors ADR 003 from Rust era)

| Package | Responsibility | Depends on |
|---|---|---|
| `internal/pac` | PAC_INFO_BUFFER construction, NDR encoding, HMAC-MD5 checksums | gokrb5/pac (types), gokrb5/crypto |
| `internal/ticket` | EncTicketPart + Authenticator assembly, encryption with AZUREADSSOACC key | gokrb5/types, gokrb5/crypto, internal/pac |
| `internal/exchange` | WS-Trust SOAP, SAML assertion, OAuth2 token exchange | net/http, encoding/xml |
| `internal/parse` | supplementalCredentials blob → RC4/AES key extraction | encoding/binary |
| `internal/discovery` | Tenant ID from domain, Kerberos realm from DNS | net/http |

### Why `internal/`

Go's `internal/` directory enforces that these packages cannot be imported by external modules. This is correct — they are glue code specific to this tool, not reusable libraries (unlike the Rust approach where crates were designed for ecosystem reuse).

## Consequences

- Single `go.mod`, single `go.sum`
- `go build ./...` builds everything
- `go test ./...` tests everything
- No monorepo complexity — Go's package system is simpler than Cargo workspaces
- If any package proves genuinely reusable, extract to separate Go module later
