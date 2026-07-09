# ADR 003: Package Boundaries — Go

- **Status:** accepted
- **Date:** 2026-07-09
- **Deciders:** skewrun

## Context

Six internal packages. Each must have clear responsibility and correct import direction.

## Decision

### Dependency graph

```
main.go
├── internal/pac          → gokrb5/pac (types), gokrb5/crypto
├── internal/ticket       → gokrb5/types, gokrb5/crypto, internal/pac
├── internal/exchange     → net/http, encoding/xml
├── internal/parse        → encoding/binary
├── internal/discovery    → net/http
└── (all orchestrated in main.go)
```

No circular dependencies. `internal/pac` and `internal/parse` are leaf packages — they know about gokrb5 but not about each other. `internal/ticket` consumes `internal/pac`. `main.go` orchestrates all.

### What goes where

| Package | Responsibility | Key functions |
|---|---|---|
| `internal/pac` | PAC_INFO_BUFFER construction, NDR serialization, checksum computation | `pac.NewBuilder(sid, rid, domain)` → `pac.InfoBuffer`, `pac.ServerChecksum()`, `pac.PrivilegeChecksum()` |
| `internal/ticket` | EncTicketPart + Authenticator assembly, encryption | `ticket.BuildAPReq(key, realm, user, pac)` |
| `internal/exchange` | WS-Trust SOAP, SAML, OAuth2 | `exchange.GetAccessToken(domain, spnegoTicket)` |
| `internal/parse` | supplementalCredentials blob parser | `parse.SupplementalCreds(blob)` → `{rc4Key, aes128Key, aes256Key}` |
| `internal/discovery` | Tenant ID, realm resolution | `discovery.TenantID(domain)`, `discovery.Realm(domain)` |

## Consequences

- `internal/pac` is the most novel code — no Go library does PAC construction
- gokrb5 provides ~70% of the types and crypto needed
- The ~850 lines of new code are split evenly across these 5 packages
- Clear separation: if `internal/pac` proves reusable, it can be split to a public module
