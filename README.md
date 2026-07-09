# azureadsssoacc → sso-forge

Cloud token forgery via AZUREADSSOACC Kerberos key extraction.

## What

Extract the AZUREADSSOACC computer account's AES256/RC4 key via DCSync → forge Kerberos
service ticket → WS-Trust exchange at `autologon.microsoftazuread-sso.com` → Entra ID
access token for ANY synced user. Bypass MFA + Conditional Access.

## Why

Domain Admin on-prem doesn't give you cloud access. Reset user passwords doesn't
bypass MFA. This converts DA → Entra ID token without touching the user.

## Feasibility

**HIGH.** AADInternals proves full chain works end-to-end. WS-Trust endpoint
still active (Microsoft docs updated June 2026). No cross-platform port exists.

## Status

Planning complete. Go implementation in progress.

## Architecture

```
sso-forge/
├── main.go                   # CLI entry point
├── internal/
│   ├── pac/                  # PAC construction (LOGON_INFO, checksums)
│   ├── ticket/               # EncTicketPart + Authenticator assembly
│   ├── exchange/             # WS-Trust → SAML → OAuth2 pipeline
│   ├── parse/                # supplementalCredentials blob parser
│   └── discovery/            # Tenant ID, realm resolution
├── docs/
│   ├── adr/                  # Architecture Decision Records
│   └── milestones.md          # Development milestones
├── go.mod
├── Makefile
└── README.md
```

## v1 Scope (2 weeks)

- Parse supplementalCredentials blob → RC4/AES keys
- Kerberos service ticket forgery (PAC + EncTicketPart) — RC4 first, AES in v1.1
- WS-Trust SOAP exchange → DesktopSsoToken
- SAML assertion → OAuth2 token exchange
- Single static binary (Go, cross-compiled)

### Dependencies

- [gokrb5 v8](https://github.com/jcmturner/gokrb5) — Kerberos crypto + types (Apache-2.0)
- Go stdlib: `net/http`, `encoding/xml`, `encoding/binary`, `crypto/*`

### Explicitly NOT in v1

- DCSync (use secretsdump.py for key extraction)
- AES256 ticket encryption (RC4 only, AES in v1.1)
- Multi-user / multi-forest
- Token caching / persistence

## Usage (planned)

```bash
# Extract key via Impacket
secretsdump.py DOMAIN/Administrator@DC -just-dc-user AZUREADSSOACC$

# Forge token
sso-forge \
  --hash <NT_HASH> \
  --sid S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-XXXX \
  --domain corp.contoso.com \
  --resource https://graph.microsoft.com

# Output: valid Entra ID access token
```

## Lab Reference

DetectionLab DC at 192.168.50.227 (WINDOMAIN/Administrator:vagrant)
Seamless SSO endpoint needs testing against a real Entra ID tenant.

## References

- [AADInternals](https://github.com/Gerenios/AADInternals) — PowerShell reference implementation
- [Microsoft Seamless SSO Docs](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-how-it-works)
- [MS-PAC Protocol Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac)
- [gokrb5](https://github.com/jcmturner/gokrb5) — Go Kerberos library
