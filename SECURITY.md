# Security Policy

## Reporting a Vulnerability

This is a security research tool. For vulnerabilities in the tool itself,
open an issue or submit a pull request.

For vulnerabilities in the techniques it uses (Seamless SSO), see:

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| master  | :white_check_mark: |

## Scope

This tool forges Kerberos tickets for Entra ID Seamless SSO using the
AZUREADSSOACC key. It is a post-exploitation tool — the operator must
already have Domain Admin or equivalent privileges to extract the key.

## Authorized Use Only

This tool is intended for authorized security testing, red team
engagements, and research. Do not use it against systems or accounts
without explicit, documented permission from their owner. Misuse for
unauthorized access is outside the scope of what this project supports
and may be illegal under applicable computer-crime law.

## Dependencies

Dependencies are pinned via go.sum. Dependabot monitors for updates.
Run `go mod verify` to validate the module cache.

## Build Integrity

Releases are built via GitHub Actions with `-ldflags="-s -w"` for
reproducible, stripped binaries. SBOMs are generated via the Scorecard
workflow.
