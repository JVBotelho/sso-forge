# azureadsssoacc

Cloud token forgery via AZUREADSSOACC Kerberos key extraction.

## What
Extract the AZUREADSSOACC computer account's AES256 key via DCSync → forge Kerberos
service ticket → WS-Trust exchange at `autologon.microsoftazuread-sso.com` → Entra ID
access token for ANY synced user. Bypass MFA + Conditional Access.

## Why
Domain Admin on-prem doesn't give you cloud access. Reset user passwords doesn't
bypass MFA. This converts DA → Entra ID token without touching the user.

## Feasibility
**HIGH (8/10).** AADInternals proves full chain works end-to-end. WS-Trust endpoint
NOT deprecated. AES256 supported. No cross-platform port exists.

## Status
Research phase. Deep dive complete. No code yet.

## Files
- `21-AZUREADSSOACC-Token-Forgery-detail.md` — Original implementation plan
- `deep-dive-21-AZUREADSSOACC.md` — Deep dive feasibility with AADInternals source audit
- `00-context.md` — Original consolidation overview

## v1 Scope
- DCSync AZUREADSSOACC AES256 key extraction
- Kerberos service ticket forging (PAC + EncTicketPart)
- WS-Trust SOAP exchange to get DesktopSsoToken
- SAML assertion → OAuth2 token exchange
- Single static binary (Rust or Go)

## Lab Reference
DetectionLab DC at 192.168.50.227 (WINDOMAIN/Administrator:vagrant)
Seamless SSO endpoint needs testing against a real Entra ID tenant.
