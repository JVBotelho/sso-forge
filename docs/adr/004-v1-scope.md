# ADR 004: v1 Scope — Forge-only, RC4-first, No DCSync

- **Status:** accepted
- **Date:** 2026-07-09
- **Deciders:** skewrun

## Context

The full pipeline has 3 stages: key extraction → ticket forgery → cloud token exchange. We must decide what ships in v1.

1. **Key extraction:** DCSync (MS-DRSR), LSA secrets, or SQL LocalDB+DPAPI. All paths exist in other tools (secretsdump.py, Mimikatz). LSA and SQL are Windows-only.
2. **Ticket forgery:** RC4-HMAC vs AES256-CTS. AES required for post-July-2026 new deployments. RC4 covers existing tenants (>80%).
3. **Scope width:** DCSync integrated vs hash-as-input. Multi-user vs single ticket. Persistence vs one-shot.

## Decision

**v1 is forge + exchange only. No key extraction. RC4-only. One ticket per execution.**

```
sso-forge \
  --hash <AZUREADSSOACC_NT_hash> \
  --sid <target_user_SID> \
  --domain <corp.contoso.com> \
  --resource https://graph.windows.net \
  --output json
```

### In v1
- Parse supplementalCredentials blob (extract RC4 and AES keys, even if AES unused)
- Kerberos ticket forging with RC4-HMAC
- WS-Trust SOAP exchange → DesktopSsoToken
- SAML 1.1 assertion → OAuth2 token
- Support for custom client_id and multiple resources

### Explicitly NOT in v1
- DCSync / LSA / SQL extraction — operator brings pre-extracted hash
- AES256 encryption — kerberos-crypto implements it but sso-forge doesn't use it yet
- Multi-user forging — one ticket per execution
- Refresh token caching / persistence
- Multi-forest support — single domain only

### v1.5 (next iteration)
- AES256 encryption support (kerberos-crypto already has it, sso-forge just needs to use it)
- Multi-forest ticket forging

### v2 (future)
- DCSync integration (or parse secretsdump output directly)
- Multi-user batch mode
- Linux LSA equivalent (if viable)

## Rationale

- **No extraction** avoids reimplementing DCSync (~2000 lines of DCERPC) and Windows-only code (LSA, SQL+DPAPI). secretsdump.py already does this.
- **RC4-first** because kerlab already has RC4-HMAC, it covers >80% of targets, and AES is additive (not a rewrite).
- **One-shot** keeps the tool focused. batching add complexity without proportional value.

## Consequences

- Operator workflow: `secretsdump.py → sso-forge`. Two tools, piped.
- The `sso-forge` CLI must accept common output formats (Impacket hash format: `DOMAIN\User:UID:LM:NT:::`)
- AES support deferred to v1.5 (kerberos-crypto implements it, sso-forge just adds `--crypto aes` flag)
