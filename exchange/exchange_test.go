package exchange

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestExtractDesktopSsoToken(t *testing.T) {
	xmlResp := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <wst:RequestSecurityTokenResponse>
      <wst:RequestedSecurityToken>
        <saml:Assertion>
          <DesktopSsoToken>eyJ0eXAiOiJKV1QifQ.test-token</DesktopSsoToken>
        </saml:Assertion>
      </wst:RequestedSecurityToken>
    </wst:RequestSecurityTokenResponse>
  </s:Body>
</s:Envelope>`

	token, err := extractDesktopSsoToken([]byte(xmlResp))
	if err != nil {
		t.Fatalf("extractDesktopSsoToken: %v", err)
	}
	if token != "eyJ0eXAiOiJKV1QifQ.test-token" {
		t.Errorf("token = %q, want %q", token, "eyJ0eXAiOiJKV1QifQ.test-token")
	}
}

func TestExtractDesktopSsoToken_RSTC(t *testing.T) {
	xmlResp := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <RequestSecurityTokenResponseCollection>
      <RequestSecurityTokenResponse>
        <RequestedSecurityToken>
          <Assertion>
            <DesktopSsoToken>rstc-token</DesktopSsoToken>
          </Assertion>
        </RequestedSecurityToken>
      </RequestSecurityTokenResponse>
    </RequestSecurityTokenResponseCollection>
  </s:Body>
</s:Envelope>`

	token, err := extractDesktopSsoToken([]byte(xmlResp))
	if err != nil {
		t.Fatalf("extractDesktopSsoToken RSTC: %v", err)
	}
	if token != "rstc-token" {
		t.Errorf("token = %q, want %q", token, "rstc-token")
	}
}

func TestExtractDesktopSsoToken_Invalid(t *testing.T) {
	_, err := extractDesktopSsoToken([]byte("<not>xml"))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestExtractDesktopSsoToken_EmptyToken(t *testing.T) {
	xmlResp := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <wst:RequestSecurityTokenResponse>
      <wst:RequestedSecurityToken>
        <saml:Assertion>
          <DesktopSsoToken></DesktopSsoToken>
        </saml:Assertion>
      </wst:RequestedSecurityToken>
    </wst:RequestSecurityTokenResponse>
  </s:Body>
</s:Envelope>`

	_, err := extractDesktopSsoToken([]byte(xmlResp))
	if err == nil {
		t.Error("expected error for empty DesktopSsoToken")
	}
}

func TestBuildSAMLAssertion(t *testing.T) {
	ssoToken := "test.sso.token"
	saml, err := buildSAMLAssertion(ssoToken)
	if err != nil {
		t.Fatalf("buildSAMLAssertion: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(saml)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	got := string(decoded)
	if !strings.Contains(got, `<saml:Assertion`) {
		t.Error("missing saml:Assertion root")
	}
	if !strings.Contains(got, ssoToken) {
		t.Errorf("SAML does not contain token %q: %s", ssoToken, got)
	}
}

func TestBuildSAMLAssertion_XMLEscape(t *testing.T) {
	ssoToken := `token<with&amp>dangerous"chars'`
	saml, err := buildSAMLAssertion(ssoToken)
	if err != nil {
		t.Fatalf("buildSAMLAssertion: %v", err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(saml)
	got := string(decoded)
	if strings.Contains(got, "<with&amp>") {
		t.Error("ampersand in input was double-escaped")
	}
	if strings.Contains(got, "dangerous\"chars'") {
		t.Error("raw quotes not escaped")
	}
}

func TestXmlEscape(t *testing.T) {
	tests := []struct {
		in, out string
	}{
		{"normal", "normal"},
		{"<tag>", "&lt;tag&gt;"},
		{"a&b", "a&amp;b"},
		{`"quoted"`, "&quot;quoted&quot;"},
		{"'single'", "&apos;single&apos;"},
		{"<&>\"'", "&lt;&amp;&gt;&quot;&apos;"},
		{"", ""},
	}
	for _, tt := range tests {
		got := xmlEscape(tt.in)
		if got != tt.out {
			t.Errorf("xmlEscape(%q) = %q, want %q", tt.in, got, tt.out)
		}
	}
}

func TestUUID(t *testing.T) {
	a := uuid()
	b := uuid()
	if a == b {
		t.Error("two UUIDs should not be equal")
	}
	if len(a) != 36 {
		t.Errorf("uuid length = %d, want 36", len(a))
	}
	parts := strings.Split(a, "-")
	if len(parts) != 5 {
		t.Errorf("uuid has %d parts, want 5", len(parts))
	}
}

func TestDiscoverTenantID_Parse(t *testing.T) {
	jsonResp := `{"authorization_endpoint":"https://login.microsoftonline.com/abc123-def456/oauth2/authorize"}`
	tenantID, err := parseDiscoveryResponse([]byte(jsonResp))
	if err != nil {
		t.Fatalf("parseDiscoveryResponse: %v", err)
	}
	if tenantID != "abc123-def456" {
		t.Errorf("tenantID = %q, want %q", tenantID, "abc123-def456")
	}
}

func TestDiscoverTenantID_ParseInvalid(t *testing.T) {
	_, err := parseDiscoveryResponse([]byte(`{"auth_endpoint": "x"}`))
	if err == nil {
		t.Error("expected error for missing authorization_endpoint")
	}
}

func TestDiscoverTenantID_Parse_NoTenant(t *testing.T) {
	// authorization_endpoint doesn't contain login.microsoftonline.com
	_, err := parseDiscoveryResponse([]byte(`{"authorization_endpoint":"https://example.com/auth"}`))
	if err == nil {
		t.Error("expected error for non-microsoft endpoint")
	}
}
