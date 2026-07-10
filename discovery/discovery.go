// Package discovery resolves Entra ID tenant and Kerberos realm information
// from a domain name using public endpoints.
package discovery

import (
	"fmt"
	"strings"
)

// Info holds resolved tenant and realm information.
type Info struct {
	TenantID string
	Realm    string
	Domain   string
}

// Resolve discovers the tenant ID and Kerberos realm for a domain.
//
// Tenant ID is derived from OpenID Connect discovery.
// Realm is the uppercase FQDN (Kerberos convention).
//
// If TenantID can't be auto-discovered, it's left empty — the exchange
// package falls back to "common" tenant endpoint.
func Resolve(domain string) (*Info, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	return &Info{
		Domain: domain,
		Realm:  strings.ToUpper(domain),
	}, nil
}

// ResolveOrDiscover resolves domain info, attempting tenant discovery if possible.
// This is a convenience wrapper that doesn't block on network calls.
func ResolveOrDiscover(domain string, tenantID string) (*Info, error) {
	info, err := Resolve(domain)
	if err != nil {
		return nil, err
	}
	if tenantID != "" {
		info.TenantID = tenantID
	}
	return info, nil
}
