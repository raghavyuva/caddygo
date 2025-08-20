package caddygo

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// generateCertTag generates a unique tag for the certificate based on the domain and certificate content.
// It extracts the certificate serial number and appends a timestamp to create a unique identifier.
//
// Parameters:
//   - domain: The domain name associated with the certificate
//   - certificate: PEM-encoded certificate content
//
// Returns a string tag and any error that occurred during the process.
//
// Returns an error if the certificate cannot be parsed.
func (c *Client) generateCertTag(domain, certificate string) (string, error) {
	// Parse certificate to get serial number
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	serialNumber := fmt.Sprintf("%x", cert.SerialNumber)
	timestamp := time.Now().Format("20060102150405")

	return fmt.Sprintf("%s-%s-%s", domain, serialNumber, timestamp), nil
}

// updateTLSConnectionPolicies updates the TLS connection policies for the specified domain.
// It creates a new policy that matches the domain and selects the certificate with the given tag.
// It also removes existing policies that match the domain.
//
// Parameters:
//   - server: The server configuration to update
//   - domain: The domain name to match
//   - certTag: The tag of the certificate to select
//
// Updates the server's TLS connection policies.
func (c *Client) updateTLSConnectionPolicies(server *caddyhttp.Server, domain, certTag string) {
	policy := &caddytls.ConnectionPolicy{
		MatchersRaw: map[string]json.RawMessage{
			"sni": caddyconfig.JSON([]string{domain}, nil),
		},
		CertSelection: &caddytls.CustomCertSelectionPolicy{
			AllTags: []string{certTag},
		},
	}

	// Remove existing policies for this domain
	var updatedPolicies []*caddytls.ConnectionPolicy
	for _, existingPolicy := range server.TLSConnPolicies {
		keep := true
		if existingPolicy.MatchersRaw != nil {
			if sniRaw, exists := existingPolicy.MatchersRaw["sni"]; exists {
				var sniHosts []string
				if err := json.Unmarshal(sniRaw, &sniHosts); err == nil {
					for _, host := range sniHosts {
						if host == domain {
							keep = false
							break
						}
					}
				}
			}
		}
		if keep {
			updatedPolicies = append(updatedPolicies, existingPolicy)
		}
	}

	// Add new policy
	updatedPolicies = append(updatedPolicies, policy)
	server.TLSConnPolicies = updatedPolicies
}
