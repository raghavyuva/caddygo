package caddygo

import (
	"net/http"
)

// Client represents a client for interacting with Caddy's admin API.
// It provides methods to manage domains, TLS certificates, and server configurations.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// DomainOptions contains configuration options for domain setup.
// It allows customization of security headers, compression, and redirect behavior.
type DomainOptions struct {
	// EnableSecurityHeaders enables security-related HTTP headers
	EnableSecurityHeaders bool
	// EnableHSTS enables HTTP Strict Transport Security header
	EnableHSTS bool
	// FrameOptions sets the X-Frame-Options header value (e.g., "DENY", "SAMEORIGIN")
	FrameOptions string
	// EnableCompression enables gzip and zstd compression
	EnableCompression bool
	// RedirectMode sets redirect behavior: "www_to_domain" or "domain_to_www"
	RedirectMode string
}
