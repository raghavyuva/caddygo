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

// UpstreamTarget represents a single backend server.
type UpstreamTarget struct {
	Host string
	Port int
}

// LoadBalancingOptions configures how traffic is distributed across upstreams.
type LoadBalancingOptions struct {
	// Policy is the load balancing algorithm: "round_robin", "first", "least_conn",
	// "random", "ip_hash", "uri_hash", "header", "cookie". Empty = Caddy default (random).
	Policy string
	// HealthCheckPath enables active health checking on this HTTP path (e.g. "/health").
	// Empty = no active health checks (passive health checks still apply).
	HealthCheckPath string
	// HealthCheckIntervalSec is seconds between health check probes. Default: 10.
	HealthCheckIntervalSec int

	// PassiveFailDurationSec is how long (seconds) to remember a backend's failures.
	// After this window the backend is eligible again. 0 = disabled.
	PassiveFailDurationSec int
	// PassiveMaxFails is consecutive failures within FailDuration before marking unhealthy. 0 = disabled.
	PassiveMaxFails int
	// PassiveUnhealthyStatus lists HTTP status codes that count as failures (e.g. 502, 503).
	PassiveUnhealthyStatus []int

	// TryDurationSec is how long Caddy retries other upstreams when one fails. 0 = no retry.
	TryDurationSec int
	// TryIntervalMs is the pause (milliseconds) between retry attempts. Default: 250.
	TryIntervalMs int
}
