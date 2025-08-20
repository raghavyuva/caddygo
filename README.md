# CaddyGo

[![Go Version](https://img.shields.io/github/go-mod/go-version/raghavyuva/caddygo)](https://golang.org)
[![Go Report Card](https://goreportcard.com/badge/github.com/raghavyuva/caddygo)](https://goreportcard.com/report/github.com/raghavyuva/caddygo)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A simple Go library for managing Caddy server configurations through its admin API. CaddyGo provides a clean, intuitive interface to add, remove, and configure domains with automatic or custom TLS certificates, following Go best practices and clean architecture principles.

## ✨ Features

- **Domain Management**: Add and remove domains with ease
- **Automatic TLS**: Support for Let's Encrypt and other ACME providers  
- **Custom Certificates**: Use your own TLS certificates
- **Security Headers**: Configurable security headers (HSTS, X-Frame-Options, etc.)
- **Compression**: Enable gzip and zstd compression
- **Redirects**: Support for www/non-www redirects
- **Configuration Reload**: Force Caddy to reload configurations
- **Clean Architecture**: Well-organized, maintainable codebase

## 📦 Installation

```bash
go get github.com/raghavyuva/caddygo
```

##  Quick Start

```go
package main

import (
    "log"
    "github.com/raghavyuva/caddygo"
)

func main() {
    // Create a new client
    client := caddygo.NewClient("http://localhost:2019")
    
    // Configure domain options
    options := caddygo.DomainOptions{
        EnableSecurityHeaders: true,
        EnableHSTS:           true,
        EnableCompression:    true,
        RedirectMode:         "www_to_domain",
    }
    
    // Add a domain with automatic TLS
    err := client.AddDomainWithAutoTLS("example.com", "localhost", 8080, options)
    if err != nil {
        log.Fatal(err)
    }
    
    // Reload configuration
    err = client.Reload()
    if err != nil {
        log.Fatal(err)
    }
    
    log.Println("Domain configured successfully!")
}
```

## Package Architecture

CaddyGo is organized into focused, single-responsibility modules:

```
caddygo/
├── types.go      # Type definitions and interfaces
├── client.go     # HTTP client and request handling
├── domain.go     # Domain management operations
├── tls.go        # TLS and certificate management
├── config.go     # Configuration helpers and utilities
└── caddygo.go    # Package entry point
```

## API Reference

### Core Types

#### Client
The main client for interacting with Caddy's admin API.

```go
type Client struct {
    BaseURL    string        // Base URL of Caddy's admin API
    HTTPClient *http.Client  // HTTP client for API requests
}
```

#### DomainOptions
Configuration options for domain setup.

```go
type DomainOptions struct {
    EnableSecurityHeaders bool   // Enable security-related HTTP headers
    EnableHSTS           bool   // Enable HTTP Strict Transport Security
    FrameOptions         string // X-Frame-Options header value
    EnableCompression    bool   // Enable gzip and zstd compression
    RedirectMode         string // Redirect behavior: "www_to_domain" or "domain_to_www"
}
```

### Client Methods

#### NewClient
Creates a new Caddy API client.

```go
func NewClient(baseURL string) *Client
```

**Parameters:**
- `baseURL`: The base URL of Caddy's admin API (defaults to "http://localhost:2019" if empty)

**Returns:** A configured Client instance

#### AddDomainWithAutoTLS
Adds a domain with automatic TLS configuration using Let's Encrypt or other ACME providers.

```go
func (c *Client) AddDomainWithAutoTLS(domain, target string, targetPort int, options DomainOptions) error
```

**Parameters:**
- `domain`: The domain name to configure (e.g., "example.com")
- `target`: The target hostname or IP address
- `targetPort`: The target port number
- `options`: Configuration options for security, compression, and redirects

**Returns:** Error if configuration fails

#### AddDomainWithTLS
Adds a domain with a custom TLS certificate.

```go
func (c *Client) AddDomainWithTLS(domain, target string, targetPort int, certificate, privateKey string, options DomainOptions) error
```

**Parameters:**
- `domain`: The domain name to configure
- `target`: The target hostname or IP address  
- `targetPort`: The target port number
- `certificate`: PEM-encoded certificate content
- `privateKey`: PEM-encoded private key content
- `options`: Configuration options

**Returns:** Error if configuration fails

#### DeleteDomain
Removes a domain configuration and all associated routes, TLS policies, and automation rules.

```go
func (c *Client) DeleteDomain(domain string) error
```

**Parameters:**
- `domain`: The domain name to remove

**Returns:** Error if deletion fails

#### Reload
Forces a reload of the Caddy configuration with cache invalidation.

```go
func (c *Client) Reload() error
```

**Returns:** Error if reload fails

## Usage Examples

### Basic Domain Setup with Auto TLS

```go
client := caddygo.NewClient("http://localhost:2019")

options := caddygo.DomainOptions{
    EnableSecurityHeaders: true,
    EnableHSTS:           true,
    EnableCompression:    true,
}

err := client.AddDomainWithAutoTLS("myapp.com", "localhost", 3000, options)
if err != nil {
    log.Fatalf("Failed to configure domain: %v", err)
}

err = client.Reload()
if err != nil {
    log.Fatalf("Failed to reload config: %v", err)
}
```

### Custom Certificate Configuration

```go
certificate := `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/OvH8T5TMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTkwMzI2MTIzNDU5WhcNMjAwMzI1MTIzNDU5WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAu1SUU7/3KryQigDTTw8cFDIehIUWqqK9t20Df1StvAhx3Xmddp/Wm3H
-----END CERTIFICATE-----`

privateKey := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
-----END PRIVATE KEY-----`

options := caddygo.DomainOptions{
    EnableSecurityHeaders: true,
    EnableHSTS:           true,
    FrameOptions:          "SAMEORIGIN",
    EnableCompression:     true,
}

err := client.AddDomainWithTLS("secure.myapp.com", "localhost", 8443, certificate, privateKey, options)
```

### Bulk Domain Management

```go
domains := []struct {
    name   string
    target string
    port   int
}{
    {"api.myapp.com", "localhost", 3001},
    {"admin.myapp.com", "localhost", 3002},
    {"cdn.myapp.com", "localhost", 3003},
}

for _, d := range domains {
    options := caddygo.DomainOptions{
        EnableSecurityHeaders: true,
        EnableCompression:     true,
        RedirectMode:          "www_to_domain",
    }
    
    err := client.AddDomainWithAutoTLS(d.name, d.target, d.port, options)
    if err != nil {
        log.Printf("Failed to add domain %s: %v", d.name, err)
        continue
    }
    
    log.Printf("Successfully configured domain: %s", d.name)
}

// Reload all configurations at once
err := client.Reload()
if err != nil {
    log.Fatalf("Failed to reload configuration: %v", err)
}
```

### Domain Cleanup

```go
// Remove a specific domain
err := client.DeleteDomain("old.example.com")
if err != nil {
    log.Printf("Failed to remove domain: %v", err)
}

// Remove multiple domains
domainsToRemove := []string{"staging.example.com", "test.example.com"}
for _, domain := range domainsToRemove {
    err := client.DeleteDomain(domain)
    if err != nil {
        log.Printf("Failed to remove %s: %v", domain, err)
    }
}

// Reload to apply changes
err = client.Reload()
```

## Configuration Options

### Security Headers
```go
options := caddygo.DomainOptions{
    EnableSecurityHeaders: true,
    EnableHSTS:           true,
    FrameOptions:          "DENY", // Options: "DENY", "SAMEORIGIN", "ALLOW-FROM"
}
```

### Compression
```go
options := caddygo.DomainOptions{
    EnableCompression: true, // Enables both gzip and zstd compression
}
```

### Redirects
```go
options := caddygo.DomainOptions{
    RedirectMode: "www_to_domain", // Options: "www_to_domain", "domain_to_www"
}
```

## Error Handling

CaddyGo provides descriptive errors for various failure scenarios:

```go
err := client.AddDomainWithAutoTLS("example.com", "localhost", 8080, options)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "failed to get current config"):
        log.Println("Unable to connect to Caddy admin API")
    case strings.Contains(err.Error(), "failed to marshal"):
        log.Println("Configuration serialization error")
    case strings.Contains(err.Error(), "failed to update config"):
        log.Println("Failed to update Caddy configuration")
    default:
        log.Printf("Unexpected error: %v", err)
    }
    return
}
```

## Requirements

- **Go**: 1.21 or later
- **Caddy**: v2 with admin API enabled
- **Network**: Access to Caddy's admin endpoint

##  Testing

Run the test suite:

```bash
go test -v
```

Run with coverage:

```bash
go test -cover
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Caddy](https://caddyserver.com/) - the modern web server
- Following Go best practices and clean architecture principles
- Inspired by the need for a clean, maintainable Caddy management library
- Reference - https://github.com/migetapp/caddy-api-client
---

**Made with ❤️ for the Go community**
