package caddygo

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// AddDomainWithAutoTLS adds a domain with automatic TLS configuration.
// It configures the domain to proxy requests to the specified target and enables
// automatic certificate management through Let's Encrypt or other ACME providers.
//
// Parameters:
//   - domain: The domain name to configure (e.g., "example.com")
//   - target: The target hostname or IP address
//   - targetPort: The target port number
//   - options: Configuration options for security headers, compression, and redirects
//
// Returns an error if the configuration fails.
func (c *Client) AddDomainWithAutoTLS(domain, target string, targetPort int, options DomainOptions) error {
	// Get current config
	resp, err := c.makeRequest("GET", "/config/", nil)
	if err != nil {
		return fmt.Errorf("failed to get current config: %w", err)
	}
	defer resp.Body.Close()

	var config caddy.Config
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	// Initialize HTTP app if not present
	if config.AppsRaw == nil {
		config.AppsRaw = make(map[string]json.RawMessage)
	}

	var httpApp caddyhttp.App
	if httpAppRaw, exists := config.AppsRaw["http"]; exists {
		if err := json.Unmarshal(httpAppRaw, &httpApp); err != nil {
			return fmt.Errorf("failed to unmarshal HTTP app: %w", err)
		}
	}

	if httpApp.Servers == nil {
		httpApp.Servers = make(map[string]*caddyhttp.Server)
	}

	if httpApp.Servers["srv0"] == nil {
		httpApp.Servers["srv0"] = &caddyhttp.Server{}
	}

	server := httpApp.Servers["srv0"]

	// Create route handlers
	var handlers []json.RawMessage

	// Add security headers if enabled
	if options.EnableSecurityHeaders {
		headersHandler := headers.Handler{
			Response: &headers.RespHeaderOps{
				HeaderOps: &headers.HeaderOps{
					Set: c.getSecurityHeaders(options.EnableHSTS, options.FrameOptions),
				},
			},
		}
		handlerRaw := caddyconfig.JSONModuleObject(headersHandler, "handler", "headers", nil)
		handlers = append(handlers, handlerRaw)
	}

	// Add compression if enabled
	if options.EnableCompression {
		encodeHandler := encode.Encode{
			EncodingsRaw: map[string]json.RawMessage{
				"gzip": json.RawMessage(`{}`),
				"zstd": json.RawMessage(`{}`),
			},
		}
		handlerRaw := caddyconfig.JSONModuleObject(encodeHandler, "handler", "encode", nil)
		handlers = append(handlers, handlerRaw)
	}

	// Add reverse proxy handler
	upstream := reverseproxy.Upstream{
		Dial: fmt.Sprintf("%s:%d", target, targetPort),
	}
	rpHandler := reverseproxy.Handler{
		Upstreams: reverseproxy.UpstreamPool{&upstream},
	}
	handlerRaw := caddyconfig.JSONModuleObject(rpHandler, "handler", "reverse_proxy", nil)
	handlers = append(handlers, handlerRaw)

	// Create routes
	var routes caddyhttp.RouteList

	// Handle redirects if specified
	if options.RedirectMode != "" {
		redirectRoute := c.createRedirectRoute(domain, options.RedirectMode)
		if redirectRoute != nil {
			routes = append(routes, *redirectRoute)
		}
	}

	// Create main route
	mainRoute := caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{
			{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{domain}, nil),
			},
		},
		HandlersRaw: handlers,
		Terminal:    true,
	}
	routes = append(routes, mainRoute)

	// Remove existing routes for this domain
	server.Routes = c.removeExistingRoutes(server.Routes, domain)

	// Add new routes
	server.Routes = append(server.Routes, routes...)

	// Configure auto TLS
	var tlsApp caddytls.TLS
	if tlsAppRaw, exists := config.AppsRaw["tls"]; exists {
		if err := json.Unmarshal(tlsAppRaw, &tlsApp); err != nil {
			return fmt.Errorf("failed to unmarshal TLS app: %w", err)
		}
	}

	if tlsApp.Automation == nil {
		tlsApp.Automation = &caddytls.AutomationConfig{}
	}

	if tlsApp.Automation.Policies == nil {
		tlsApp.Automation.Policies = []*caddytls.AutomationPolicy{}
	}

	// Find existing on-demand policy or create new one
	var onDemandPolicy *caddytls.AutomationPolicy
	for _, policy := range tlsApp.Automation.Policies {
		if policy.OnDemand {
			onDemandPolicy = policy
			break
		}
	}

	if onDemandPolicy == nil {
		onDemandPolicy = &caddytls.AutomationPolicy{
			OnDemand:    true,
			KeyType:     "p384",
			SubjectsRaw: []string{},
		}
		tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, onDemandPolicy)
	}

	// Add domain to subjects if not already present
	if !c.containsString(onDemandPolicy.SubjectsRaw, domain) {
		onDemandPolicy.SubjectsRaw = append(onDemandPolicy.SubjectsRaw, domain)
	}

	// Update apps in config
	httpAppRaw, err := json.Marshal(httpApp)
	if err != nil {
		return fmt.Errorf("failed to marshal HTTP app: %w", err)
	}
	config.AppsRaw["http"] = httpAppRaw

	tlsAppRaw, err := json.Marshal(tlsApp)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS app: %w", err)
	}
	config.AppsRaw["tls"] = tlsAppRaw

	// Update configuration
	_, err = c.makeRequest("POST", "/config/", config)
	if err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	return nil
}

// AddDomainWithTLS adds a domain with a custom TLS certificate.
// It configures the domain to proxy requests to the specified target using
// the provided certificate and private key.
//
// Parameters:
//   - domain: The domain name to configure (e.g., "example.com")
//   - target: The target hostname or IP address
//   - targetPort: The target port number
//   - certificate: PEM-encoded certificate content
//   - privateKey: PEM-encoded private key content
//   - options: Configuration options for security headers, compression, and redirects
//
// Returns an error if the configuration fails.
func (c *Client) AddDomainWithTLS(domain, target string, targetPort int, certificate, privateKey string, options DomainOptions) error {
	// Extract certificate serial number for tagging
	certTag, err := c.generateCertTag(domain, certificate)
	if err != nil {
		return fmt.Errorf("failed to generate certificate tag: %w", err)
	}

	// Get current config
	resp, err := c.makeRequest("GET", "/config/", nil)
	if err != nil {
		return fmt.Errorf("failed to get current config: %w", err)
	}
	defer resp.Body.Close()

	var config caddy.Config
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	// Initialize HTTP app if not present
	if config.AppsRaw == nil {
		config.AppsRaw = make(map[string]json.RawMessage)
	}

	var httpApp caddyhttp.App
	if httpAppRaw, exists := config.AppsRaw["http"]; exists {
		if err := json.Unmarshal(httpAppRaw, &httpApp); err != nil {
			return fmt.Errorf("failed to unmarshal HTTP app: %w", err)
		}
	}

	if httpApp.Servers == nil {
		httpApp.Servers = make(map[string]*caddyhttp.Server)
	}

	if httpApp.Servers["srv0"] == nil {
		httpApp.Servers["srv0"] = &caddyhttp.Server{}
	}

	server := httpApp.Servers["srv0"]

	// Create route handlers (similar to AddDomainWithAutoTLS)
	var handlers []json.RawMessage

	// Add security headers if enabled
	if options.EnableSecurityHeaders {
		headersHandler := headers.Handler{
			Response: &headers.RespHeaderOps{
				HeaderOps: &headers.HeaderOps{
					Set: c.getSecurityHeaders(options.EnableHSTS, options.FrameOptions),
				},
			},
		}
		handlerRaw := caddyconfig.JSONModuleObject(headersHandler, "handler", "headers", nil)
		handlers = append(handlers, handlerRaw)
	}

	// Add compression if enabled
	if options.EnableCompression {
		encodeHandler := encode.Encode{
			EncodingsRaw: map[string]json.RawMessage{
				"gzip": json.RawMessage(`{}`),
				"zstd": json.RawMessage(`{}`),
			},
		}
		handlerRaw := caddyconfig.JSONModuleObject(encodeHandler, "handler", "encode", nil)
		handlers = append(handlers, handlerRaw)
	}

	// Add reverse proxy handler
	upstream := reverseproxy.Upstream{
		Dial: fmt.Sprintf("%s:%d", target, targetPort),
	}
	rpHandler := reverseproxy.Handler{
		Upstreams: reverseproxy.UpstreamPool{&upstream},
	}
	handlerRaw := caddyconfig.JSONModuleObject(rpHandler, "handler", "reverse_proxy", nil)
	handlers = append(handlers, handlerRaw)

	// Create routes
	var routes caddyhttp.RouteList

	// Handle redirects if specified
	if options.RedirectMode != "" {
		redirectRoute := c.createRedirectRoute(domain, options.RedirectMode)
		if redirectRoute != nil {
			routes = append(routes, *redirectRoute)
		}
	}

	// Create main route
	mainRoute := caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{
			{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{domain}, nil),
			},
		},
		HandlersRaw: handlers,
		Terminal:    true,
	}
	routes = append(routes, mainRoute)

	// Remove existing routes for this domain
	server.Routes = c.removeExistingRoutes(server.Routes, domain)

	// Add new routes
	server.Routes = append(server.Routes, routes...)

	// Configure TLS with custom certificate
	var tlsApp caddytls.TLS
	if tlsAppRaw, exists := config.AppsRaw["tls"]; exists {
		if err := json.Unmarshal(tlsAppRaw, &tlsApp); err != nil {
			return fmt.Errorf("failed to unmarshal TLS app: %w", err)
		}
	}

	// Add certificate
	if tlsApp.CertificatesRaw == nil {
		tlsApp.CertificatesRaw = make(caddy.ModuleMap)
	}

	tlsApp.CertificatesRaw["load_pem"] = caddyconfig.JSON([]caddytls.CertKeyPEMPair{
		{
			CertificatePEM: certificate,
			KeyPEM:         privateKey,
			Tags:           []string{certTag},
		},
	}, nil)

	// Update TLS connection policies
	c.updateTLSConnectionPolicies(server, domain, certTag)

	// Update apps in config
	httpAppRaw, err := json.Marshal(httpApp)
	if err != nil {
		return fmt.Errorf("failed to marshal HTTP app: %w", err)
	}
	config.AppsRaw["http"] = httpAppRaw

	tlsAppRaw, err := json.Marshal(tlsApp)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS app: %w", err)
	}
	config.AppsRaw["tls"] = tlsAppRaw

	// Update configuration
	_, err = c.makeRequest("POST", "/config/", config)
	if err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	return nil
}

// AddDomainWithACME adds a domain with explicit ACME policy configuration.
// This approach uses non-on-demand ACME policies for more controlled certificate management.
//
// Parameters:
//   - domain: The domain name to configure (e.g., "example.com")
//   - target: The target hostname or IP address
//   - targetPort: The target port number
//   - options: Configuration options for security headers, compression, and redirects
//
// Returns an error if the configuration fails.
func (c *Client) AddDomainWithACME(domain, target string, targetPort int, options DomainOptions) error {
	// Get current config
	resp, err := c.makeRequest("GET", "/config/", nil)
	if err != nil {
		return fmt.Errorf("failed to get current config: %w", err)
	}
	defer resp.Body.Close()

	var config caddy.Config
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	// Initialize HTTP app if not present
	if config.AppsRaw == nil {
		config.AppsRaw = make(map[string]json.RawMessage)
	}

	var httpApp caddyhttp.App
	if httpAppRaw, exists := config.AppsRaw["http"]; exists {
		if err := json.Unmarshal(httpAppRaw, &httpApp); err != nil {
			return fmt.Errorf("failed to unmarshal HTTP app: %w", err)
		}
	}

	if httpApp.Servers == nil {
		httpApp.Servers = make(map[string]*caddyhttp.Server)
	}

	if httpApp.Servers["srv0"] == nil {
		httpApp.Servers["srv0"] = &caddyhttp.Server{}
	}

	server := httpApp.Servers["srv0"]

	// Create route handlers
	var handlers []json.RawMessage

	// Add security headers if enabled
	if options.EnableSecurityHeaders {
		headersHandler := headers.Handler{
			Response: &headers.RespHeaderOps{
				HeaderOps: &headers.HeaderOps{
					Set: c.getSecurityHeaders(options.EnableHSTS, options.FrameOptions),
				},
			},
		}
		handlerRaw := caddyconfig.JSONModuleObject(headersHandler, "handler", "headers", nil)
		handlers = append(handlers, handlerRaw)
	}

	// Add compression if enabled
	if options.EnableCompression {
		encodeHandler := encode.Encode{
			EncodingsRaw: map[string]json.RawMessage{
				"gzip": json.RawMessage(`{}`),
				"zstd": json.RawMessage(`{}`),
			},
		}
		handlerRaw := caddyconfig.JSONModuleObject(encodeHandler, "handler", "encode", nil)
		handlers = append(handlers, handlerRaw)
	}

	// Add reverse proxy handler
	upstream := reverseproxy.Upstream{
		Dial: fmt.Sprintf("%s:%d", target, targetPort),
	}
	rpHandler := reverseproxy.Handler{
		Upstreams: reverseproxy.UpstreamPool{&upstream},
	}
	handlerRaw := caddyconfig.JSONModuleObject(rpHandler, "handler", "reverse_proxy", nil)
	handlers = append(handlers, handlerRaw)

	// Create routes
	var routes caddyhttp.RouteList

	// Handle redirects if specified
	if options.RedirectMode != "" {
		redirectRoute := c.createRedirectRoute(domain, options.RedirectMode)
		if redirectRoute != nil {
			routes = append(routes, *redirectRoute)
		}
	}

	// Create main route
	mainRoute := caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{
			{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{domain}, nil),
			},
		},
		HandlersRaw: handlers,
		Terminal:    true,
	}
	routes = append(routes, mainRoute)

	// Remove existing routes for this domain
	server.Routes = c.removeExistingRoutes(server.Routes, domain)

	// Add new routes
	server.Routes = append(server.Routes, routes...)

	// Configure ACME TLS automation
	var tlsApp caddytls.TLS
	if tlsAppRaw, exists := config.AppsRaw["tls"]; exists {
		if err := json.Unmarshal(tlsAppRaw, &tlsApp); err != nil {
			return fmt.Errorf("failed to unmarshal TLS app: %w", err)
		}
	}

	if tlsApp.Automation == nil {
		tlsApp.Automation = &caddytls.AutomationConfig{}
	}

	if tlsApp.Automation.Policies == nil {
		tlsApp.Automation.Policies = []*caddytls.AutomationPolicy{}
	}

	// Find existing ACME policy (non-on-demand)
	var acmePolicy *caddytls.AutomationPolicy
	for _, policy := range tlsApp.Automation.Policies {
		if !policy.OnDemand {
			acmePolicy = policy
			break
		}
	}

	if acmePolicy == nil {
		acmePolicy = &caddytls.AutomationPolicy{
			SubjectsRaw: []string{},
			IssuersRaw: []json.RawMessage{
				caddyconfig.JSONModuleObject(caddytls.ACMEIssuer{}, "module", "acme", nil),
			},
		}
		tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, acmePolicy)
	}

	// Add domain to ACME subjects
	if !c.containsString(acmePolicy.SubjectsRaw, domain) {
		acmePolicy.SubjectsRaw = append(acmePolicy.SubjectsRaw, domain)
	}

	// Update apps in config
	httpAppRaw, err := json.Marshal(httpApp)
	if err != nil {
		return fmt.Errorf("failed to marshal HTTP app: %w", err)
	}
	config.AppsRaw["http"] = httpAppRaw

	tlsAppRaw, err := json.Marshal(tlsApp)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS app: %w", err)
	}
	config.AppsRaw["tls"] = tlsAppRaw

	// Update configuration
	_, err = c.makeRequest("POST", "/config/", config)
	if err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	return nil
}

// DeleteDomain removes a domain configuration from Caddy.
// It removes all routes, TLS policies, and automation rules associated with the domain.
//
// Parameters:
//   - domain: The domain name to remove (e.g., "example.com")
//
// Returns an error if the deletion fails.
func (c *Client) DeleteDomain(domain string) error {
	// Get current config
	resp, err := c.makeRequest("GET", "/config/", nil)
	if err != nil {
		return fmt.Errorf("failed to get current config: %w", err)
	}
	defer resp.Body.Close()

	var config caddy.Config
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	// Remove domain from HTTP routes
	if httpAppRaw, exists := config.AppsRaw["http"]; exists {
		var httpApp caddyhttp.App
		if err := json.Unmarshal(httpAppRaw, &httpApp); err != nil {
			return fmt.Errorf("failed to unmarshal HTTP app: %w", err)
		}

		if server := httpApp.Servers["srv0"]; server != nil {
			server.Routes = c.removeExistingRoutes(server.Routes, domain)

			// Remove TLS connection policies for this domain
			if server.TLSConnPolicies != nil {
				var updatedPolicies []*caddytls.ConnectionPolicy
				for _, policy := range server.TLSConnPolicies {
					keep := true
					if policy.MatchersRaw != nil {
						for _, matcherRaw := range policy.MatchersRaw {
							var matcher map[string]interface{}
							if err := json.Unmarshal(matcherRaw, &matcher); err == nil {
								if sni, ok := matcher["sni"].([]interface{}); ok {
									for _, s := range sni {
										if s == domain {
											keep = false
											break
										}
									}
								}
							}
							if !keep {
								break
							}
						}
					}
					if keep {
						updatedPolicies = append(updatedPolicies, policy)
					}
				}
				server.TLSConnPolicies = updatedPolicies
			}
		}

		httpAppRaw, err := json.Marshal(httpApp)
		if err != nil {
			return fmt.Errorf("failed to marshal HTTP app: %w", err)
		}
		config.AppsRaw["http"] = httpAppRaw
	}

	// Remove domain from TLS automation subjects
	if tlsAppRaw, exists := config.AppsRaw["tls"]; exists {
		var tlsApp caddytls.TLS
		if err := json.Unmarshal(tlsAppRaw, &tlsApp); err != nil {
			return fmt.Errorf("failed to unmarshal TLS app: %w", err)
		}

		if tlsApp.Automation != nil && tlsApp.Automation.Policies != nil {
			for _, policy := range tlsApp.Automation.Policies {
				policy.SubjectsRaw = c.removeString(policy.SubjectsRaw, domain)
			}
		}

		tlsAppRaw, err := json.Marshal(tlsApp)
		if err != nil {
			return fmt.Errorf("failed to marshal TLS app: %w", err)
		}
		config.AppsRaw["tls"] = tlsAppRaw
	}

	// Update configuration
	_, err = c.makeRequest("POST", "/config/", config)
	if err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	return nil
}
