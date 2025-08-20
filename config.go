package caddygo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Reload forces a reload of the Caddy configuration.
// This method fetches the current configuration and sends it back to Caddy
// with cache invalidation headers to ensure the configuration is reloaded.
//
// Returns an error if the reload fails.
func (c *Client) Reload() error {
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

	// Reload with must-revalidate header
	req, err := http.NewRequest("POST", c.BaseURL+"/load", nil)
	if err != nil {
		return fmt.Errorf("failed to create reload request: %w", err)
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	req.Body = io.NopCloser(bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "must-revalidate")

	resp, err = c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reload failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// getSecurityHeaders returns a map of security headers based on the provided configuration.
// It includes X-Content-Type-Options, X-Frame-Options, and Referrer-Policy headers.
// If enableHSTS is true, it also includes Strict-Transport-Security.
//
// Parameters:
//   - enableHSTS: Whether to enable HTTP Strict Transport Security
//   - frameOptions: The value for the X-Frame-Options header
//
// Returns a map of security headers.
func (c *Client) getSecurityHeaders(enableHSTS bool, frameOptions string) map[string][]string {
	if frameOptions == "" {
		frameOptions = "DENY"
	}

	headers := map[string][]string{
		"X-Content-Type-Options": {"nosniff"},
		"X-Frame-Options":        {frameOptions},
		"Referrer-Policy":        {"strict-origin-when-cross-origin"},
	}

	if enableHSTS {
		headers["Strict-Transport-Security"] = []string{"max-age=31536000; includeSubDomains"}
	}

	return headers
}

// createRedirectRoute creates a redirect route for the specified domain and redirect mode.
// It handles both www_to_domain and domain_to_www redirects.
//
// Parameters:
//   - domain: The domain name to redirect from
//   - redirectMode: The redirect mode: "www_to_domain" or "domain_to_www"
//
// Returns a pointer to a caddyhttp.Route that handles the redirect.
//
// Returns nil if the redirect mode is invalid.
func (c *Client) createRedirectRoute(domain, redirectMode string) *caddyhttp.Route {
	baseDomain := strings.TrimPrefix(domain, "www.")
	var sourceDomain, targetDomain string

	if redirectMode == "www_to_domain" {
		sourceDomain = "www." + baseDomain
		targetDomain = baseDomain
	} else if redirectMode == "domain_to_www" {
		sourceDomain = baseDomain
		targetDomain = "www." + baseDomain
	} else {
		return nil
	}

	redirectHandler := caddyhttp.StaticResponse{
		StatusCode: caddyhttp.WeakString("308"),
		Headers: http.Header{
			"Location": []string{fmt.Sprintf("https://%s{http.request.uri}", targetDomain)},
		},
	}

	return &caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{
			{
				"host": caddyconfig.JSON(caddyhttp.MatchHost{sourceDomain}, nil),
			},
		},
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(redirectHandler, "handler", "static_response", nil),
		},
	}
}

// removeExistingRoutes filters out routes that contain the specified domain.
// It checks each route's MatcherSetsRaw for host matches and removes routes
// that match the domain.
//
// Parameters:
//   - routes: The list of routes to filter
//   - domain: The domain name to remove
//
// Returns a new list of routes without the specified domain.
func (c *Client) removeExistingRoutes(routes caddyhttp.RouteList, domain string) caddyhttp.RouteList {
	var filtered caddyhttp.RouteList
	for _, route := range routes {
		shouldKeep := true
		for _, matcherSet := range route.MatcherSetsRaw {
			if hostRaw, exists := matcherSet["host"]; exists {
				var hosts caddyhttp.MatchHost
				if err := json.Unmarshal(hostRaw, &hosts); err == nil {
					for _, host := range hosts {
						if host == domain {
							shouldKeep = false
							break
						}
					}
				}
			}
			if !shouldKeep {
				break
			}
		}
		if shouldKeep {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

// containsString checks if a slice contains a specific string.
//
// Parameters:
//   - slice: The slice to search
//   - item: The string to find
//
// Returns true if the string is found in the slice, false otherwise.
func (c *Client) containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// removeString removes a specific string from a slice.
//
// Parameters:
//   - slice: The slice to modify
//   - item: The string to remove
//
// Returns a new slice with the specified string removed.
func (c *Client) removeString(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}
