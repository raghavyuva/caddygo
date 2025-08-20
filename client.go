package caddygo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NewClient creates a new Caddy API client.
// If baseURL is empty, it defaults to "http://localhost:2019".
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:2019"
	}

	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// makeRequest makes an HTTP request to the Caddy API.
// It handles JSON marshaling and error checking for API requests.
//
// Parameters:
//   - method: HTTP method (e.g., "GET", "POST")
//   - endpoint: API endpoint path (e.g., "/config/")
//   - data: Optional data to send in the request body
//
// Returns the HTTP response and any error that occurred during the request.
//
// Returns an error if the request fails to be created or if the API returns a non-200 status code.
func (c *Client) makeRequest(method, endpoint string, data interface{}) (*http.Response, error) {
	url := c.BaseURL + endpoint

	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return resp, nil
}
