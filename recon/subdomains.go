package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Certificate Transparency log URL (crt.sh)
const crtShURL = "https://crt.sh/?q=%s&output=json"

// SubdomainResult holds the data we extract
type SubdomainResult struct {
	Subdomain string
	Source    string
}

// GetSubdomains queries crt.sh for subdomains
func GetSubdomains(domain string) ([]SubdomainResult, error) {
	url := fmt.Sprintf(crtShURL, domain)

	// 1. Create a custom HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 2. Pretend to be a normal web browser so crt.sh doesn't block us!
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")

	// 3. Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to crt.sh: %v", err)
	}
	defer resp.Body.Close()

	// If the server gives us an error (like 502 or 503), stop here
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse the JSON response
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	var results []SubdomainResult
	seen := make(map[string]bool) // To prevent duplicate subdomains

	for _, entry := range raw {
		name, ok := entry["name_value"].(string)
		if !ok {
			continue
		}

		// Split by newline because crt.sh sometimes groups multiple subdomains together
		for _, n := range strings.Split(name, "\n") {
			n = strings.TrimSpace(n)
			if n != "" && !seen[n] {
				seen[n] = true
				results = append(results, SubdomainResult{
					Subdomain: n,
					Source:    "crt.sh",
				})
			}
		}
	}

	return results, nil
}
