package recon

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// VulnResult holds the URL and a list of missing security headers
type VulnResult struct {
	URL     string
	IsAlive bool
	Bugs    []string
}

// CheckVulns checks for missing security headers
func CheckVulns(url string) VulnResult {
	result := VulnResult{
		URL:  url,
		Bugs: []string{},
	}

	// We ignore SSL errors again because we are hacking!
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return result // Site is dead, no bugs to report
	}
	defer resp.Body.Close()

	result.IsAlive = true

	// 1. Check for missing X-Frame-Options (Clickjacking vulnerability)
	if resp.Header.Get("X-Frame-Options") == "" {
		result.Bugs = append(result.Bugs, "Missing X-Frame-Options (Clickjacking Risk)")
	}

	// 2. Check for missing Strict-Transport-Security (HSTS)
	if resp.Header.Get("Strict-Transport-Security") == "" {
		result.Bugs = append(result.Bugs, "Missing HSTS (Insecure HTTPS)")
	}

	// 3. Check for missing Content-Security-Policy (XSS Risk)
	if resp.Header.Get("Content-Security-Policy") == "" {
		result.Bugs = append(result.Bugs, "Missing CSP (XSS Risk)")
	}

	// 4. Check if Server version is leaked (Information Disclosure)
	if resp.Header.Get("Server") != "" {
		serverSw := resp.Header.Get("Server")
		result.Bugs = append(result.Bugs, fmt.Sprintf("Leaks Server Software: %s", serverSw))
	}

	return result
}
