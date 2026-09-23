package main

import (
	"flag"
	"fmt"
	"log"
	"spectre-asm/recon"
)

func main() {
	// 1. Define a command line flag
	domain := flag.String("domain", "", "The target domain to scan (e.g., example.com)")
	flag.Parse()

	if *domain == "" {
		log.Fatal("Please provide a domain using -domain <example.com>")
	}

	fmt.Printf("[*] Starting Attack Surface Management scan for: %s\n", *domain)
	fmt.Println("--------------------------------------------------")

	// 2. Get Subdomains
	fmt.Printf("[*] Querying crt.sh for subdomains...\n")
	results, err := recon.GetSubdomains(*domain)
	if err != nil {
		log.Fatalf("Error during recon: %v", err)
	}

	fmt.Printf("[+] Found %d unique subdomains!\n", len(results))
	fmt.Println("--------------------------------------------------")

	// 3. Check if they are live (The new part!)
	fmt.Printf("[*] Checking for live web servers (HTTP/HTTPS)...\n")
	liveHosts := recon.CheckLive(extractSubdomains(results))

	fmt.Printf("[+] Found %d live websites!\n", len(liveHosts))
	for _, host := range liveHosts {
		fmt.Printf("  -> [%d] %s\n", host.StatusCode, host.URL)
	}
}

// Helper function to convert []SubdomainResult to []string
func extractSubdomains(results []recon.SubdomainResult) []string {
	var subs []string
	for _, r := range results {
		subs = append(subs, r.Subdomain)
	}
	return subs
}
