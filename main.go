package main

import (
	"flag"
	"fmt"
	"log"
	"spectre-asm/recon"
	"strings"
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

	// Filter out wildcards (*) and emails (@) before probing
	var cleanSubs []string
	for _, r := range results {
		if !strings.Contains(r.Subdomain, "*") && !strings.Contains(r.Subdomain, "@") {
			cleanSubs = append(cleanSubs, r.Subdomain)
		}
	}
	fmt.Printf("[+] Found %d unique subdomains!\n", len(cleanSubs))
	fmt.Println("--------------------------------------------------")

	// 3. Check if they are live
	fmt.Printf("[*] Checking for live web servers (HTTP/HTTPS)...\n")
	liveHosts := recon.CheckLive(cleanSubs)

	fmt.Printf("[+] Found %d live websites!\n", len(liveHosts))
	fmt.Println("--------------------------------------------------")

	// 4. Check for Bugs! (The new part)
	fmt.Printf("[*] Scanning live websites for vulnerabilities...\n")
	for _, host := range liveHosts {
		vulnReport := recon.CheckVulns(host.URL)

		if vulnReport.IsAlive {
			if len(vulnReport.Bugs) > 0 {
				fmt.Printf("🚨 [BUGS FOUND] on %s:\n", vulnReport.URL)
				for _, bug := range vulnReport.Bugs {
					fmt.Printf("    [-] %s\n", bug)
				}
			} else {
				fmt.Printf("✅ [SECURE] %s (No obvious misconfigurations)\n", vulnReport.URL)
			}
		}
	}
	fmt.Println("--------------------------------------------------")
	fmt.Println("[*] Scan complete!")
}
