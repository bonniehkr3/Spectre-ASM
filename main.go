package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"spectre-asm/recon"
	"strings"
)

func main() {
	domain := flag.String("domain", "", "The target domain to scan (e.g., example.com)")
	flag.Parse()

	if *domain == "" {
		log.Fatal("Please provide a domain using -domain <example.com>")
	}

	fmt.Printf("[*] Starting Attack Surface Management scan for: %s\n", *domain)
	fmt.Println("--------------------------------------------------")

	// 1. Get Subdomains
	fmt.Printf("[*] Querying crt.sh for subdomains...\n")
	results, err := recon.GetSubdomains(*domain)
	if err != nil {
		log.Fatalf("Error during recon: %v", err)
	}

	// Filter out wildcards and emails
	var cleanSubs []string
	for _, r := range results {
		if !strings.Contains(r.Subdomain, "*") && !strings.Contains(r.Subdomain, "@") {
			cleanSubs = append(cleanSubs, r.Subdomain)
		}
	}
	fmt.Printf("[+] Found %d unique subdomains!\n", len(cleanSubs))
	fmt.Println("--------------------------------------------------")

	// 2. Check if they are live
	fmt.Printf("[*] Checking for live web servers...\n")
	liveHosts := recon.CheckLive(cleanSubs)
	fmt.Printf("[+] Found %d live websites!\n", len(liveHosts))
	fmt.Println("--------------------------------------------------")

	// 3. Check for Bugs and build the report
	fmt.Printf("[*] Scanning for vulnerabilities and building report...\n")

	var finalReport []recon.VulnResult
	for _, host := range liveHosts {
		vulnReport := recon.CheckVulns(host.URL)
		if vulnReport.IsAlive {
			finalReport = append(finalReport, vulnReport)
		}
	}

	// 4. Save to JSON file
	fileName := fmt.Sprintf("report_%s.json", strings.ReplaceAll(*domain, ".", "_"))
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("Failed to create report file: %v", err)
	}
	defer file.Close()

	jsonData, err := json.MarshalIndent(finalReport, "", "  ")
	if err != nil {
		log.Fatalf("Failed to generate JSON: %v", err)
	}

	file.Write(jsonData)

	fmt.Println("--------------------------------------------------")
	fmt.Printf("✅ Scan complete! Report saved to %s\n", fileName)
}
