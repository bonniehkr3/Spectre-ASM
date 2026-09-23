package main

import (
    "flag"
    "fmt"
    "log"
    "spectre-asm/recon" // This imports the folder we just created!
)

func main() {
    // 1. Define a command line flag (like a real hacker tool!)
    domain := flag.String("domain", "", "The target domain to scan (e.g., example.com)")
    flag.Parse()

    // 2. Check if the user provided a domain
    if *domain == "" {
        log.Fatal("Please provide a domain using -domain <example.com>")
    }

    fmt.Printf("[*] Starting Attack Surface Management scan for: %s\n", *domain)
    fmt.Println("--------------------------------------------------")

    // 3. Call our recon function from the recon folder
    fmt.Printf("[*] Querying crt.sh for subdomains...\n")
    results, err := recon.GetSubdomains(*domain)
    if err != nil {
        log.Fatalf("Error during recon: %v", err)
    }

    // 4. Print the results
    fmt.Printf("[+] Found %d unique subdomains!\n", len(results))
    for _, result := range results {
        fmt.Printf("  -> %s\n", result.Subdomain)
    }
}