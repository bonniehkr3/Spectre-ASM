### 🛰️ Spectre-ASM

A fast, lightweight Attack Surface Management (ASM) tool written in Go. It queries Certificate Transparency logs to quickly enumerate subdomains for a target domain.

### 🚀 Features

Blazing Fast: Built with Go for high concurrency and speed.
Passive Recon: Uses crt.sh (Certificate Transparency) to find subdomains without touching the target's servers.
CLI First: Designed to be easily integrated into bash scripts or automation pipelines.

### ⚙️ Setup & Usage

1. Ensure you have Go installed.
2. Clone the repo.
3. Run the tool:
go run main.go -domain example.com

### 🎯 Next Steps / TODO

 . Add HTTP probing (check if subdomains are live).
 . Output results to JSON/CSV.
 . Add additional passive sources (Shodan, HackerTarget).

### ⚠️ Ethical Disclaimer
This tool is designed by Bonniehkr3 for authorized security testing and educational purposes only. Only scan domains you have permission to test.