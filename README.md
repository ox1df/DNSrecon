# DNS Recon Tool

## Overview

The **zero two** is DNS Recon Tool  that is a comprehensive script for gathering DNS information and subdomain enumeration using various open-source tools. It automates the reconnaissance process and includes an optional VirusTotal domain check.

## Features

- Subdomain enumeration using `amass`, `subfinder`, and `assetfinder`
- Brute-force subdomain discovery using `dnsrecon`
- DNS record lookup with `dig`
- Zone transfer testing
- VirusTotal API integration for domain reputation checks
- Output results stored in a user-defined directory

## Requirements

Ensure you have the following tools installed:

- `amass`
- `subfinder`
- `assetfinder`
- `dnsrecon`
- `dig`
- Python 3
- `requests` library (install using `pip install requests`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/DNSrecon.git
   cd Zerotwo
   ```
2. Install dependencies:
   ```bash
   sudo apt install amass subfinder assetfinder dnsrecon dig
   pip install requests
   ```

## Usage

1. Run the script:
   ```bash
   python3 Zerotwo.py
   ```
2. Enter the target domain.
3. Provide an output directory (or use the default `./dns_recon`).
4. The script will execute various DNS reconnaissance tasks and save the results in the specified directory.

## VirusTotal Integration

- The first time you run the script, you will be prompted to enter your VirusTotal API key.
- The key will be saved in `virustotal_api_key.txt` for future use.

## Output

Results are stored in the specified output directory with the following files:

- `amass.txt` - Amass subdomain enumeration results
- `subfinder.txt` - Subfinder results
- `assetfinder.txt` - Assetfinder results
- `dnsrecon.txt` - DNS brute-force results
- `dig.txt` - DNS record lookup
- `zone_transfer.txt` - Zone transfer test results
- `virustotal.txt` - VirusTotal domain reputation results

## Disclaimer

This tool is for educational and authorized security testing purposes only. Unauthorized use is illegal and may result in severe penalties.

## Author

Developed by **0xffsec**.

