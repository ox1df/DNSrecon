import os
import subprocess
import requests
import json

print(r"""
  ______        ____  _
 |___  /       |___ \| |
    / / ___ _ __ __) | |___      _____
   / / / _ \ '__|__ <| __\ \ /\ / / _ \
  / /_|  __/ |  ___) | |_ \ V  V / (_) |
 /_____\___|_| |____/ \__| \_/\_/ \___/

       made by 0xffsec

""")

def check_tool(tool):
    """Check if a tool is installed"""
    return subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def install_tools():
    """Prompt user to install missing tools"""
    required_tools = ["amass", "subfinder", "assetfinder", "dnsrecon", "dig"]
    missing = [tool for tool in required_tools if not check_tool(tool)]

    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        choice = input("Do you want to install them? (y/n): ").strip().lower()
        if choice == "y":
            os.system(f"sudo apt install {' '.join(missing)}")
        else:
            print("[!] Some functionalities may not work!")

def get_output_dir():
    """Ask user where to save the output"""
    directory = input("Enter output directory (default: ./dns_recon): ").strip()
    if not directory:
        directory = "dns_recon"
    os.makedirs(directory, exist_ok=True)
    return directory

def run_command(command, output_file):
    """Run a shell command and save output"""
    with open(output_file, "w") as f:
        subprocess.run(command, shell=True, stdout=f, stderr=subprocess.DEVNULL)

def get_virustotal_api_key():
    """Ask for VirusTotal API key on first run and store it"""
    key_file = "virustotal_api_key.txt"
    if not os.path.exists(key_file):
        api_key = input("Enter your VirusTotal API key: ").strip()
        with open(key_file, "w") as f:
            f.write(api_key)
    else:
        with open(key_file, "r") as f:
            api_key = f.read().strip()
    return api_key

def virustotal_check(api_key, domain):
    """Check subdomains against VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return json.dumps(data, indent=4)
    else:
        return "Error checking VirusTotal"

def dns_recon():
    install_tools()

    api_key = get_virustotal_api_key()
    domain = input("Enter target domain: ").strip()
    wordlist = input("Enter path to wordlist (or press enter to use default): ").strip()
    if not wordlist:
        wordlist = "/usr/share/wordlists/dnsmap.txt"
    output_dir = get_output_dir()

    print("[+] Running DNS Recon...")
    run_command(f"amass enum -d {domain}", f"{output_dir}/amass.txt")
    run_command(f"subfinder -d {domain}", f"{output_dir}/subfinder.txt")
    run_command(f"assetfinder --subs-only {domain}", f"{output_dir}/assetfinder.txt")
    run_command(f"dnsrecon -d {domain} -t brt -D {wordlist}", f"{output_dir}/dnsrecon.txt")
    run_command(f"dig {domain} ANY +noall +answer", f"{output_dir}/dig.txt")

    print("[+] Checking for zone transfer...")
    with open(f"{output_dir}/nameservers.txt", "w") as ns_file:
        subprocess.run(f"dig NS {domain} +short", shell=True, stdout=ns_file, stderr=subprocess.DEVNULL)
    with open(f"{output_dir}/nameservers.txt") as ns_file:
        for ns in ns_file:
            run_command(f"dig axfr @{ns.strip()} {domain}", f"{output_dir}/zone_transfer.txt")

    vt_result = virustotal_check(api_key, domain)
    with open(f"{output_dir}/virustotal.txt", "w") as vt_file:
        vt_file.write(vt_result)

    print(f"[+] Recon complete! Check results in {output_dir}")

dns_recon()
