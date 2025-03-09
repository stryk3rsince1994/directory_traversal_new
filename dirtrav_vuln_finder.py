import os
import re
from pathlib import Path

# Define the output directory
output_dir = "/home/stryk3r/Desktop/tools/Directory_Trav_tool/findings_from_scan"
os.makedirs(output_dir, exist_ok=True)

# Define regex patterns for interesting findings
patterns = {
    "IP_Addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Email_Addresses": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "URLs": r"https?://[^\s]+",
    "Cookies": r"cookie\s*=\s*[^\s;]+",
    "Tokens": r"(?:access_token|refresh_token|api_key)\s*=\s*[^\s;]+",
    "Sensitive_Info": r"(?:password|secret|api_key|private_key)\s*=\s*[^\s]+",
    "JavaScript_Functions": r"function\s+\w+\s*\([^)]*\)\s*\{",
    "HTML_Forms": r"<form[^>]*>.*?</form>",
}

# Function to scan a file for interesting findings
def scan_file(file_path):
    findings = {category: [] for category in patterns.keys()}
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
            for category, pattern in patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings[category].extend(matches)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return findings

# Function to save findings to categorized files
def save_findings(findings, file_name):
    for category, matches in findings.items():
        if matches:
            category_file = os.path.join(output_dir, f"{category}.txt")
            with open(category_file, "a", encoding="utf-8") as f:
                f.write(f"Findings from {file_name}:\n")
                f.write("\n".join(matches))
                f.write("\n\n")

# Main function to handle input and scan files
def main():
    input_path = input("Enter the path to a .txt file or a directory to scan: ").strip()

    if os.path.isfile(input_path) and input_path.endswith(".txt"):
        print(f"Scanning file: {input_path}")
        findings = scan_file(input_path)
        save_findings(findings, os.path.basename(input_path))
    elif os.path.isdir(input_path):
        print(f"Scanning directory: {input_path}")
        for root, _, files in os.walk(input_path):
            for file in files:
                if file.endswith(".txt") or file.endswith(".html") or file.endswith(".js"):
                    file_path = os.path.join(root, file)
                    print(f"Scanning file: {file_path}")
                    findings = scan_file(file_path)
                    save_findings(findings, file)
    else:
        print("Invalid input. Please provide a valid .txt file or directory.")
        return

    print(f"Scan complete. Findings saved to {output_dir}")

if __name__ == "__main__":
    main()
