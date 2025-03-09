# directory_traversal_new
2025, new code to find directory traversal.. please read the readme.md file



chmod +x directorytravers_scanner.py dirtrav_vuln_finder.py

use first
$ python3 directorytravers_scanner.py

use second
$ python3 dirtrav_vuln_finder.py


than follow what the app ask for your input.

there is a payload you can use, the payload is "dotdotpwn.txt" 

the "target.txt" file already has domains in it if you want to test, but you can edit the file and put your own targest in the target text. it will ask the file you want to use to scan which is the target.txt file, or you can use an ip address or single domain name.

Need anything reach out.

FEEL FREE TO USE AND EDIT CODE JUST GIVE ME CREDIT PLEASE!



David Cantrell
Cantrell1980@gmail.com
AKA Stryk3r


Example Output:
Terminal:
Copy
  _    _           _   _      _____ _   _ _______ ______ _____  
 | |  | |   /\    | \ | |    |_   _| \ | |__   __|  ____|  __ \ 
 | |__| |  /  \   |  \| |______| | |  \| |  | |  | |__  | |__) |
 |  __  | / /\ \  | . ` |______| | | . ` |  | |  |  __| |  ___/ 
 | |  | |/ ____ \ | |\  |     _| |_| |\  |  | |  | |____| |     
 |_|  |_/_/    \_\|_| \_|    |_____|_| \_|  |_|  |______|_|     
Written by David Cantrell AKA Stryk3r
D33pS33k

Enter the path to the HTML/JavaScript file to scan: /path/to/file.html
Scanning file: /path/to/file.html
Vulnerabilities found:
XSS_Vulnerabilities: <script>alert('XSS')</script>
Hardcoded_Credentials: password = 'admin123'
Findings saved to findings_abc123xyz.txt
Do you want to run Kali Linux tools for additional analysis? (y/n): y
Running Kali Linux tools for additional analysis...
Findings File (findings_abc123xyz.txt):
Copy
Vulnerability Findings:
XSS_Vulnerabilities: <script>alert('XSS')</script>
Hardcoded_Credentials: password = 'admin123'
Notes:
Ensure you have the required Kali Linux tools installed (e.g., nikto).

Modify the regex patterns or add new ones to suit your specific needs.

The script is designed for HTML and JavaScript files but can be adapted for other file types.
