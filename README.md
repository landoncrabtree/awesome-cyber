# Awesome Cyber
A curated list of tools useful within the field of cyber security, for both blue and red team operations. 

## Red Team

### Obfuscation / AV Bypass
* <https://github.com/danielbohannon/Invoke-Obfuscation> - PowerShell module for obfuscating PowerShell scripts to bypass AV/EDR solutions.
* <https://github.com/OmerYa/Invisi-Shell> - Used to bypass PowerShell security (logging, AMSI, etc).
* <https://github.com/RythmStick/AMSITrigger> - Finds which string(s) trigger AMSI.
* <https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell> - AMSI bypasses (Most are patched, but can be obfuscated to bypass)
* <https://upx.github.io/> - PE packer.

### OSINT
* <https://crt.sh> - Find certificates based on a domain name. Can be used to find subdomains.
* <https://securitytrails.com> - Extensive DNS information.
* <https://dorksearch.com/> - Premade Google dork queries.
* <https://hunter.io> - Find company email format and list of employee email addresses.
* <https://www.shodan.io> - Scans for all digital assets
* <https://exiftool.org/> - Read (and modify) metadata of files.
* <https://www.spiderfoot.net/> - Automatic OSINT analysis.
* <https://github.com/laramies/theHarvester> - Collects names, emails, IPs, and subdomains of a target.
* <https://github.com/landoncrabtree/ScrapeIn> - Scrapes LinkedIn to create a list of employee email addresses (for use in Initial Access).

### Reconaissance
* <https://nmap.org/> - Find running services on a network.
* <https://github.com/robertdavidgraham/masscan> - Like nmap, but faster (thus, not stealthy.)
* <https://github.com/RustScan/RustScan> - A rust network scanner that is faster than Nmap, and sends open ports to Nmap for service/version detection.
* <https://github.com/FortyNorthSecurity/EyeWitness> - Screenshots webpages. Supports multi-domain lists and Nmap output.
* <https://github.com/sullo/nikto> - Web server scanner to perform security checks on a web server.
* <https://github.com/sqlmapproject/sqlmap> - Performs automated SQL injection tests on GET and POST requests.
* <https://portswigger.net/burp> - An advanced web application testing suite that can be used to get info on how webpages work.
* <https://github.com/wpscanteam/wpscan> - Automatic WordPress scanner to identify information about a WordPress site and possible vulnerabilities.


### Leaked Credentials
* <https://dehashed.com> - Leaked credential search engine to find passwords based on username, email, etc.
* <https://leakcheck.com> - Leaked credential search engine to find passwords based on username, email, domain, etc.
* <https://snusbase.com> - Leaked credential search engine to find passwords based on username, email, etc.

### Initial Access
* <https://github.com/gophish/gophish> - Phishing campaign framework to compromise user credentials.
* <https://github.com/blacklanternsecurity/TREVORspray> - Advanced password spraying tool for Active Directory environments.


### Post Exploitation

### Exfiltration

### Credential Dumping

## Blue Team (Coming Soon)
