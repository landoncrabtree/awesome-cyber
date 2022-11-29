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
* <https://github.com/lanmaster53/recon-ng> - Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.
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
* <https://github.com/lanmaster53/recon-ng> - Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.
* <https://nmap.org/> - Find running services on a network.
* <https://github.com/robertdavidgraham/masscan> - Like nmap, but faster (thus, not stealthy.)
* <https://github.com/RustScan/RustScan> - A rust network scanner that is faster than Nmap, and sends open ports to Nmap for service/version detection.
* <https://github.com/FortyNorthSecurity/EyeWitness> - Screenshots webpages. Supports multi-domain lists and Nmap output.
* <https://github.com/sullo/nikto> - Web server scanner to perform security checks on a web server.
* <https://github.com/sqlmapproject/sqlmap> - Performs automated SQL injection tests on GET and POST requests.
* <https://github.com/codingo/NoSQLMap> - Like sqlmap, but for NoSQL.
* <https://portswigger.net/burp> - An advanced web application testing suite that can be used to get info on how webpages work.
* <https://github.com/wpscanteam/wpscan> - Automatic WordPress scanner to identify information about a WordPress site and possible vulnerabilities.
* <https://github.com/v0re/dirb> - Web application directory / file fuzzer to find other pages.
* <https://github.com/OJ/gobuster> - Like dirb, but written in Go. Also supports DNS busting (such as subdomains).
* <https://github.com/epi052/feroxbuster> - Like dirb, but written in Rust.
* <https://github.com/evyatarmeged/Raccoon> All-in-one Reconaissance. Port/service scans, dirbusting, and web application retrieval.
* <https://github.com/infosec-au/altdns> - Subdomain enumeration using mutated wordlists.
* <https://github.com/jordanpotti/AWSBucketDump> - Enumerate AWS S3 buckets to find interesting files.

### Social Engineering
https://github.com/trustedsec/social-engineer-toolkit - Social engineering framework. 
* <https://github.com/gophish/gophish> - Phishing campaign framework to compromise user credentials.

### Leaked Credentials
* <https://dehashed.com> - Leaked credential search engine to find passwords based on username, email, etc.
* <https://leakcheck.com> - Leaked credential search engine to find passwords based on username, email, domain, etc.
* <https://snusbase.com> - Leaked credential search engine to find passwords based on username, email, etc.

### Initial Access
* <https://github.com/blacklanternsecurity/TREVORspray> - Advanced password spraying tool for Active Directory environments.
* <https://github.com/vanhauser-thc/thc-hydra> - Bruteforcer with multiple protocol support.

### Post Exploitation

### Exfiltration

### Credential Dumping

## Blue Team (WIP)

### Deobfuscation
* <https://github.com/de4dot/de4dot> - .NET deobfuscator and unpacker.
* <https://github.com/horsicq/XPEViewer> - PE file viewer (headers, libraries, strings, etc).
* <https://github.com/NotPrab/.NET-Deobfuscator/blob/master/README.md> - List of unpackers for specific packers.
* <https://github.com/wildcardc/cfxc-deobf> - ConfuserEx unpacker.
* <https://github.com/ViRb3/de4dot-cex> - ConfuserEx unpacker.
* <https://github.com/undebel/NoFuserEx> - ConfuserEx unpacker.
* <https://github.com/landoncrabtree/UnconfuserExTools> - ConfuserEx toolkit (old).
* <https://github.com/R3MRUM/PSDecode> - PowerShell deobfuscator. 

### Reverse Engineering
* <https://github.com/dnSpy/dnSpy> - .NET debugger and editor.
* <https://github.com/NationalSecurityAgency/ghidra> - Disassembler and decompiler for multiple executable formats.
* <https://github.com/rizinorg/cutter> - Disassembler and decompiler for multiple executable formats, based on Rizin.
* <https://github.com/rizinorg/rizin> - CLI disassembler.
* <https://www.sourceware.org/gdb/> - CLI debugger.
* <https://github.com/hugsy/gef> - GDB addon with advanced features -- GDB Enhanced Features.
