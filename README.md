# Awesome Cyber
A curated list of awesome cybersecurity tools for both red, blue, and purple team operations.

## General

### Other awesome-Collections
If you are looking for more specific information and/or tools, this contains a list of resource collections.
Repository | Description
---- | ----
[awesome-reversing](https://github.com/tylerha97/awesome-reversing)  |  A curated list of awesome reversing resources.
[awesome-hacking](https://github.com/carpedm20/awesome-hacking) | A list of hacking resources and tools: RE, web, forensics, etc.
[awesome-osint](https://github.com/jivoi/awesome-osint) | A curated list of amazingly awesome OSINT.
[awesome-pentest](https://github.com/enaqx/awesome-pentest) | A collection of awesome penetration testing resources, tools and other shiny things.
[awesome-social-engineering](https://github.com/v2-dev/awesome-social-engineering)  | A curated list of awesome social engineering resources. 

## Red Team

### Obfuscation / AV Bypass
Repository | Description
---- | ----
[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation>)  | PowerShell module for obfuscating PowerShell scripts to bypass AV/EDR solutions.
[Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)  | Used to bypass PowerShell security (logging, AMSI, etc).
[AMSITrigger](https://github.com/RythmStick/AMSITrigger) | Finds which string(s) trigger AMSI.
[Amsi-Bypass-PowerShell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)  | AMSI bypasses (Most are patched, but can be obfuscated to bypass)
[UPX](https://upx.github.io/) | PE packer.

### OSINT
Repository | Description
---- | ----
[Recon-NG](https://github.com/lanmaster53/recon-ng) | Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.
[crt.sh](https://crt.sh)  | Find certificates based on a domain name. Can be used to find subdomains.
[SecurityTrails](https://securitytrails.com)  | Extensive DNS information.
[DorkSearch](https://dorksearch.com/) | Premade Google dork queries.
[Hunter](https://hunter.io)  | Find company email format and list of employee email addresses.
[Shodan](https://shodan.io) | Scans for all digital assets.
[ExifTool](https://exiftool.org)  | Read (and modify) metadata of files.
[SpiderFoot](https://spiderfoot.net)  | Automatic OSINT analysis.
[TheHarvester](https://github.com/laramies/theHarvester)  | Collects names, emails, IPs, and subdomains of a target.
[ScrapeIn](https://github.com/landoncrabtree/ScrapeIn)  | Scrapes LinkedIn to create a list of employee email addresses (for use in Initial Access).

### Reconaissance
Repository | Description
---- | ----
[Recon-NG](https://github.com/lanmaster53/recon-ng) | Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.
[Nmap](https://nmap.org/) | Find running services on a network.
[Masscan](https://github.com/robertdavidgraham/masscan) | Like nmap, but faster (thus, not stealthy.)
[Rustscan](https://github.com/RustScan/RustScan)  | A rust network scanner that is faster than Nmap, and sends open ports to Nmap for service/version detection.
[EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)  | Screenshots webpages. Supports multi-domain lists and Nmap output.
[GoWitness](https://github.com/sensepost/gowitness) | Like EyeWitness, but in Go.
[Nikto](https://github.com/sullo/nikto) | Web server scanner to perform security checks on a web server.
[sqlmap](https://github.com/sqlmapproject/sqlmap) | Performs automated SQL injection tests on GET and POST requests.
[nosqlmap](https://github.com/codingo/NoSQLMap) | Like sqlmap, but for NoSQL.
[burpsuite](https://portswigger.net/burp) | An advanced web application testing suite that can be used to get info on how webpages work.
[wpscan](https://github.com/wpscanteam/wpscan)  | Automatic WordPress scanner to identify information about a WordPress site and possible vulnerabilities.
[dirb](https://github.com/v0re/dirb)  | Web application directory / file fuzzer to find other pages.
[gobuster](https://github.com/OJ/gobuster)  | Like dirb, but written in Go. Also supports DNS busting (such as subdomains).
[feroxbuster](https://github.com/epi052/feroxbuster)  | Like dirb, but written in Rust.
[Raccoon](https://github.com/evyatarmeged/Raccoon)  | All-in-one Reconaissance. Port/service scans, dirbusting, and web application retrieval.
[altdns](https://github.com/infosec-au/altdns)  | Subdomain enumeration using mutated wordlists.
[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) | Enumerate AWS S3 buckets to find interesting files.

### Social Engineering
Repository | Description
---- | ----
[Social Engineering Toolkit](https://github.com/trustedsec/social-engineer-toolkit)  | Social engineering framework. 
[GoPhish](https://github.com/gophish/gophish>) | Phishing campaign framework to compromise user credentials.

### Leaked Credentials
Repository | Description
---- | ----
[Dehashed](https://dehashed.com)  | Leaked credential search engine to find passwords based on username, email, etc.
[LeakCheck](https://leakcheck.com)  | Leaked credential search engine to find passwords based on username, email, domain, etc.
[Snusbase](https://snusbase.com)  | Leaked credential search engine to find passwords based on username, email, etc.

### Initial Access
Repository | Description
---- | ----
[TREVORspray](https://github.com/blacklanternsecurity/TREVORspray) | Advanced password spraying tool for Active Directory environments.
[THC-Hydra](https://github.com/vanhauser-thc/thc-hydra) | Bruteforcer with multiple protocol support.

### Post Exploitation

### Exfiltration

### Credential Dumping

## Blue Team (WIP)

### Deobfuscation
Repository | Description
---- | ----
[de4dot](https://github.com/de4dot/de4dot)  | .NET deobfuscator and unpacker.
[XPEViewer](https://github.com/horsicq/XPEViewer) | PE file viewer (headers, libraries, strings, etc).
[Packer-specific Unpackers](https://github.com/NotPrab/.NET-Deobfuscator/blob/master/README.md) | List of unpackers for specific packers.
[cfxc-deobf](https://github.com/wildcardc/cfxc-deobf) | ConfuserEx unpacker.
[de4dot-cex](https://github.com/ViRb3/de4dot-cex) | ConfuserEx unpacker.
[NoFuserEx](https://github.com/undebel/NoFuserEx) | ConfuserEx unpacker.
[UnconfuserExTools](https://github.com/landoncrabtree/UnconfuserExTools)  | ConfuserEx deobfuscation toolkit (old).
[PSDecode](https://github.com/R3MRUM/PSDecode)  | PowerShell deobfuscator. 

### Reverse Engineering
Repository | Description
---- | ----
[dnSpy](https://github.com/dnSpy/dnSpy) | .NET debugger and editor.
[IDA](https://www.hex-rays.com/products/ida/index.shtml)  | Disassembler and decompiler for multiple executable formats.
[ghidra](https://github.com/NationalSecurityAgency/ghidra)  | Disassembler and decompiler for multiple executable formats.
[cutter](https://github.com/rizinorg/cutter)  | Disassembler and decompiler for multiple executable formats, based on Rizin.
[rizin](https://github.com/rizinorg/rizin)  | CLI disassembler.
[gdb](https://www.sourceware.org/gdb/)  | CLI debugger.
[GEF](https://github.com/hugsy/gef) | GDB addon with advanced features -- GDB Enhanced Features.
[hexedit](https://github.com/pixel/hexedit) | View file hexadecimal.

### Malware Analysis
Repository | Description
---- | ----
[Cuckoo](https://cuckoosandbox.org/)  | Automated dynamic malware analysis.
[Wireshark](https://www.wireshark.org/download.html)  | View incoming and outgoing network connections.

