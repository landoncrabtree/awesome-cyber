# awesome-cyber
A curated list of awesome cybersecurity tools for both red, blue, and purple team operations.

## General

### Operating Systems
OS | Description
---- | ----
[FlareVM](https://github.com/mandiant/flare-vm) | Windows distribution for malware analysis and incident response.
[Kali](https://www.kali.org/) | Open-source, Debian-based Linux distribution geared towards various information security tasks, such as Penetration Testing.
[Parrot](https://www.parrotsec.org/)  | Parrot Security (ParrotOS, Parrot) is a Free and Open source GNU/Linux distribution based on Debian Stable designed for security experts, developers and privacy aware people.
[REMnux](https://remnux.org/) | Linux toolkit for reverse engineering malware.

### Other awesome-Collections
This repository is just a brief (and generalized) list of resources and tools for both sides of cyber: blue and red team operations. As such, this is not meant to be in-depth resources. If you are looking for more specific information and/or tools, this contains a list of resource collections.
Repository | Description
---- | ----
[awesome-reversing](https://github.com/tylerha97/awesome-reversing)  |  A curated list of awesome reversing resources.
[awesome-hacking](https://github.com/carpedm20/awesome-hacking) | A list of hacking resources and tools: RE, web, forensics, etc.
[awesome-osint](https://github.com/jivoi/awesome-osint) | A curated list of amazingly awesome OSINT.
[awesome-pentest](https://github.com/enaqx/awesome-pentest) | A collection of awesome penetration testing resources, tools and other shiny things.
[awesome-social-engineering](https://github.com/v2-dev/awesome-social-engineering)  | A curated list of awesome social engineering resources. 
[awesome-asset-discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery)  | List of Awesome Asset Discovery Resources.
[awesome-incident-response](https://github.com/meirwah/awesome-incident-response) | A curated list of tools for incident response.
[awesome-red-teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)  | List of Awesome Red Teaming Resources.
[awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis)  | A curated list of awesome malware analysis tools and resources.

## Red Team

### Defense Evasion
Repository | Description
---- | ----
[Amsi-Bypass-PowerShell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)  | AMSI bypasses (Most are patched, but can be obfuscated to bypass)
[AMSITrigger](https://github.com/RythmStick/AMSITrigger) | Finds which string(s) trigger AMSI.
[Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)  | Used to bypass PowerShell security (logging, AMSI, etc).
[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation>)  | PowerShell module for obfuscating PowerShell scripts to bypass AV/EDR solutions.
[UPX](https://upx.github.io/) | PE packer.

### OSINT
Repository | Description
---- | ----
[crt.sh](https://crt.sh)  | Find certificates based on a domain name. Can be used to find subdomains.
[DorkSearch](https://dorksearch.com/) | Premade Google dork queries.
[ExifTool](https://exiftool.org)  | Read (and modify) metadata of files.
[Hunter](https://hunter.io)  | Find company email format and list of employee email addresses.
[Recon-NG](https://github.com/lanmaster53/recon-ng) | Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.
[ScrapeIn](https://github.com/landoncrabtree/ScrapeIn)  | Scrapes LinkedIn to create a list of employee email addresses (for use in Initial Access).
[SecurityTrails](https://securitytrails.com)  | Extensive DNS information.
[Shodan](https://shodan.io) | Scans for all digital assets.
[SpiderFoot](https://spiderfoot.net)  | Automatic OSINT analysis.
[TheHarvester](https://github.com/laramies/theHarvester)  | Collects names, emails, IPs, and subdomains of a target.

### Reconaissance
Repository | Description
---- | ----
[altdns](https://github.com/infosec-au/altdns)  | Subdomain enumeration using mutated wordlists.
[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) | Enumerate AWS S3 buckets to find interesting files.
[burpsuite](https://portswigger.net/burp) | An advanced web application testing suite that can be used to get info on how webpages work.
[CloudBrute](https://github.com/0xsha/CloudBrute) | Enumerates "the cloud" (Google, AWS, DigitalOcean, etc) to find infrastructure, files, and apps for a given target.
[dirb](https://github.com/v0re/dirb)  | Web application directory / file fuzzer to find other pages.
[DNSDumpster](https://dnsdumpster.com/) | Online tool for DNS information of a domain.
[EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)  | Screenshots webpages. Supports multi-domain lists and Nmap output.
[feroxbuster](https://github.com/epi052/feroxbuster)  | Like dirb, but written in Rust.
[gobuster](https://github.com/OJ/gobuster)  | Like dirb, but written in Go. Also supports DNS busting (such as subdomains).
[GoWitness](https://github.com/sensepost/gowitness) | Like EyeWitness, but in Go.
[Masscan](https://github.com/robertdavidgraham/masscan) | Like nmap, but faster (thus, not stealthy.)
[Nikto](https://github.com/sullo/nikto) | Web server scanner to perform security checks on a web server.
[Nmap](https://nmap.org/) | Find running services on a network.
[nosqlmap](https://github.com/codingo/NoSQLMap) | Like sqlmap, but for NoSQL.
[Raccoon](https://github.com/evyatarmeged/Raccoon)  | All-in-one Reconaissance. Port/service scans, dirbusting, and web application retrieval.
[Recon-NG](https://github.com/lanmaster53/recon-ng) | Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.
[Rustscan](https://github.com/RustScan/RustScan)  | A rust network scanner that is faster than Nmap, and sends open ports to Nmap for service/version detection.
[sqlmap](https://github.com/sqlmapproject/sqlmap) | Performs automated SQL injection tests on GET and POST requests.
[subfinder](https://github.com/projectdiscovery/subfinder)  | Passive subdomain discovery tool.
[wpscan](https://github.com/wpscanteam/wpscan)  | Automatic WordPress scanner to identify information about a WordPress site and possible vulnerabilities.

### Social Engineering
Repository | Description
---- | ----
[GoPhish](https://github.com/gophish/gophish>) | Phishing campaign framework to compromise user credentials.
[Social Engineering Toolkit](https://github.com/trustedsec/social-engineer-toolkit)  | Social engineering framework. 
[SpoofCheck](https://github.com/BishopFox/spoofcheck) | Checks if a domain can be spoofed.

### Leaked Credentials
Repository | Description
---- | ----
[Dehashed](https://dehashed.com)  | Leaked credential search engine to find passwords based on username, email, etc.
[LeakCheck](https://leakcheck.com)  | Leaked credential search engine to find passwords based on username, email, domain, etc.
[Snusbase](https://snusbase.com)  | Leaked credential search engine to find passwords based on username, email, etc.

### Initial Access
Repository | Description
---- | ----
[Easysploit](https://github.com/KALILINUXTRICKSYT/easysploit) | Automatic Metasploit payload generator and shell listener.
[GoPhish](https://github.com/gophish/gophish>) | Phishing campaign framework to compromise user credentials.
[Medusa](https://github.com/jmk-foofus/medusa)  | Bruteforcer with multiple protocol support.
[Metasploit](https://github.com/rapid7/metasploit-framework)  | Exploit framework that can be used for intial access and/or post-exploitation.
[Searchsploit](https://gitlab.com/exploit-database/exploitdb) | Search ExploitDB for exploits. Useful if you identify a service version.
[THC-Hydra](https://github.com/vanhauser-thc/thc-hydra) | Bruteforcer with multiple protocol support.
[TREVORspray](https://github.com/blacklanternsecurity/TREVORspray) | Advanced password spraying tool for Active Directory environments.

### C2 Frameworks
C2 frameworks can be considered both initial access and post-exploitation, as they generate payloads to be used in phishing campaigns (initial access) and will provide access to the host machine when ran (post exploitation).
Repository | Description
---- | ----
[Cobalt Strike](https://www.cobaltstrike.com/)  | Most robust and advanced C2 framework (also paid).
[Pupy](https://github.com/n1nj4sec/pupy)  | Python and C C2 framework.
[Sliver](https://github.com/BishopFox/sliver) | Go C2 framework.
[Villain](https://github.com/t3l3machus/Villain)  | Python and Powershell C2 framework.

### Post Exploitation
Repository | Description
---- | ----
[BeRoot](https://github.com/AlessandroZ/BeRoot) | Automated Windows, Linux, and Mac privilege escalation path discovery tool.
[BloodHound](https://github.com/BloodHoundAD/BloodHound)  | Active Directory visualizer, useful for finding misconfigurations and/or shortest path to Domain Admin.
[GTFOBins](https://gtfobins.github.io/) | Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
[Impacket](https://github.com/SecureAuthCorp/impacket)  | A collection of Python scripts useful for Windows targets: psexec, smbexec, kerberoasting, ticket attacks, etc.
[Invoke-PrivescCheck](https://github.com/itm4n/PrivescCheck)  | Automated Windows privilege escalation path discovery tool.
[LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) | Microsoft-signed binaries to perform APT or red-team functions (ie: dumping process memory).
[Metasploit](https://github.com/rapid7/metasploit-framework)  | Exploit framework that can be used for intial access and/or post-exploitation.
[Mimikatz](https://github.com/ParrotSec/mimikatz) | Mimikatz is both an exploit on Microsoft Windows that extracts passwords stored in memory and software that performs that exploit.
[PEASS-ng](https://github.com/carlospolop/PEASS-ng) | Automated Windows, Linux, and Mac privilege escalation path discovery tool.
[PowerHub](https://github.com/AdrianVollmer/PowerHub) | Post-exploitation module for bypassing endpoint protection and running arbitrary files.
[PowerSploit](https://github.com/AdrianVollmer/PowerSploit) | A PowerShell post-exploitation framework with many modules: exfiltration, privelege escalation, etc.
[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) | Automated Windows privilege escalation path discovery tool.
[SharpHound](https://github.com/BloodHoundAD/SharpHound)  | Data ingestor for BloodHound.
[smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) | Allows connection to the SMB protocol.
[smbmap](https://github.com/ShawnDEvans/smbmap) | Enumerates SMB shares.

### Exfiltration

### Credential Dumping

## Blue Team (WIP)

### Deobfuscation
Repository | Description
---- | ----
[cfxc-deobf](https://github.com/wildcardc/cfxc-deobf) | ConfuserEx unpacker.
[de4dot-cex](https://github.com/ViRb3/de4dot-cex) | ConfuserEx unpacker.
[de4dot](https://github.com/de4dot/de4dot)  | .NET deobfuscator and unpacker.
[NoFuserEx](https://github.com/undebel/NoFuserEx) | ConfuserEx unpacker.
[Packer-specific Unpackers](https://github.com/NotPrab/.NET-Deobfuscator/blob/master/README.md) | List of unpackers for specific packers.
[PSDecode](https://github.com/R3MRUM/PSDecode)  | PowerShell deobfuscator. 
[UnconfuserExTools](https://github.com/landoncrabtree/UnconfuserExTools)  | ConfuserEx deobfuscation toolkit (old).
[XPEViewer](https://github.com/horsicq/XPEViewer) | PE file viewer (headers, libraries, strings, etc).

### Reverse Engineering
Repository | Description
---- | ----
[cutter](https://github.com/rizinorg/cutter)  | Disassembler and decompiler for multiple executable formats, based on Rizin.
[Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | Detect file type and packer used.
[dnSpy](https://github.com/dnSpy/dnSpy) | .NET debugger and editor.
[gdb](https://www.sourceware.org/gdb/)  | CLI debugger.
[GEF](https://github.com/hugsy/gef) | GDB addon with advanced features -- GDB Enhanced Features.
[ghidra](https://github.com/NationalSecurityAgency/ghidra)  | Disassembler and decompiler for multiple executable formats.
[hexedit](https://github.com/pixel/hexedit) | View file hexadecimal.
[IDA](https://www.hex-rays.com/products/ida/index.shtml)  | Disassembler and decompiler for multiple executable formats.
[rizin](https://github.com/rizinorg/rizin)  | CLI disassembler.

### Malware Analysis
Repository | Description
---- | ----
[Cuckoo](https://cuckoosandbox.org/)  | Automated dynamic malware analysis.
[Wireshark](https://www.wireshark.org/download.html)  | View incoming and outgoing network connections.

