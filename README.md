# awesome-cyber
A curated list of awesome cybersecurity tools for both red, blue, and purple team operations.

## Contributions?
Contributions are welcome! The goal of this repository is to be an up-to-date source of tools for all facets of cybersecurity. The landscape changes constantly and so do the tools. It's hard keeping track of everything! If you want to add (or remove outdated) tools, feel free to create an issue or a PR. 

<a href = "https://github.com/Tanu-N-Prabhu/Python/graphs/contributors">
  <img src = "https://contrib.rocks/image?repo=landoncrabtree/awesome-cyber"/>
</a>

## Quick links
* [General](#general)
    * [Operating Systems](#operating-systems)
    * [Other awesome-Collections](#other-awesome-collections)
* [Red Team Tools](#red-team)
    * [Defense Evasion](#defense-evasion)
    * [OSINT](#osint)
    * [Reconaissance](#reconaissance)
    * [Social Engineering](#social-engineering)
    * [Leaked Credentials](#leaked-credentials)
    * [Web Exploitation](#web-exploitation)
    * [Wireless](#wireless)
    * [Initial Access](#initial-access)
    * [C2 Frameworks](#c2-frameworks)
    * [Post Exploitation](#post-exploitation)
    * [Exfiltration](#exfiltration)
    * [Credential Dumping](#credential-dumping)
* [Blue Team Tools](#blue-team)
    * [Forensics](#forensics)
    * [Deobfuscation](#deobfuscation)
    * [Reverse Engineering](#reverse-engineering)
    * [Malware Analysis](#malware-analysis)
    * [Hardening](#hardening)
* [CTF stuff](https://github.com/landoncrabtree/awesome-cyber/tree/main#ctf)

## General

### Operating Systems
OS | Description
---- | ----
[FlareVM](https://github.com/mandiant/flare-vm) | Windows distribution for malware analysis and incident response.
[Kali](https://www.kali.org/) | Open-source, Debian-based Linux distribution geared towards various information security tasks, such as Penetration Testing.
[Parrot](https://www.parrotsec.org/) | Parrot Security (ParrotOS, Parrot) is a Free and Open source GNU/Linux distribution based on Debian Stable designed for security experts, developers and privacy aware people.
[REMnux](https://remnux.org/) | Linux toolkit for reverse engineering malware.

### Other awesome-Collections
This repository is just a brief (and generalized) list of resources and tools for both sides of cyber: blue and red team operations. As such, this is not meant to be in-depth resources. If you are looking for more specific information and/or tools, this contains a list of resource collections.
Repository | Description
---- | ----
[awesome-reversing](https://github.com/tylerha97/awesome-reversing) |  A curated list of awesome reversing resources.
[awesome-hacking](https://github.com/carpedm20/awesome-hacking) | A list of hacking resources and tools: RE, web, forensics, etc.
[awesome-osint](https://github.com/jivoi/awesome-osint) | A curated list of amazingly awesome OSINT.
[awesome-pentest](https://github.com/enaqx/awesome-pentest) | A collection of awesome penetration testing resources, tools and other shiny things.
[awesome-social-engineering](https://github.com/v2-dev/awesome-social-engineering) | A curated list of awesome social engineering resources. 
[awesome-asset-discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery) | List of Awesome Asset Discovery Resources.
[awesome-incident-response](https://github.com/meirwah/awesome-incident-response) | A curated list of tools for incident response.
[awesome-red-teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming) | List of Awesome Red Teaming Resources.
[awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis) | A curated list of awesome malware analysis tools and resources.
[awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) | A list of plugins for IDA, Ghidra, GDB, OllyDBG, etc. 
[awesome-forensics](https://github.com/cugu/awesome-forensics) | A curated list of awesome forensic analysis tools and resources
[awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools) | Tools for PCAP files
[awesome-windows-post-exploitation](https://github.com/emilyanncr/Windows-Post-Exploitation) | Windows post-exploitation tools, resources, techniques and commands to use during post-exploitation phase of penetration test.

## Red Team

### Defense Evasion
Repository | Description
---- | ----
[Amsi-Bypass-PowerShell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) | AMSI bypasses (Most are patched, but can be obfuscated to bypass)
[AMSITrigger](https://github.com/RythmStick/AMSITrigger) | Finds which string(s) trigger AMSI.
[chameleon](https://github.com/klezVirus/chameleon) | PowerShell Script Obfuscator
[Invisi-Shell](https://github.com/OmerYa/Invisi-Shell) | Used to bypass PowerShell security (logging, AMSI, etc).
[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation>) | PowerShell module for obfuscating PowerShell scripts to bypass AV/EDR solutions.
[ISESteroids](https://powershell.one/isesteroids/quickstart/overview) | Powerful extension for the built-in ISE PowerShell editor (has obfuscation module)
[Invoke-Stealth](https://github.com/JoelGMSec/Invoke-Stealth) | Simple & Powerful PowerShell Script Obfuscator
[UPX](https://upx.github.io/) | PE packer.
[Unprotect](https://unprotect.it) | Contains malware evasion techniques along with PoC. 

### OSINT
Repository | Description
---- | ----
[Cloudmare](https://github.com/mrh0wl/Cloudmare) |  Cloudflare, Sucuri, Incapsula real IP tracker. 
[crt.sh](https://crt.sh) | Find certificates based on a domain name. Can be used to find subdomains.
[DorkSearch](https://dorksearch.com/) | Premade Google dork queries.
[ExifTool](https://exiftool.org) | Read (and modify) metadata of files.
[FaceCheck.ID](https://facecheck.id) | Reverse image lookup based on facial-recognition.
[Hunter](https://hunter.io) | Find company email format and list of employee email addresses.
[osintframework](https://osintframework.com/) | An online database of OSINT tools.
[PimEyes](https://pimeyes.com/) | Reverse image lookup based on facial-recognition.
[Recon-NG](https://github.com/lanmaster53/recon-ng) | Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.
[ScrapeIn](https://github.com/landoncrabtree/ScrapeIn) | Scrapes LinkedIn to create a list of employee email addresses (for use in Initial Access).
[SecurityTrails](https://securitytrails.com) | Extensive DNS information.
[Shodan](https://shodan.io) | Scans for all digital assets.
[SpiderFoot](https://spiderfoot.net) | Automatic OSINT analysis.
[TheHarvester](https://github.com/laramies/theHarvester) | Collects names, emails, IPs, and subdomains of a target.

### Reconaissance
Repository | Description
---- | ----
[altdns](https://github.com/infosec-au/altdns) | Subdomain enumeration using mutated wordlists.
[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) | Enumerate AWS S3 buckets to find interesting files.
[burpsuite](https://portswigger.net/burp) | An advanced web application testing suite that can be used to get info on how webpages work.
[CameRadar](https://github.com/Ullaakut/cameradar) |  Cameradar hacks its way into RTSP videosurveillance cameraa
[CloudBrute](https://github.com/0xsha/CloudBrute) | Enumerates "the cloud" (Google, AWS, DigitalOcean, etc) to find infrastructure, files, and apps for a given target.
[dirb](https://github.com/v0re/dirb) | Web application directory / file fuzzer to find other pages.
[DNSDumpster](https://dnsdumpster.com/) | Online tool for DNS information of a domain.
[EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) | Screenshots webpages. Supports multi-domain lists and Nmap output.
[feroxbuster](https://github.com/epi052/feroxbuster) | Like dirb, but written in Rust.
[gobuster](https://github.com/OJ/gobuster) | Like dirb, but written in Go. Also supports DNS busting (such as subdomains).
[GoWitness](https://github.com/sensepost/gowitness) | Like EyeWitness, but in Go.
[Masscan](https://github.com/robertdavidgraham/masscan) | Like nmap, but faster (thus, not stealthy.)
[Nikto](https://github.com/sullo/nikto) | Web server scanner to perform security checks on a web server.
[Nmap](https://nmap.org/) | Find running services on a network.
[Raccoon](https://github.com/evyatarmeged/Raccoon) | All-in-one Reconaissance. Port/service scans, dirbusting, and web application retrieval.
[Recon-NG](https://github.com/lanmaster53/recon-ng) | Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.
[Rustscan](https://github.com/RustScan/RustScan) | A rust network scanner that is faster than Nmap, and sends open ports to Nmap for service/version detection.
[subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery tool.
[wappalyzer](https://www.wappalyzer.com/) | Identify what frameworks a website runs
[wpscan](https://github.com/wpscanteam/wpscan) | Automatic WordPress scanner to identify information about a WordPress site and possible vulnerabilities.

### Social Engineering
Repository | Description
---- | ----
[evilginx](https://github.com/kgretzky/evilginx2) | Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication
[GoPhish](https://github.com/gophish/gophish>) | Phishing campaign framework to compromise user credentials.
[Social Engineering Toolkit](https://github.com/trustedsec/social-engineer-toolkit) | Social engineering framework. 
[SpoofCheck](https://github.com/BishopFox/spoofcheck) | Checks if a domain can be spoofed.
[zphisher](https://github.com/htr-tech/zphisher) | An automated phishing tool with 30+ templates.

### Leaked Credentials
Repository | Description
---- | ----
[Dehashed](https://dehashed.com) | Leaked credential search engine to find passwords based on username, email, etc.
[LeakCheck](https://leakcheck.com) | Leaked credential search engine to find passwords based on username, email, domain, etc.
[Snusbase](https://snusbase.com) | Leaked credential search engine to find passwords based on username, email, etc.

### Web Exploitation
Repository | Description
---- | ----
[Arachni](https://github.com/Arachni/arachni) |  Web Application Security Scanner Framework
[burpsuite](https://portswigger.net/burp/communitydownload) | Full web testing suite, including proxied requests
[Caido](https://caido.io/) | Like Burp but written in Rust
[dirb](https://github.com/v0re/dirb) | Web application directory/file fuzzer to find other pages or files worth looking at.
[dotGit](https://github.com/davtur19/DotGit) | A Firefox and Chrome extension that shows you if there is an exposed `.git` directory 
[feroxbuster](https://github.com/epi052/feroxbuster) | Web application directory/file fuzzer to find other pages or files worth looking at. Written in Rust.
[flask-unsign](https://github.com/Paradoxis/Flask-Unsign) | Command line tool to fetch, decode, brute-force and craft session cookies of a Flask application
[gobuster](https://github.com/OJ/gobuster) | Web application directory/file fuzzer to find other pages or files worth looking at. Also supports DNS busting (such as subdomains). Written in Go.
[Nikto](https://github.com/sullo/nikto) | Web server scanner to perform security checks on a web server.
[nosqlmap](https://github.com/codingo/NoSQLMap) | Like sqlmap, but for NoSQL.
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master) | Useful payloads for a variety of attacks such as SQLi, IDOR, XSS, etc.
[sqlmap](https://github.com/sqlmapproject/sqlmap) | Performs automated SQL injection tests on GET and POST requests.
[w3af](https://w3af.org/) | Web application attack and audit framework.
[wappalyzer](https://www.wappalyzer.com/) | Identify what frameworks a website runs
[wpscan](https://github.com/wpscanteam/wpscan) | Automatic WordPress scanner to identify information about a WordPress site and possible vulnerabilities.
### Wireless
Repository | Description
---- | ----
[Aircrack-ng](https://www.aircrack-ng.org) | Aircrack-ng is a complete suite of tools to assess WiFi network security.
[Kismet](https://www.kismetwireless.net/) | sniffer, WIDS, and wardriving tool for Wi-Fi, Bluetooth, Zigbee, RF, and more
[Reaver](https://github.com/t6x/reaver-wps-fork-t6x) | Reaver implements a brute force attack against Wifi Protected Setup (WPS) registrar PINs in order to recover WPA/WPA2 passphrases
[Wifite](https://www.kali.org/tools/wifite/) | Python script to automate wireless auditing using aircrack-ng tools
[WifiPhisher](https://github.com/wifiphisher/wifiphisher) |  The Rogue Access Point Framework 

### Initial Access
Repository | Description
---- | ----
[Easysploit](https://github.com/KALILINUXTRICKSYT/easysploit) | Automatic Metasploit payload generator and shell listener.
[Impacket](https://github.com/SecureAuthCorp/impacket) | A collection of Python scripts useful for Windows targets: psexec, smbexec, kerberoasting, ticket attacks, etc.
[Kerbrute](https://github.com/ropnop/kerbrute) | A tool to perform Kerberos pre-auth bruteforcing
[Medusa](https://github.com/jmk-foofus/medusa) | Bruteforcer with multiple protocol support.
[Metasploit](https://github.com/rapid7/metasploit-framework) | Exploit framework that can be used for intial access and/or post-exploitation.
[Searchsploit](https://gitlab.com/exploit-database/exploitdb) | Search ExploitDB for exploits. Useful if you identify a service version.
[TeamFiltration](https://github.com/Flangvik/TeamFiltration) | Cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
[THC-Hydra](https://github.com/vanhauser-thc/thc-hydra) | Bruteforcer with multiple protocol support.
[TREVORspray](https://github.com/blacklanternsecurity/TREVORspray) | Advanced password spraying tool for Active Directory environments.

### C2 Frameworks
C2 frameworks can be considered both initial access and post-exploitation, as they generate payloads to be used in phishing campaigns (initial access) and will provide access to the host machine when ran (post exploitation).
Repository | Description
---- | ----
[Cobalt Strike](https://www.cobaltstrike.com/) | Most robust and advanced C2 framework (also paid).
[Pupy](https://github.com/n1nj4sec/pupy) | Python and C C2 framework.
[Sliver](https://github.com/BishopFox/sliver) | Go C2 framework.
[Villain](https://github.com/t3l3machus/Villain) | Python and Powershell C2 framework.

### Post Exploitation
Repository | Description
---- | ----
[BeRoot](https://github.com/AlessandroZ/BeRoot) | Automated Windows, Linux, and Mac privilege escalation path discovery tool.
[BloodHound](https://github.com/BloodHoundAD/BloodHound) | Active Directory visualizer, useful for finding misconfigurations and/or shortest path to Domain Admin.
[CrackmapExec](https://github.com/mpgn/CrackMapExec) | Post-exploitation tool that helps automate assessing the security of large Active Directory networks
[GTFOBins](https://gtfobins.github.io/) | Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
[Impacket](https://github.com/SecureAuthCorp/impacket) | A collection of Python scripts useful for Windows targets: psexec, smbexec, kerberoasting, ticket attacks, etc.
[Invoke-PrivescCheck](https://github.com/itm4n/PrivescCheck) | Automated Windows privilege escalation path discovery tool.
[LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) | Microsoft-signed binaries to perform APT or red-team functions (ie: dumping process memory).
[Metasploit](https://github.com/rapid7/metasploit-framework) | Exploit framework that can be used for intial access and/or post-exploitation.
[Mimikatz](https://github.com/ParrotSec/mimikatz) | Mimikatz is both an exploit on Microsoft Windows that extracts passwords stored in memory and software that performs that exploit.
[nishang](https://github.com/samratashok/nishang) | Offensive PowerShell for red team, penetration testing and offensive security.
[PEASS-ng](https://github.com/carlospolop/PEASS-ng) | Automated Windows, Linux, and Mac privilege escalation path discovery tool.
[PowerHub](https://github.com/AdrianVollmer/PowerHub) | Post-exploitation module for bypassing endpoint protection and running arbitrary files.
[PowerSploit](https://github.com/AdrianVollmer/PowerSploit) | A PowerShell post-exploitation framework with many modules: exfiltration, privelege escalation, etc.
[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) | Automated Windows privilege escalation path discovery tool.
[Searchsploit](https://gitlab.com/exploit-database/exploitdb) | Search ExploitDB for exploits. Useful if you identify a service version.
[SharpHound](https://github.com/BloodHoundAD/SharpHound) | Data ingestor for BloodHound.
[smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) | Allows connection to the SMB protocol.
[smbmap](https://github.com/ShawnDEvans/smbmap) | Enumerates SMB shares.

### Exfiltration
Repository | Description
---- | ----
[DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) | Data exfiltration over DNS request covert channel
[PowerSploit](https://github.com/AdrianVollmer/PowerSploit) | A PowerShell post-exploitation framework with many modules: exfiltration, privelege escalation, etc.

### Credential Dumping
Repository | Description
---- | ----
[certsync](https://github.com/zblurx/certsync) | Dump NTDS with golden certificates and UnPAC the hash
[Dumpert](https://github.com/outflanknl/Dumpert) | LSASS memory dumper using direct system calls and API unhooking.
[Mimikatz](https://github.com/ParrotSec/mimikatz) | Mimikatz is both an exploit on Microsoft Windows that extracts passwords stored in memory and software that performs that exploit.
[nishang](https://github.com/samratashok/nishang) | Offensive PowerShell for red team, penetration testing and offensive security.
[PowerSploit](https://github.com/AdrianVollmer/PowerSploit) | A PowerShell post-exploitation framework with many modules: exfiltration, privelege escalation, etc.

### Password Cracking
Repository | Description
---- | ----
[CeWL](https://github.com/digininja/CeWL) | Scrape a website to generate a wordlist 
[crunch](https://github.com/jim3ma/crunch) | Generate wordlists based on requirements such as minimum and maximum length, character sets, etc.
[Cupp](https://github.com/Mebus/cupp) | Utilize OSINT to create password candidates for a specific person
[hashcat](https://hashcat.net/hashcat) | Password cracking tool with multiple different supported formats
[JohnTheRipper](https://www.openwall.com/john/) | Password cracking tool (slower than Hashcat) but supports more formats with the Jumbo version
[Mentalist](https://github.com/sc0tfree/mentalist) | A GUI for wordlisst generation

## Blue Team

### Forensics
Repository | Description
---- | ----
[Autopsy](https://github.com/sleuthkit/autopsy) | Investigate disk images
[Chainsaw](https://github.com/WithSecureLabs/chainsaw) |  Rapidly Search and Hunt through Windows Forensic Artefacts
[FTK Imager](https://www.exterro.com/ftk-imager) | Investigate disk images
[Velociraptor](https://github.com/Velocidex/velociraptor) | Velociraptor is a tool for collecting host based state information using The Velociraptor Query Language (VQL) queries.
[Volatility](https://github.com/volatilityfoundation/volatility) | An advanced memory forensics framework
[Wireshark](https://www.wireshark.org/) | Network traffic packet analyzer
[ZimmermanTools](https://ericzimmerman.github.io) | Eric Zimmerman's toolset for Windows forensics. EVTX, registry, ShellBags, ShimCache, and more.

### Deobfuscation
Repository | Description
---- | ----
[cfxc-deobf](https://github.com/wildcardc/cfxc-deobf) | ConfuserEx unpacker.
[de4dot-cex](https://github.com/ViRb3/de4dot-cex) | ConfuserEx unpacker.
[de4dot](https://github.com/de4dot/de4dot) | .NET deobfuscator and unpacker.
[FLOSS](https://github.com/mandiant/flare-floss) | Automatically extract obfuscated strings from malware.
[NoFuserEx](https://github.com/undebel/NoFuserEx) | ConfuserEx unpacker.
[Packer-specific Unpackers](https://github.com/NotPrab/.NET-Deobfuscator/blob/master/README.md) | List of unpackers for specific packers.
[PSDecode](https://github.com/R3MRUM/PSDecode) | PowerShell deobfuscator. 
[UnconfuserExTools](https://github.com/landoncrabtree/UnconfuserExTools) | ConfuserEx deobfuscation toolkit (old).

### Reverse Engineering
Repository | Description
---- | ----
[awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) | A list of plugins for IDA, Ghidra, GDB, OllyDBG, etc. 
[Cerberus](https://github.com/h311d1n3r/Cerberus) | A Python tool to unstrip Rust/Go binaries on Linux
[cutter](https://github.com/rizinorg/cutter) | Disassembler and decompiler for multiple executable formats, based on Rizin.
[Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | Detect file type and packer used.
[dnSpy](https://github.com/dnSpy/dnSpy) | .NET debugger and editor.
[dotPeak](https://www.jetbrains.com/decompiler/) | .NET Decompiler and assembly browser
[FLOSS](https://github.com/mandiant/flare-floss) | Automatically extract obfuscated strings from malware.
[GDB](https://www.sourceware.org/gdb/) | Debugging tool for C, C++, Go, Rust, and more. 
[GEF](https://github.com/hugsy/gef) | GDB addon with advanced features -- GDB Enhanced Features.
[ghidra](https://github.com/NationalSecurityAgency/ghidra) | Disassembler and decompiler for multiple executable formats.
[hexedit](https://github.com/pixel/hexedit) | View file hexadecimal.
[JADX](https://github.com/skylot/jadx) |  decompilation tool that can decompile JAR, APK, DEX, AAR, AAB, ZIP files
[IDA](https://www.hex-rays.com/products/ida/index.shtml) | Disassembler and decompiler for multiple executable formats.
[PEiD](https://github.com/wolfram77web/app-peid) | detects most common packers, cryptors and compilers for PE files.
[rizin](https://github.com/rizinorg/rizin) | CLI disassembler.
[XPEViewer](https://github.com/horsicq/XPEViewer) | PE file viewer (headers, libraries, strings, etc).

### Malware Analysis
Repository | Description
---- | ----
[Cuckoo](https://cuckoosandbox.org/) | Automated dynamic malware analysis.
[Wireshark](https://www.wireshark.org/download.html) | View incoming and outgoing network connections.

### Hardening
Repository | Description
---- | ----
[BLUESPAWN](https://github.com/ION28/BLUESPAWN) |  An Active Defense and EDR software to empower Blue Teams 
[CISBenchmarks](https://downloads.cisecurity.org/#/) | Benchmark for security configuration best practices
[HardeningKitty](https://github.com/0x6d69636b/windows_hardening) |  HardeningKitty and Windows Hardening settings and configurations 
[Linux Hardening](https://madaidans-insecurities.github.io/guides/linux-hardening.html) | Linux Hardening
[SteamRoller](https://github.com/Msfv3n0m/SteamRoller) | automating basic security configurations across an Active Directory environment 



## CTF

Coming soon?




