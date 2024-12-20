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

> This repository is just a brief (and generalized) list of resources and tools for both sides of cyber: blue and red team operations. As such, this is not meant to be in-depth resources. If you are looking for more specific information and/or tools, this contains a list of resource collections.

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

| Repository                                                                         | Description                                                        |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| [Amsi-Bypass-PowerShell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) | AMSI bypasses (most are patched, but can be obfuscated to bypass). |
| [AMSITrigger](https://github.com/RythmStick/AMSITrigger)                           | Finds which string(s) trigger AMSI.                                |
| [chameleon](https://github.com/klezVirus/chameleon)                                | PowerShell script obfuscator.                                      |
| [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)                             | Used to bypass PowerShell security (logging, AMSI, etc).           |
| [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation>)        | PowerShell script obfuscator.                                      |
| [ISESteroids](https://powershell.one/isesteroids/quickstart/overview)              | PowerShell script obfuscator.                                      |
| [Invoke-Stealth](https://github.com/JoelGMSec/Invoke-Stealth)                      | PowerShell script obfuscator.                                      |
| [UPX](https://upx.github.io/)                                                      | PE packer.                                                         |
| [Unprotect](https://unprotect.it)                                                  | Contains malware evasion techniques along with PoC.                |

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

| Repository                                                    | Description                                                                                                         |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| [altdns](https://github.com/infosec-au/altdns)                | Subdomain enumeration using mutated wordlists.                                                                      |
| [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) | Enumerate AWS S3 buckets to find interesting files.                                                                 |
| [CameRadar](https://github.com/Ullaakut/cameradar)            | Cameradar hacks its way into RTSP videosurveillance cameraa                                                         |
| [CloudBrute](https://github.com/0xsha/CloudBrute)             | Enumerates "the cloud" (Google, AWS, DigitalOcean, etc) to find infrastructure, files, and apps for a given target. |
| [dirb](https://github.com/v0re/dirb)                          | Web application directory / file fuzzer to find other pages.                                                        |
| [DNSDumpster](https://dnsdumpster.com/)                       | Online tool for DNS information of a domain.                                                                        |
| [feroxbuster](https://github.com/epi052/feroxbuster)          | Web application directory / file fuzzer to find other pages.                                                        |
| [gobuster](https://github.com/OJ/gobuster)                    | Web application directory / file fuzzer to find other pages, and support for DNS and vhost fuzzing.                 |
| [GoWitness](https://github.com/sensepost/gowitness)           | Screenshots webpages. Supports multi-domain lists and Nmap output.                                                  |
| [Masscan](https://github.com/robertdavidgraham/masscan)       | Like nmap, but faster (thus, not stealthy.)                                                                         |
| [Nikto](https://github.com/sullo/nikto)                       | Web server scanner to perform security checks on a web server.                                                      |
| [Nmap](https://nmap.org/)                                     | Finds open ports on a network. Additionally can detect version, OS, and more.                                       |
| [Raccoon](https://github.com/evyatarmeged/Raccoon)            | All-in-one reconaissance. port/service scans, dirbusting, and web application retrieval.                            |
| [Recon-NG](https://github.com/lanmaster53/recon-ng)           | Reconaissance and OSINT framework. Has many modules such as port scanning, subdomain finding, Shodan, etc.          |
| [subfinder](https://github.com/projectdiscovery/subfinder)    | Passive subdomain discovery tool.                                                                                   |
| [wappalyzer](https://www.wappalyzer.com/)                     | Identify what frameworks a website runs                                                                             |
| [wpscan](https://github.com/wpscanteam/wpscan)                | Automatic WordPress scanner to identify information about a WordPress site and possible vulnerabilities.            |

### Social Engineering

| Repository                                                                          | Description                                                                                                                                                      |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [evilginx](https://github.com/kgretzky/evilginx2)                                   | Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication |
| [GoPhish](https://github.com/gophish/gophish>)                                      | Phishing campaign framework to compromise user credentials.                                                                                                      |
| [msfvenom](https://www.offsec.com/metasploit-unleashed/msfvenom/)                   | Generate malicious payloads for social engineering (ie: VBA, .exe, etc)                                                                                          |
| [Social Engineering Toolkit](https://github.com/trustedsec/social-engineer-toolkit) | Social engineering framework.                                                                                                                                    |
| [SpoofCheck](https://github.com/BishopFox/spoofcheck)                               | Checks if a domain can be spoofed.                                                                                                                               |
| [zphisher](https://github.com/htr-tech/zphisher)                                    | Phishing campaign framework to compromise user credentials.                                                                                                      |
### Leaked Credentials

| Repository                         | Description                      |
| ---------------------------------- | -------------------------------- |
| [Dehashed](https://dehashed.com)   | Leaked credential search engine. |
| [LeakCheck](https://leakcheck.com) | Leaked credential search engine. |
| [Snusbase](https://snusbase.com)   | Leaked credential search engine. |

### Web Exploitation

| Repository                                                                              | Description                                                                                              |
| --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| [Arachni](https://github.com/Arachni/arachni)                                           | Web Application Security Scanner Framework                                                               |
| [burpsuite](https://portswigger.net/burp/communitydownload)                             | Full web testing suite, including proxied requests.                                                      |
| [Caido](https://caido.io/)                                                              | Full web testing suite, including proxied requests. (Like Burp but written in Rust)                      |
| [dirb](https://github.com/v0re/dirb)                                                    | Web application directory/file fuzzer.                                                                   |
| [dotGit](https://github.com/davtur19/DotGit)                                            | A Firefox and Chrome extension that shows you if there is an exposed `.git` directory                    |
| [feroxbuster](https://github.com/epi052/feroxbuster)                                    | Web application directory/file fuzzer.                                                                   |
| [flask-unsign](https://github.com/Paradoxis/Flask-Unsign)                               | Decode, bruteforce, and craft Flask session tokens.                                                      |
| [gobuster](https://github.com/OJ/gobuster)                                              | Web application directory/file/DNS/vhost fuzzing.                                                        |
| [Nikto](https://github.com/sullo/nikto)                                                 | Web server scanner to perform security checks on a web server.                                           |
| [nosqlmap](https://github.com/codingo/NoSQLMap)                                         | Performs automated NoSQL injection tests.                                                                |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master) | Useful payloads for a variety of attacks such as SQLi, IDOR, XSS, etc.                                   |
| [sqlmap](https://github.com/sqlmapproject/sqlmap)                                       | Performs automated SQL injection tests.                                                                  |
| [w3af](https://w3af.org/)                                                               | Web application attack and audit framework.                                                              |
| [wappalyzer](https://www.wappalyzer.com/)                                               | Identify what frameworks a website runs.                                                                 |
| [wpscan](https://github.com/wpscanteam/wpscan)                                          | Automatic WordPress scanner to identify information about a WordPress site and possible vulnerabilities. |

### Wireless

Repository | Description
---- | ----
[Aircrack-ng](https://www.aircrack-ng.org) | Aircrack-ng is a complete suite of tools to assess WiFi network security.
[Kismet](https://www.kismetwireless.net/) | sniffer, WIDS, and wardriving tool for Wi-Fi, Bluetooth, Zigbee, RF, and more
[Reaver](https://github.com/t6x/reaver-wps-fork-t6x) | Reaver implements a brute force attack against Wifi Protected Setup (WPS) registrar PINs in order to recover WPA/WPA2 passphrases
[Wifite](https://www.kali.org/tools/wifite/) | Python script to automate wireless auditing using aircrack-ng tools
[WifiPhisher](https://github.com/wifiphisher/wifiphisher) |  The Rogue Access Point Framework

### Initial Access

| Repository                                                         | Description                                                                                                                                      |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| [Easysploit](https://github.com/KALILINUXTRICKSYT/easysploit)      | Automatic Metasploit payload generator and shell listener.                                                                                       |
| [Impacket](https://github.com/SecureAuthCorp/impacket)             | A tool to perform Kerberos pre-auth bruteforcing (ASREP roast) via GetNPUsers.py                                                                 |
| [Kerbrute](https://github.com/ropnop/kerbrute)                     | A tool to perform Kerberos pre-auth bruteforcing (ASREP roast)                                                                                   |
| [Medusa](https://github.com/jmk-foofus/medusa)                     | Bruteforcer with multiple protocol support.                                                                                                      |
| [Metasploit](https://github.com/rapid7/metasploit-framework)       | Exploit framework that can be used for intial access and/or post-exploitation.                                                                   |
| [NetExec](https://github.com/Pennyw0rth/NetExec)                   | Bruteforce common Windows protocols (WinRM, LDAP, RDP, SMB, WMI, etc.). Try username `null or ''` and password `''` for unauthenticated access.  |
| [Searchsploit](https://gitlab.com/exploit-database/exploitdb)      | Search ExploitDB for exploits.                                                                                                                   |
| [TeamFiltration](https://github.com/Flangvik/TeamFiltration)       | Cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts                                              |
| [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra)            | Bruteforcer with multiple protocol support.                                                                                                      |
| [TREVORspray](https://github.com/blacklanternsecurity/TREVORspray) | Advanced password spraying tool for Active Directory environments.                                                                               |

### C2 Frameworks

> C2 frameworks can be considered both initial access and post-exploitation, as they generate payloads to be used in phishing campaigns (initial access) and will provide access to the host machine when ran (post exploitation).

Repository | Description
---- | ----
[Cobalt Strike](https://www.cobaltstrike.com/) | Most robust and advanced C2 framework (also paid).
[Pupy](https://github.com/n1nj4sec/pupy) | Python and C C2 framework.
[Sliver](https://github.com/BishopFox/sliver) | Go C2 framework.
[Villain](https://github.com/t3l3machus/Villain) | Python and Powershell C2 framework.

### Post Exploitation

> Modules for lateral movement, exfiltration, system enumeration, and more.

| Repository                                                  | Description                                                                                                                                                                           |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound)    | Active Directory visualizer, useful for finding misconfigurations and/or shortest path to Domain Admin.                                                                               |
| [BloodHound.py](https://github.com/dirkjanm/BloodHound.py)  | Remote Python data ingestor for BloodHound.                                                                                                                                           |
| [Impacket](https://github.com/SecureAuthCorp/impacket)      | A collection of Python scripts useful for Windows targets: psexec, smbexec, kerberoasting, ticket attacks, etc.                                                                       |
| [Mimikatz](https://github.com/ParrotSec/mimikatz)           | Mimikatz is both an exploit on Microsoft Windows that extracts passwords stored in memory and software that performs that exploit.                                                    |
| [nishang](https://github.com/samratashok/nishang)           | Offensive PowerShell for red team, penetration testing and offensive security.                                                                                                        |
| [PowerHub](https://github.com/AdrianVollmer/PowerHub)       | Post-exploitation module for bypassing endpoint protection and running arbitrary files.                                                                                               |
| [PowerSploit](https://github.com/AdrianVollmer/PowerSploit) | A PowerShell post-exploitation framework with many modules: exfiltration, privelege escalation, etc.                                                                                  |
| [SharpHound](https://github.com/BloodHoundAD/SharpHound)    | C# data ingestor for BloodHound. (Recommend [SharpHound.ps1](https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1) for Bloodhound Kali version) |

### Privilege Escalation

> These tools automatically enumerate current user privileges and try to find misconfigurations that would allow escalation to `root` and/or `NT AUTHORITY\SYSTEM`.

| Repository                                                                                | Description                                                                                    |
| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [BeRoot](https://github.com/AlessandroZ/BeRoot)                                           | Automated Windows, Linux, and Mac privilege escalation path discovery tool.                    |
| [GTFOBins](https://gtfobins.github.io/)                                                   | Unix binaries that can be used to bypass local security restrictions in misconfigured systems. |
| [Invoke-PrivescCheck](https://github.com/itm4n/PrivescCheck)                              | Automated Windows privilege escalation path discovery tool.                                    |
| [PEASS-ng](https://github.com/carlospolop/PEASS-ng)                                       | Automated Windows, Linux, and Mac privilege escalation path discovery tool.                    |
| [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) | Automated Windows privilege escalation path discovery tool.                                    |

### Exfiltration

> Data exfiltration

| Repository                                                  | Description                                                                                          |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator)  | Data exfiltration over DNS request covert channel                                                    |

### Credential Dumping

> These tools help dump cached credentials from a system.

| Repository                                             | Description                                                                  |
| ------------------------------------------------------ | ---------------------------------------------------------------------------- |
| [certsync](https://github.com/zblurx/certsync)         | Dump NTDS with golden certificates and UnPAC the hash                        |
| [Dumpert](https://github.com/outflanknl/Dumpert)       | LSASS memory dumper using direct system calls and API unhooking.             |
| [Impacket](https://github.com/SecureAuthCorp/impacket) | Dump domain credentials via DCSync or from NTDS.DIT/SAM with secretsdump.py. |
| [Mimikatz](https://github.com/ParrotSec/mimikatz)      | Dump local and domain credentials with sekurlsa, lsadump modules.            |

### Password Cracking

> These tools assist in uncovering passwords, whether it be for a hash or for password spraying attempts.

| Repository                                         | Description                                                                                       |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| [CeWL](https://github.com/digininja/CeWL)          | Scrape websites to generate wordlists.                                                            |
| [crunch](https://github.com/jim3ma/crunch)         | Generate wordlists based on requirements such as minimum and maximum length, character sets, etc. |
| [Cupp](https://github.com/Mebus/cupp)              | Utilize OSINT to create password candidates for a specific person.                                |
| [hashcat](https://hashcat.net/hashcat)             | Password cracking tool.                                                                           |
| [JohnTheRipper](https://www.openwall.com/john/)    | Password cracking tool.                                                                           |
| [Mentalist](https://github.com/sc0tfree/mentalist) | A GUI for wordlist generation based on rules such as appending, prepending, etc.                  |

### AI / LLM

> This section will probably be outdated quick.

| Repository                                                        | Description                                                                                                                     |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [HarmBench](https://www.harmbench.org/)                           | A standardized evaluation framework for automated red teaming and robust refusal.                                               |
| [Adversarial Suffix](https://llm-attacks.org/index.html#examples) | Jailbreak based on prepending a potentially malicious query.                                                                    |
| [AutoDAN-Turbo](https://autodans.github.io/AutoDAN-Turbo/)        | Black-box jailbreak method that can automatically discover as many jailbreak strategies as possible from scratch.               |
| [Best-of-N](https://jplhughes.github.io/bon-jailbreaking/)        | Black-box algorithm that jailbreaks frontier AI systems across modalities (text, image, vision) by mutating the original query. |

## Blue Team

### Forensics

| Repository                                                                    | Description                                                                                                             |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| [Angle-Grinder](https://github.com/rcoh/angle-grinder)                        | Parse, aggregate, sum, average, min/max, percentile, and sort log files.                                                |
| [Autopsy](https://github.com/sleuthkit/autopsy)                               | Investigate disk images.                                                                                                |
| [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) | Show persistence on Windows                                                                                             |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw)                        | Parse and threat hunt Windows EVTX files.                                                                               |
| [FTK Imager](https://www.exterro.com/ftk-imager)                              | Investigate disk images.                                                                                                |
| [KnockKnock](https://objective-see.org/products/knockknock.html)              | Show persistence on macOS                                                                                               |
| [Magika](https://github.com/google/magika)                                    | Detect file content types with deep learning.                                                                           |
| [Velociraptor](https://github.com/Velocidex/velociraptor)                     | Velociraptor is a tool for collecting host based state information using The Velociraptor Query Language (VQL) queries. |
| [Volatility](https://github.com/volatilityfoundation/volatility)              | Analyze memory dump files.                                                                                              |
| [ZimmermanTools](https://ericzimmerman.github.io)                             | Eric Zimmerman's toolset for Windows forensics: EVTX, registry, ShellBags, ShimCache, and more.                         |
### Network Analysis

| Repository                              | Description                                                    |
| --------------------------------------- | -------------------------------------------------------------- |
| [mitmproxy](https://mitmproxy.org/)     | CLI-based HTTP(S) proxy to intercept and modify HTTP requests. |
| [Wireshark](https://www.wireshark.org/) | GUI-based pcap, pcapng analyzer and network traffic sniffer.   |

### Deobfuscation & Unpacking

| Repository                                                                                      | Description                                            |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| [cfxc-deobf](https://github.com/wildcardc/cfxc-deobf)                                           | ConfuserEx unpacker.                                   |
| [de4dot-cex](https://github.com/ViRb3/de4dot-cex)                                               | ConfuserEx unpacker.                                   |
| [de4dot](https://github.com/de4dot/de4dot)                                                      | .NET deobfuscator and unpacker.                        |
| [deobfuscate.io](https://deobfuscate.io/)                                                       | Javascript deobfuscator.                               |
| [FLOSS](https://github.com/mandiant/flare-floss)                                                | Automatically extract obfuscated strings from malware. |
| [NoFuserEx](https://github.com/undebel/NoFuserEx)                                               | ConfuserEx unpacker.                                   |
| [Packer-specific Unpackers](https://github.com/NotPrab/.NET-Deobfuscator/blob/master/README.md) | List of unpackers for specific packers.                |
| [PSDecode](https://github.com/R3MRUM/PSDecode)                                                  | PowerShell deobfuscator.                               |
| [relative.im](https://deobfuscate.relative.im/)                                                 | Javascript deobfuscator.                               |
| [UnconfuserExTools](https://github.com/landoncrabtree/UnconfuserExTools)                        | ConfuserEx deobfuscation toolkit (old).                |

### Reverse Engineering

| Repository                                                                            | Description                                                |
| ------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| [awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) | A list of plugins for IDA, Ghidra, GDB, OllyDBG, etc.      |
| [Binary Ninja](https://binary.ninja/)                                                 | Decompiler, disassembler, and debugger GUI.                |
| [Cerberus](https://github.com/h311d1n3r/Cerberus)                                     | Unstrips Rust and Go binaries.                             |
| [cutter](https://github.com/rizinorg/cutter)                                          | Decompiler, disassembler, and debugger GUI based on Rizin. |
| [dnSpy](https://github.com/dnSpy/dnSpy)                                               | .NET debugger and editor.                                  |
| [dotPeak](https://www.jetbrains.com/decompiler/)                                      | .NET Decompiler and assembly browser                       |
| [GDB](https://www.sourceware.org/gdb/)                                                | CLI debugger for Linux executables.                        |
| [GEF](https://github.com/hugsy/gef)                                                   | GDB addon with advanced features.                          |
| [ghidra](https://github.com/NationalSecurityAgency/ghidra)                            | Decompiler and disassembler GUI.                           |
| [JADX](https://github.com/skylot/jadx)                                                | JAR, APK, DEX, AAR, AAB, and ZIP decompiler.               |
| [IDA](https://www.hex-rays.com/products/ida/index.shtml)                              | Decompiler and disassembler GUI.                           |
| [OllyDbg](https://www.ollydbg.de/)                                                    | GUI debugger for Windows executables.                      |
| [pycdc](https://github.com/zrax/pycdc)                                                | Decompile .pyc files into Python source code.              |
| [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor)                  | Extract .pyc files from PyInstaller compiled executables.  |
| [redress](https://github.com/goretk/redress)                                          | Analyzes stripped Go binaries.                             |
| [rizin](https://github.com/rizinorg/rizin)                                            | Disassembler and debugger CLI.                             |
| [x64dbg](https://x64dbg.com/)                                                         | GUI debugger for Windows executables.                      |
| [XPEViewer](https://github.com/horsicq/XPEViewer)                                     | PE file viewer (headers, libraries, strings, etc).         |

### Malware Analysis

| Repository                                                                                    | Description                                                                                       |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| [any.run](https://any.run)                                                                    | Cloud-based sandbox.                                                                              |
| [CAPA](https://github.com/mandiant/capa)                                                      | Identify capabilities in executable files.                                                        |
| [CAPEv2](https://github.com/kevoreilly/CAPEv2)                                                | Self-hosted sandbox.                                                                              |
| [Cuckoo](https://cuckoosandbox.org/)                                                          | Self-hosted sandbox.                                                                              |
| [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy)                                   | Detect file type and packer used for Windows executables.                                         |
| [DRAKVUF](https://github.com/CERT-Polska/drakvuf-sandbox?tab=readme-ov-file)                  | Self-hosted sandbox.                                                                              |
| [Joe's Sandbox](https://www.joesandbox.com/#windows)                                          | Cloud-based sandbox.                                                                              |
| [mac-monitor](https://github.com/redcanaryco/mac-monitor)                                     | Advanced process monitoring for macOS                                                             |
| [oletools](https://github.com/decalage2/oletools)                                             | Toolkit for Microsoft Office documents (Word, Excel, etc.) to extract VBA, embedded objects, etc. |
| [PEiD](https://github.com/wolfram77web/app-peid)                                              | Detect packer, cryptor, and compiler used for Windows executables.                                |
| [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) | Shows parent-child relationships between processes and open DLL handles.                          |
| [Process Hacker](https://processhacker.sourceforge.io/)                                       | Process Explorer + more                                                                           |
| [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)           | Tracks registry, file system, network, and process activity.                                      |

### Hardening

Repository | Description
---- | ----
[BLUESPAWN](https://github.com/ION28/BLUESPAWN) |  An Active Defense and EDR software to empower Blue Teams
[CISBenchmarks](https://downloads.cisecurity.org) | Benchmark for security configuration best practices
[HardeningKitty](https://github.com/0x6d69636b/windows_hardening) | HardeningKitty and Windows Hardening settings and configurations
[Linux Hardening](https://madaidans-insecurities.github.io/guides/linux-hardening.html) | Linux Hardening
[SteamRoller](https://github.com/Msfv3n0m/SteamRoller) | Automating basic security configurations across an Active Directory environment

## CTF

Coming soon?




