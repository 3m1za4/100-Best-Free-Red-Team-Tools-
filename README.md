[![Red Team Tools](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhqaEH1QZLUx7puOELe9mwgEQxmu5c6MDqI2gkkazvYx64ELy2JPgTy2AB-yJ5nL4bHW9rcVi7yaTT4_lHfWLPoJCn_QeEEYbgaRDt6Tm__ml47sb8qs7f4nqbrXSGr2BoCoYvOcQ4jptnE_c2S8A_zTPxm-blVo1PLXZcGdzMryXLRPO0zqGPptIKAPg/s16000/Red%20Team%20Tools.webp "Red Team Tools")](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhqaEH1QZLUx7puOELe9mwgEQxmu5c6MDqI2gkkazvYx64ELy2JPgTy2AB-yJ5nL4bHW9rcVi7yaTT4_lHfWLPoJCn_QeEEYbgaRDt6Tm__ml47sb8qs7f4nqbrXSGr2BoCoYvOcQ4jptnE_c2S8A_zTPxm-blVo1PLXZcGdzMryXLRPO0zqGPptIKAPg/s16000/Red%20Team%20Tools.webp)

We are bringing here a collection of open-source and commercial Red Team tools that aid in red team operations. This repository will help you with the majority part of red team engagement. You can also join the [**Certified Red Team Expert**](https://ethicalhackersacademy.com/collections/ethical-hackers-academy/products/certified-redteam-expert) program to become a master in red team operation and understand real-world attacks.

-   Reconnaissance
-   Weaponization
-   Delivery
-   Command and Control
-   Lateral Movement
-   Establish Foothold
-   Escalate Privileges
-   Data Exfiltration
-   Misc
-   References

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#reconnaissance)**Reconnaissance**

### [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#active-intelligence-gathering)**Active Intelligence Gathering**

-   [**EyeWitness**](https://github.com/ChrisTruncer/EyeWitness) is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
-   [**AWSBucketDump**](https://github.com/jordanpotti/AWSBucketDump) is a tool to quickly enumerate AWS S3 buckets to look for loot. 
-   [**AQUATONE**](https://github.com/michenriksen/aquatone) is a set of tools for performing reconnaissance on domain names. 
-   [**spoofcheck**](https://github.com/BishopFox/spoofcheck) a program that checks if a domain can be spoofed. The program checks SPF and DMARC records for weak configurations that allow spoofing. 
-   [**Nmap**](https://github.com/nmap/nmap) is used to discover hosts and services on a computer network, thus building a “map” of the network. 
-   [**dnsrecon**](https://github.com/darkoperator/dnsrecon) a tool [DNS](https://cybersecuritynews.com/dns-attacks/) Enumeration Script. 
-   [**dirsearch**](https://github.com/maurosoria/dirsearch) is a simple command line tool designed to brute force directories and files in websites. 
-   [**Sn1per**](https://github.com/1N3/Sn1per) automated pentest recon scanner. 

### [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#passive-intelligence-gathering)**Passive Intelligence Gathering**

-   [**Social Mapper**](https://github.com/SpiderLabs/social_mapper) [OSINT](https://cybersecuritynews.com/osint-tools/) Social Media Mapping Tool, takes a list of names & images (or LinkedIn company name) and performs automated target searching on a huge scale across multiple social media sites. Not restricted by APIs as it instruments a browser using Selenium. Outputs reports to aid in correlating targets across sites. 
-   [**skiptracer**](https://github.com/xillwillx/skiptracer) OSINT scraping framework, utilizes some basic python webscraping (BeautifulSoup) of PII paywall sites to compile passive information on a target on a ramen noodle budget. 
-   [**FOCA**](https://github.com/ElevenPaths/FOCA) (Fingerprinting Organizations with Collected Archives) is a tool used mainly to find metadata and hidden information in the documents its scans. 
-   [**theHarvester**](https://github.com/laramies/theHarvester) is a tool for gathering subdomain names, e-mail addresses, virtual hosts, open ports/ banners, and employee names from different public sources. 
-   [**Metagoofil**](https://github.com/laramies/metagoofil) is a tool for extracting metadata of public documents (pdf,doc,xls,ppt,etc) availables in the target websites. 
-   [**SimplyEmail**](https://github.com/killswitch-GUI/SimplyEmail) Email recon made fast and easy, with a framework to build on.
-   [**truffleHog**](https://github.com/dxa4481/truffleHog) searches through git repositories for secrets, digging deep into commit history and branches. 
-   **[Just-Metadata](https://github.com/ChrisTruncer/Just-Metadata)** is a tool that gathers and analyzes metadata about IP addresses. It attempts to find relationships between systems within a large dataset. 
-   [**typofinder**](https://github.com/nccgroup/typofinder) a finder of domain typos showing country of IP address. 
-   [**pwnedOrNot**](https://github.com/thewhiteh4t/pwnedOrNot) is a python script which checks if the email account has been compromised in a data breach, if the email account is compromised it proceeds to find passwords for the compromised account. 
-   [**GitHarvester**](https://github.com/metac0rtex/GitHarvester) This tool is used for harvesting information from GitHub like google dork. 
-   [**pwndb**](https://github.com/davidtavarez/pwndb/) is a python command-line tool for searching leaked credentials using the Onion service with the same name.
-   [**LinkedInt**](https://github.com/vysecurity/LinkedInt) LinkedIn Recon Tool. 
-   [**CrossLinked**](https://github.com/m8r0wn/CrossLinked) LinkedIn enumeration tool to extract valid employee names from an organization through search engine scraping. 
-   [**findomain**](https://github.com/Edu4rdSHL/findomain) is a fast domain enumeration tool that uses Certificate Transparency logs and a selection of APIs. [h](https://github.com/Edu4rdSHL/findomain)

### [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#frameworks)**Frameworks**

-   [**Maltego**](https://www.paterva.com/web7/downloads.php) is a unique platform developed to deliver a clear threat picture to the environment that an organization owns and operates. 
-   [**SpiderFoot**](https://github.com/smicallef/spiderfoot) the open source footprinting and intelligence-gathering tool. 
-   [**datasploit**](https://github.com/DataSploit/datasploit) is an OSINT Framework to perform various recon techniques on Companies, People, Phone Number, Bitcoin Addresses, etc., aggregate all the raw data, and give data in multiple formats. 
-   **[Recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng)** is a full-featured Web Reconnaissance framework written in Python. 

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#weaponization)**Weaponization**

-   **[WinRAR Remote Code Execution](https://github.com/WyAtu/CVE-2018-20250)** Proof of Concept exploit for CVE-2018-20250. 
-   **[Composite Moniker](https://github.com/rxwx/CVE-2017-8570)** Proof of Concept exploit for CVE-2017-8570. 
-   **[Exploit toolkit](https://github.com/bhdresh/CVE-2017-8759) [C](https://github.com/bhdresh/CVE-2017-8759)[VE-2017-8759](https://github.com/bhdresh/CVE-2017-8759)** is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft .NET Framework RCE. 
-   **[CVE-2017-11882 Exploit](https://github.com/unamer/CVE-2017-11882)** accepts over 17k bytes long command/code in maximum. 
-   **[Adobe Flash Exploit](https://github.com/anbai-inc/CVE-2018-4878)** CVE-2018-4878. 
-   **[Exploit toolkit CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199)** is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft Office RCE. 
-   [**demiguise**](https://github.com/nccgroup/demiguise) is a HTA encryption tool for RedTeams. 
-   **[Office-DDE-Payloads](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads)** collection of scripts and templates to generate Office documents embedded with the DDE, macro-less command execution technique. 
-   [**CACTUSTORCH**](https://github.com/mdsecactivebreach/CACTUSTORCH) Payload Generation for Adversary Simulations. 
-   [**SharpShooter**](https://github.com/mdsecactivebreach/SharpShooter) is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. 
-   [**Don’t kill my cat**](https://github.com/Mr-Un1k0d3r/DKMC) is a tool that generates obfuscated shellcode that is stored inside of polyglot images. The image is 100% valid and also 100% valid shellcode. 
-   [**Malicious Macro Generator Utility**](https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator) Simple utility design to generate obfuscated macro that also include a AV / Sandboxes escape mechanism. 
-   **[SCT Obfuscator](https://github.com/Mr-Un1k0d3r/SCT-obfuscator)** Cobalt Strike SCT payload obfuscator. 
-   **[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)** PowerShell Obfuscator.
-   **[Invoke-CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter)** PowerShell remote download cradle generator and obfuscator. 
-   **[Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)** cmd.exe Command Obfuscation Generator & Detection Test Harness. 
-   [**morphHTA**](https://github.com/vysec/morphHTA) Morphing Cobalt Strike’s evil.HTA. 
-   [**Unicorn**](https://github.com/trustedsec/unicorn) is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. 
-   [**Shellter**](https://www.shellterproject.com/) is a dynamic shellcode injection tool, and the first truly dynamic PE infector ever created. 
-   [**EmbedInHTML**](https://github.com/Arno0x/EmbedInHTML) Embed and hide any file in an HTML file. 
-   [**SigThief**](https://github.com/secretsquirrel/SigThief) Stealing Signatures and Making One Invalid Signature at a Time. 
-   [**Veil**](https://github.com/Veil-Framework/Veil) is a tool designed to generate metasploit payloads that bypass common anti-virus solutions. 
-   [**CheckPlease**](https://github.com/Arvanaghi/CheckPlease) Sandbox evasion modules written in PowerShell, Python, Go, Ruby, C, C#, Perl, and Rust.
-   **[Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage)** is a tool to embeded a PowerShell script in the pixels of a PNG file and generates a oneliner to execute. 
-   [**LuckyStrike**](https://github.com/curi0usJack/luckystrike) a PowerShell based utility for the creation of malicious Office macro documents. To be used for pentesting or educational purposes only. 
-   [**ClickOnceGenerator**](https://github.com/Mr-Un1k0d3r/ClickOnceGenerator) Quick Malicious ClickOnceGenerator for Red Team. The default application a simple WebBrowser widget that point to a website of your choice. 
-   **[macro\_pack](https://github.com/sevagas/macro_pack)** is a tool by @EmericNasi used to automatize obfuscation and generation of MS Office documents, VB scripts, and other formats for pentest, demo, and social engineering assessments. 
-   [**StarFighters**](https://github.com/Cn33liz/StarFighters) a JavaScript and VBScript Based Empire Launcher. 
-   **[nps\_payload](https://github.com/trustedsec/nps_payload)** this script will generate payloads for basic intrusion detection avoidance. It utilizes publicly demonstrated techniques from several different sources. 
-   [**SocialEngineeringPayloads**](https://github.com/trustedsec/nps_payload) a collection of social engineering tricks and payloads being used for credential theft and spear phishing attacks. 
-   **[The Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)** is an open-source penetration testing framework designed for social engineering. 
-   [**Phishery**](https://github.com/ryhanson/phishery) is a Simple SSL Enabled HTTP server with the primary purpose of phishing credentials via Basic Authentication. 
-   [**PowerShdll**](https://github.com/p3nt4/PowerShdll) run PowerShell with rundll32. Bypass software restrictions. 
-   **[Ultimate AppLocker ByPass List](https://github.com/api0cradle/UltimateAppLockerByPassList)** The goal of this repository is to document the most common techniques to bypass AppLocker. 
-   [**Ruler**](https://github.com/sensepost/ruler) is a tool that allows you to interact with Exchange servers remotely, through either the MAPI/HTTP or RPC/HTTP protocol. 
-   **[Generate-Macro](https://github.com/enigma0x3/Generate-Macro)** is a standalone PowerShell script that will generate a malicious Microsoft Office document with a specified payload and persistence method. 
-   **[Malicious Macro MSBuild Generator](https://github.com/infosecn1nja/MaliciousMacroMSBuild)** Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass. 
-   **[Meta Twin](https://github.com/threatexpress/metatwin)** is designed as a file resource cloner. Metadata, including digital signature, is extracted from one file and injected into another. 
-   [**WePWNise**](https://github.com/mwrlabs/wePWNise) generates architecture-independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software. 
-   [**DotNetToJScript**](https://github.com/tyranid/DotNetToJScript) a tool to create a JScript file which loads a .NET v2 assembly from memory. 
-   [**PSAmsi**](https://github.com/cobbr/PSAmsi) is a tool for auditing and defeating AMSI signatures. 
-   [**Reflective DLL injection**](https://github.com/stephenfewer/ReflectiveDLLInjection) is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process. 
-   [**ps1encode**](https://github.com/CroweCybersecurity/ps1encode) use to generate and encode a powershell based metasploit payloads. 
-   **[Worse PDF](https://github.com/3gstudent/Worse-PDF)** turn a normal PDF file into malicious. Use to steal Net-NTLM Hashes from windows machines. 
-   [**SpookFlare**](https://github.com/hlldz/SpookFlare) has a different perspective to bypass security measures and it gives you the opportunity to bypass the endpoint countermeasures at the client-side detection and network-side detection. 
-   [**GreatSCT**](https://github.com/GreatSCT/GreatSCT) is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team. 
-   [**nps**](https://github.com/Ben0xA/nps) running powershell without PowerShell. 
-   **[Meterpreter\_Paranoid\_Mode.sh](https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL)** allows users to secure their staged/stageless connection for Meterpreter by having it check the certificate of the handler it is connecting to.
-   **[The Backdoor Factory (BDF)](https://github.com/secretsquirrel/the-backdoor-factory)** is to patch executable binaries with user desired shellcode and continue normal execution of the prepatched state. 
-   [**MacroShop**](https://github.com/khr0x40sh/MacroShop) a collection of scripts to aid in delivering payloads via Office Macros. 
-   [**UnmanagedPowerShell**](https://github.com/leechristensen/UnmanagedPowerShell) Executes PowerShell from an unmanaged process. 
-   **[evil-ssdp](https://gitlab.com/initstring/evil-ssdp)** Spoof SSDP replies to phish for [NTLM](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm) hashes on a network. Creates a fake UPNP device, tricking users into visiting a malicious phishing page. 
-   [**Ebowla**](https://github.com/Genetic-Malware/Ebowla) Framework for Making Environmental Keyed Payloads. 
-   **[make-pdf-embedded](https://github.com/DidierStevens/DidierStevensSuite/blob/master/make-pdf-embedded.py)** a tool to create a PDF document with an embedded file. 
-   [**avet**](https://github.com/govolution/avet) (AntiVirusEvasionTool) is targeting windows machines with executable files using different evasion techniques. 
-   [**EvilClippy**](https://github.com/outflanknl/EvilClippy) A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows.
-   [**CallObfuscator**](https://github.com/d35ha/CallObfuscator) Obfuscate windows apis from static analysis tools and debuggers. 
-   [**Donut**](https://github.com/TheWover/donut) is a shellcode generation tool that creates position-independant shellcode payloads from .NET Assemblies. This shellcode may be used to inject the Assembly into arbitrary Windows processes. 

### [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#phishing)**Phishing**

-   **[King Phisher](https://github.com/securestate/king-phisher)** is a tool for testing and promoting user awareness by simulating real-world phishing attacks.
-   [**FiercePhish**](https://github.com/Raikia/FiercePhish) is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more. 
-   [**ReelPhish**](https://github.com/fireeye/ReelPhish/) is a Real-Time Two-Factor Phishing Tool.
-   [**Gophish**](https://github.com/gophish/gophish) is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily set up and execute phishing engagements and security awareness training.
-   [**CredSniper**](https://github.com/ustayready/CredSniper) is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens. 
-   [**PwnAuth**](https://github.com/fireeye/PwnAuth) is a web application framework for launching and managing OAuth abuse campaigns.
-   **[Phishing Frenzy](https://github.com/pentestgeek/phishing-frenzy)** Ruby on Rails Phishing Framework.
-   **[Phishing Pretexts](https://github.com/L4bF0x/PhishingPretexts)** are a library of pretexts to use on offensive phishing engagements. 
-   [**Modlishka**](https://github.com/drk1wi/Modlishka) is a flexible and powerful reverse proxy, that will take your ethical phishing campaigns to the next level.
-   [**Evilginx2**](https://github.com/kgretzky/evilginx2) is a man-in-the-middle attack framework for phishing credentials and session cookies of any web service.

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#watering-hole-attack)**Watering Hole Attack**

-   [**BeEF**](https://github.com/beefproject/beef) is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#command-and-control)**Command and Control**

### [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#remote-access-tools)Remote Access Tools

-   **[Cobalt Strike](https://cobaltstrike.com/)** is software for Adversary Simulations and [Red Team Operations](https://cybersecuritynews.com/red-team-and-blue-team/). 
-   [**Empire**](https://github.com/EmpireProject/Empire) is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent. 
-   **[Metasploit Framework](https://github.com/rapid7/metasploit-framework)** is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. 
-   [**SILENTTRINITY**](https://github.com/byt3bl33d3r/SILENTTRINITY) A post-exploitation agent powered by Python, IronPython, C#/.NET. 
-   [**Pupy**](https://github.com/n1nj4sec/pupy) is an opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python.
-   [**Koadic**](https://github.com/zerosum0x0/koadic) or COM Command & Control, is a Windows post-exploitation rootkit similar to other [penetration testing tools](https://cybersecuritynews.com/penetration-testing-tools/) such as Meterpreter and Powershell Empire.
-   [**PoshC2**](https://github.com/nettitude/PoshC2_Python) is a proxy aware C2 framework written completely in PowerShell to aid penetration testers with red teaming, post-exploitation and lateral movement.
-   [**Merlin**](https://github.com/Ne0nd0g/merlin) is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang. 
-   [**Quasar**](https://github.com/quasar/QuasarRAT) is a fast and light-weight remote administration tool coded in C#. Providing high stability and an easy-to-use user interface, Quasar is the perfect remote administration solution for you. 
-   [**Covenant**](https://github.com/cobbr/Covenant) is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers.
-   [**FactionC2**](https://github.com/FactionC2/) is a C2 framework which use websockets based API that allows for interacting with agents and transports.
-   [**DNScat2**](https://github.com/iagox86/dnscat2) is a tool is designed to create an encrypted [command-and-control](https://cybersecuritynews.com/command-and-controlc2-server/) (C&C) channel over the DNS protocol.
-   [**Sliver**](https://github.com/BishopFox/sliver) is a general purpose cross-platform implant framework that supports C2 over Mutual-TLS, HTTP(S), and DNS. 
-   [**EvilOSX**](https://github.com/Marten4n6/EvilOSX) An evil RAT (Remote Administration Tool) for macOS / OS X. 
-   [**EggShell**](https://github.com/neoneggplant/EggShell) is a post exploitation surveillance tool written in Python. It gives you a command line session with extra functionality between you and a target machine.
-   [**Gcat**](https://github.com/byt3bl33d3r/gcat) a stealthy Python based backdoor that uses Gmail as a command and control server.
-   [**TrevorC2**](https://github.com/trustedsec/trevorc2) is a legitimate website (browsable) that tunnels client/server communications for covert command execution.

### [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#staging)**Staging**

-   **[Rapid Attack Infrastructure (RAI)](https://github.com/obscuritylabs/RAI)** Red Team Infrastructure… Quick… Fast… Simplified One of the most tedious phases of a Red Team Operation is usually the infrastructure setup. This usually entails a teamserver or controller, domains, redirectors, and a Phishing server. 
-   **[Red Baron](https://github.com/byt3bl33d3r/Red-Baron)** is a set of modules and custom/third-party providers for Terraform which tries to automate creating resilient, disposable, secure and agile infrastructure for Red Teams. 
-   [**EvilURL**](https://github.com/UndeadSec/EvilURL) generate unicode evil domains for IDN Homograph Attack and detect them.
-   [**Domain Hunter**](https://github.com/threatexpress/domainhunter) checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for phishing and C2 domain names. 
-   [**PowerDNS**](https://github.com/mdsecactivebreach/PowerDNS) is a simple proof of concept to demonstrate the execution of PowerShell script using DNS only.
-   [**Chameleon**](https://github.com/mdsecactivebreach/Chameleon) a tool for evading Proxy categorisation. 
-   [**CatMyFish**](https://github.com/Mr-Un1k0d3r/CatMyFish) Search for categorized domain that can be used during red teaming engagement. Perfect to setup whitelisted domain for your Cobalt Strike beacon C&C. 
-   **[Malleable C2](https://github.com/rsmudge/Malleable-C2-Profiles)** is a domain specific language to redefine indicators in Beacon’s communication. 
-   **[Malleable-C2-Randomizer](https://github.com/bluscreenofjeff/Malleable-C2-Randomizer)** This script randomizes Cobalt Strike Malleable C2 profiles through the use of a metalanguage, hopefully reducing the chances of flagging signature-based detection controls.
-   [**FindFrontableDomains**](https://github.com/rvrsh3ll/FindFrontableDomains) search for potential frontable domains. 
-   **[Postfix-Server-Setup](https://github.com/n0pe-sled/Postfix-Server-Setup)** Setting up a phishing server is a very long and tedious process. It can take hours to setup, and can be compromised in minutes. 
-   [**DomainFrontingLists**](https://github.com/vysec/DomainFrontingLists) a list of Domain Frontable Domains by CDN.
-   **[Apache2-Mod-Rewrite-Setup](https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup)** Quickly Implement Mod-Rewrite in your infastructure.
-   [**mod\_rewrite rule**](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10) to evade vendor sandboxes. 
-   **[external\_c2 framework](https://github.com/Und3rf10w/external_c2_framework)** a python framework for usage with Cobalt Strike’s External C2. 
-   **[Malleable-C2-Profiles](https://github.com/xx0hcd/Malleable-C2-Profiles)** A collection of profiles used in different projects using [Cobalt Strike](https://www.cobaltstrike.com/) 
-   [**ExternalC2**](https://github.com/ryhanson/ExternalC2) a library for integrating communication channels with the Cobalt Strike External C2 server. 
-   [**cs2modrewrite**](https://github.com/threatexpress/cs2modrewrite) a tools for convert Cobalt Strike profiles to modrewrite scripts.
-   [**e2modrewrite**](https://github.com/infosecn1nja/e2modrewrite) a tools for convert Empire profiles to Apache modrewrite scripts. 
-   [**redi**](https://github.com/taherio/redi) automated script for setting up CobaltStrike redirectors (nginx reverse proxy, letsencrypt). 
-   **[cat-sites](https://github.com/audrummer15/cat-sites)** Library of sites for categorization. 
-   [**ycsm**](https://github.com/infosecn1nja/ycsm) is a quick script installation for resilient redirector using nginx reverse proxy and letsencrypt compatible with some popular Post-Ex Tools (Cobalt Strike, Empire, Metasploit, PoshC2).
-   **[Domain Fronting Google App Engine](https://github.com/redteam-cyberark/Google-Domain-fronting)**.
-   [**DomainFrontDiscover**](https://github.com/peewpw/DomainFrontDiscover) Scripts and results for finding domain frontable CloudFront domains.
-   **[Automated Empire Infrastructure](https://github.com/bneg/RedTeam-Automation)** 
-   **[Serving Random Payloads](https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9)** with NGINX. 
-   [**meek**](https://github.com/arlolra/meek) is a blocking-resistant pluggable transport for Tor. It encodes a data stream as a sequence of HTTPS requests and responses.
-   **[CobaltStrike-ToolKit](https://github.com/killswitch-GUI/CobaltStrike-ToolKit)** Some useful scripts for CobaltStrike. 
-   [**mkhtaccess\_red**](https://github.com/violentlydave/mkhtaccess_red) Auto-generate an HTaccess for payload delivery — automatically pulls ips/nets/etc from known sandbox companies/sources that have been seen before, and redirects them to a benign payload. 
-   [**RedFile**](https://github.com/outflanknl/RedFile) a flask wsgi application that serves files with intelligence, good for serving conditional RedTeam payloads. 
-   [**keyserver**](https://github.com/leoloobeek/keyserver) Easily serve HTTP and DNS keys for proper payload protection. 
-   [**DoHC2**](https://github.com/SpiderLabs/DoHC2) allows the [ExternalC2](https://github.com/ryhanson/ExternalC2) library from Ryan Hanson to be leveraged for command and control (C2) via DNS over HTTPS (DoH). This is built for the popular Adversary Simulation and Red Team Operations Software Cobalt Strike
-   [**HTran**](https://github.com/HiwinCN/HTran) is a connection bouncer, a kind of proxy server. A “listener” program is hacked stealthily onto an unsuspecting host anywhere on the Internet. 

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#lateral-movement)**Lateral Movement**

-   [**CrackMapExec**](https://github.com/byt3bl33d3r/CrackMapExec) is a swiss army knife for pentesting networks. 
-   [**PowerLessShell**](https://github.com/Mr-Un1k0d3r/PowerLessShell) rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe.
-   [**GoFetch**](https://github.com/GoFetchAD/GoFetch) is a tool to automatically exercise an attack plan generated by the BloodHound application.
-   [**ANGRYPUPPY**](https://github.com/vysec/ANGRYPUPPY) a bloodhound attack path automation in CobaltStrike. 
-   [**DeathStar**](https://github.com/byt3bl33d3r/DeathStar) is a Python script that uses Empire’s RESTful API to automate gaining Domain Admin rights in Active Directory environments using a variety of techinques. 
-   [**SharpHound**](https://github.com/BloodHoundAD/SharpHound) C# Rewrite of the BloodHound Ingestor.
-   [**BloodHound.py**](https://github.com/fox-it/BloodHound.py) is a Python based ingestor for BloodHound, based on Impacket. 
-   [**Responder**](https://github.com/SpiderLabs/Responder) is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
-   [**SessionGopher**](https://github.com/fireeye/SessionGopher) is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.
-   [**PowerSploit**](https://github.com/PowerShellMafia/PowerSploit) is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. 
-   [**Nishang**](https://github.com/samratashok/nishang) is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing. 
-   [**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) is a Windows PowerShell LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool. 
-   [**PowerUpSQL**](https://github.com/NetSPI/PowerUpSQL) a PowerShell Toolkit for Attacking SQL Server.
-   [**MailSniper**](https://github.com/dafthack/MailSniper) is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.). 
-   [**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) is a tool written in PowerShell to perform a password spray attack against users of a domain. 
-   [**WMIOps**](https://github.com/ChrisTruncer/WMIOps) is a powershell script that uses WMI to perform a variety of actions on hosts, local or remote, within a Windows environment. It’s designed primarily for use on penetration tests or red team engagements. 
-   [**Mimikatz**](https://github.com/gentilkiwi/mimikatz) is an open-source utility that enables the viewing of credential information from the Windows lsass.
-   [**LaZagne**](https://github.com/AlessandroZ/LaZagne) project is an open source application used to retrieve lots of passwords stored on a local computer. 
-   [**mimipenguin**](https://github.com/huntergregal/mimipenguin) a tool to dump the login password from the current linux desktop user. Adapted from the idea behind the popular Windows tool mimikatz.
-   [**PsExec**](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software. 
-   [**KeeThief**](https://github.com/HarmJ0y/KeeThief) allows for the extraction of KeePass 2.X key material from memory, as well as the backdooring and enumeration of the KeePass trigger system. 
-   [**PSAttack**](https://github.com/jaredhaight/PSAttack) combines some of the best projects in the infosec powershell community into a self contained custom PowerShell console. 
-   **[Internal Monologue Attack](https://github.com/eladshamir/Internal-Monologue)** Retrieving NTLM Hashes without Touching LSASS. 
-   [**Im**](https://github.com/CoreSecurity/impacket)**[p](https://github.com/CoreSecurity/impacket)**[**acket**](https://github.com/CoreSecurity/impacket) is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (for instance NMB, SMB1-3 and MS-DCERPC) the protocol implementation itself. 
-   [**icebreaker**](https://github.com/DanMcInerney/icebreaker) gets plaintext Active Directory credentials if you’re on the internal network but outside the AD environment. 
-   **[Living Off The Land Binaries and Scripts](https://github.com/api0cradle/LOLBAS) (and now also Libraries)** The goal of these lists are to document every binary, script and library that can be used for other purposes than they are designed to. 
-   [**WSUSpendu**](https://github.com/AlsidOfficial/WSUSpendu) for compromised WSUS server to extend the compromise to clients. 
-   [**Evilgrade**](https://github.com/infobyte/evilgrade) is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates. 
-   [**NetRipper**](https://github.com/NytroRST/NetRipper) is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption. 
-   [**LethalHTA**](https://github.com/codewhitesec/LethalHTA) Lateral Movement technique using DCOM and HTA.
-   **[Invoke-PowerThIEf](https://github.com/nettitude/Invoke-PowerThIEf)** an Internet Explorer Post Exploitation library.
-   [**RedSnarf**](https://github.com/nccgroup/redsnarf) is a pen-testing / red-teaming tool for Windows environments. 
-   [**HoneypotBuster**](https://github.com/JavelinNetworks/HoneypotBuster) Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host. 
-   [**PAExec**](https://www.poweradmin.com/paexec/) lets you launch Windows programs on remote Windows computers without needing to install software on the remote computer first. 

-   [**Tunna**](https://github.com/SECFORCE/Tunna) is a set of tools which will wrap and tunnel any TCP communication over HTTP. It can be used to bypass network restrictions in fully firewalled environments. 
-   [**reGeorg**](https://github.com/sensepost/reGeorg) the successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn. 
-   [**Blade**](https://github.com/wonderqs/Blade) is a webshell connection tool based on console, currently under development and aims to be a choice of replacement of Chooper. 
-   [**TinyShell**](https://github.com/threatexpress/tinyshell) Web Shell Framework.
-   [**PowerLurk**](https://github.com/Sw4mpf0x/PowerLurk) is a PowerShell toolset for building malicious WMI Event Subsriptions. 
-   [**DAMP**](https://github.com/HarmJ0y/DAMP) The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.

**Domain Escalation**

[**PowerView**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) is a PowerShell tool to gain network situational awareness on Windows domains.

[**Get-GPPPassword**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences. 

[**Invoke-ACLpwn**](https://github.com/fox-it/Invoke-ACLPwn) is a tool that automates the discovery and pwnage of ACLs in Active Directory that are unsafe configured. 

[![web](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjk33Km-slMbOcmnmR7jMjZHgp79mf8FurnLnp0gCLWogBSXqzRvh6Ea5L-W2ap895eV5cMwSfcmMTlpd9hCBrLMuL5n9xmrKhhgirtz58_xMTNQrF7H13NdrDJKlzWt_uZcL_JDFev8kfJZO0hpWSd6halRSoUKoWm7Xk_YeBRpJCh_mDw7BBnTth2Ow/s16000/gartner-300x250.png)](https://www.indusface.com/gartner-peer-insights-voc-web-application-and-api-protection-2023.php?utm_source=cybersecuritynews&utm_medium=ppc&utm_campaign=gartner-2023)

[**BloodHound**](https://github.com/BloodHoundAD/BloodHound) uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. 

[**PyKEK**](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) (Python Kerberos Exploitation Kit), a python library to manipulate KRB5-related data. 

[**Grouper**](https://github.com/l0ss/Grouper) a PowerShell script for helping to find vulnerable settings in AD Group Policy. 

[**ADRecon**](https://github.com/sense-of-security/ADRecon) is a tool which extracts various artifacts (as highlighted below) out of an AD environment in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis. 

[**ADACLScanner**](https://github.com/canix1/ADACLScanner) one script for ACL’s in Active Directory. 

[**ACLight**](https://github.com/cyberark/ACLight) a useful script for advanced discovery of Domain Privileged Accounts that could be targeted – including Shadow Admins. 

[**LAPSToolkit**](https://github.com/leoloobeek/LAPSToolkit) a tool to audit and attack LAPS environments. 

[**PingCastle**](https://www.pingcastle.com/download) is a free, Windows-based utility to audit the risk level of your AD infrastructure and check for vulnerable practices.

[**RiskySPNs**](https://github.com/cyberark/RiskySPN) is a collection of PowerShell scripts focused on detecting and abusing accounts associated with SPNs (Service Principal Name). 

[**Mystique**](https://github.com/machosec/Mystique) is a PowerShell tool to play with Kerberos S4U extensions, this module can assist blue teams to identify risky Kerberos delegation configurations as well as red teams to impersonate arbitrary users by leveraging KCD with Protocol Transition. 

[**Rubeus**](https://github.com/GhostPack/Rubeus) is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpy’s Kekeo project. 

[**kekeo**](https://github.com/gentilkiwi/kekeo) is a little toolbox I have started to manipulate Microsoft Kerberos in C (and for fun). 

[](https://github.com/infosecn1nja/Red-Teaming-Toolkit#local-escalation)**Local Escalation**

[**UACMe**](https://github.com/hfiref0x/UACME) is an open source assessment tool that contains many methods for bypassing Windows User Account Control on multiple versions of the operating system. 

**[windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)** a collection windows kernel exploit. 

[**PowerUp**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations. 

**[The Elevate Kit](https://github.com/rsmudge/ElevateKit)** demonstrates how to use third-party privilege escalation attacks with Cobalt Strike’s Beacon payload. 

[**Sherlock**](https://github.com/rasta-mouse/Sherlock) a powerShell script to quickly find missing software patches for local privilege escalation vulnerabilities. 

[**Tokenvator**](https://github.com/0xbadjuju/Tokenvator) a tool to elevate privilege with Windows Tokens. 

**[CloakifyFactory](https://github.com/TryCatchHCF/Cloakify)** & the Cloakify Toolset – Data Exfiltration & Infiltration In Plain Sight; Evade DLP/MLS Devices; Social Engineering of Analysts; Defeat Data Whitelisting Controls; Evade AV Detection. 

[**DET**](https://github.com/sensepost/DET) (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time. 

[**DNSExfiltrator**](https://github.com/Arno0x/DNSExfiltrator) allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.

[**PyExfil**](https://github.com/ytisf/PyExfil) a Python Package for Data Exfiltration. 

**[Egress-Assess](https://github.com/ChrisTruncer/Egress-Assess)** is a tool used to test egress data detection capabilities.

**[Powershell RAT](https://github.com/Viralmaniar/Powershell-RAT)** python based backdoor that uses Gmail to exfiltrate data as an e-mail attachment.

[](https://github.com/infosecn1nja/Red-Teaming-Toolkit#misc)**Misc**

[](https://github.com/infosecn1nja/Red-Teaming-Toolkit#adversary-emulation)**Adversary Emulation**

**[MITRE CALDERA](https://github.com/mitre/caldera)** – An automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks. 

[**APTSimulator**](https://github.com/NextronSystems/APTSimulator) – A Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.

[**Atomic Red Team**](https://github.com/redcanaryco/atomic-red-team) – Small and highly portable detection tests mapped to the Mitre ATT&CK Framework.

**Network Flight Simulator** – [flightsim](https://github.com/alphasoc/flightsim) is a lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility. 

[**Metta**](https://github.com/uber-common/metta) – A security preparedness tool to do adversarial simulation. 

**[Red Team Automation (RTA)](https://github.com/endgameinc/RTA)** – RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK. 

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#wireless-networks)**Wireless Networks**

[**Wifiphisher**](https://github.com/wifiphisher/wifiphisher) is a security tool that performs Wi-Fi automatic association attacks to force wireless clients to unknowingly connect to an attacker-controlled Access Point.

[**mana**](https://github.com/sensepost/mana) toolkit for wifi rogue AP attacks and MitM. 

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#embedded--peripheral-devices-hacking)**Embedded & Peripheral Devices Hacking**

[**magspoof**](https://github.com/samyk/magspoof) a portable device that can spoof/emulate any magnetic stripe, credit card or hotel card “wirelessly”, even on standard magstripe (non-NFC/RFID) readers. 

[**WarBerryPi**](https://github.com/secgroundzero/warberry) was built to be used as a hardware implant during red teaming scenarios where we want to obtain as much information as possible in a short period of time with being as stealth as possible. 

[**P4wnP1**](https://github.com/mame82/P4wnP1) is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W (required for HID backdoor).

[**malusb**](https://github.com/ebursztein/malusb) HID spoofing multi-OS payload for Teensy. 

[**Fenrir**](https://github.com/Orange-Cyberdefense/fenrir-ocd) is a tool designed to be used “out-of-the-box” for penetration tests and offensive engagements. Its main feature and purpose is to bypass wired 802.1x protection and to give you an access to the target network. 

[**poisontap**](https://github.com/samyk/poisontap) exploits locked/password protected computers over USB, drops persistent WebSocket-based backdoor, exposes internal router, and siphons cookies using Raspberry Pi Zero & Node.js. 

[**WHID**](https://github.com/whid-injector/WHID) WiFi HID Injector – An USB Rubberducky / BadUSB On Steroids. 

[**PhanTap**](https://github.com/nccgroup/phantap) is an ‘invisible’ network tap aimed at red teams. With limited physical access to a target building, this tap can be installed inline between a network device and the corporate network.

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#software-for-team-communication)**Software For Team Communication**

[**RocketChat**](https://rocket.chat/) is free, unlimited and open source. Replace email & Slack with the ultimate team chat software solution. 

[**Etherpad**](https://etherpad.org/) is an open source, web-based collaborative real-time editor, allowing authors to simultaneously edit a text document

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#log-aggregation)**Log Aggregation**

[**RedELK**](https://github.com/outflanknl/RedELK/) Red Team’s SIEM – easy deployable tool for Red Teams used for tracking and alarming about Blue Team activities as well as better usability in long term operations.

[**CobaltSplunk**](https://github.com/vysec/CobaltSplunk) Splunk Dashboard for CobaltStrike logs. 

**[Red Team Telemetry](https://github.com/ztgrace/red_team_telemetry)** A collection of scripts and configurations to enable centralized logging of red team infrastructure. 

**[Elastic for Red Teaming](https://github.com/SecurityRiskAdvisors/RedTeamSIEM)** Repository of resources for configuring a Red Team SIEM using Elastic.

[**Ghostwriter**](https://github.com/GhostManager/Ghostwriter) is a Django project written in Python 3.7 and is designed to be used by a team of operators. 

### [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#c-offensive-framework)**C# Offensive Framework**

-   [**SharpSploit**](https://github.com/cobbr/SharpSploit) is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers. 
-   [**GhostPack**](https://github.com/GhostPack) is (currently) a collection various C# implementations of previous PowerShell functionality, and includes six separate toolsets being released today- Seatbelt, SharpUp, SharpRoast, SharpDump, SafetyKatz, and SharpWMI. 
-   [**SharpWeb**](https://github.com/djhohnstein/SharpWeb) .NET 2.0 CLR project to retrieve saved browser credentials from Google Chrome, Mozilla Firefox and Microsoft Internet Explorer/Edge. 
-   [**reconerator**](https://github.com/stufus/reconerator) C# Targeted Attack Reconnissance Tools.
-   [**SharpView**](https://github.com/tevora-threat/SharpView) C# implementation of harmj0y’s PowerView.
-   [**Watson**](https://github.com/rasta-mouse/Watson) is a (.NET 2.0 compliant) C# implementation of Sherlock. 

### [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#labs)**Labs**

-   **[Detection Lab](https://github.com/clong/DetectionLab)** This lab has been designed with defenders in mind. Its primary purpose is to allow the user to quickly build a Windows domain that comes pre-loaded with security tooling and some best practices when it comes to system logging configurations. 
-   **[Modern Windows Attacks and Defense Lab](https://github.com/jaredhaight/WindowsAttackAndDefenseLab)** This is the lab configuration for the Modern Windows Attacks and Defense class that Sean Metcalf (@pyrotek3) and I teach.
-   [**Invoke-UserSimulator**](https://github.com/ubeeri/Invoke-UserSimulator) Simulates common user behaviour on local and remote Windows hosts. 
-   **[Invoke-ADLabDeployer](https://github.com/outflanknl/Invoke-ADLabDeployer)** Automated deployment of Windows and Active Directory test lab networks. Useful for red and blue teams. 
-   [**Sheepl**](https://github.com/SpiderLabs/sheepl) Creating realistic user behaviour for supporting tradecraft development within lab environments. 

## [](https://github.com/infosecn1nja/Red-Teaming-Toolkit#references)**References**

-   **[MITRE’s ATT&CK™](https://attack.mitre.org/wiki/Main_Page)** is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s lifecycle and the platforms they are known to target. 
-   **[Cheat](https://github.com/HarmJ0y/CheatSheets) [S](https://github.com/HarmJ0y/CheatSheets)[heets](https://github.com/HarmJ0y/CheatSheets)** for various projects (Beacon/Cobalt Strike,PowerView, PowerUp, Empire, and PowerSploit). 
-   **[PRE-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Main_Page)** Adversarial Tactics, Techniques & Common Knowledge for Left-of-Exploit. 
-   [**Adversary OPSEC**](https://attack.mitre.org/pre-attack/index.php/Adversary_OPSEC) consists of the use of various technologies or 3rd party services to obfuscate, hide, or blend in with accepted network traffic or system behavior. 
-   [**Adversary Emulation Plans**](https://attack.mitre.org/wiki/Adversary_Emulation_Plans) To showcase the practical use of ATT&CK for offensive operators and defenders, MITRE created Adversary Emulation Plans. 
-   [**Red-Team-Infrastructure-Wiki**](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki) Wiki to collect Red Team infrastructure hardening resources. 
-   **[Advanced Threat Tactics – Course and Notes](https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes)** This is a course on red team operations and adversary simulations. 
-   **[Red Team Tips](https://vincentyiu.co.uk/red-team-tips)** as posted by @vysecurity on Twitter. 
-   **[Awesome Red Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)** List of Awesome Red Team / Red Teaming Resources. 
-   **[APT & CyberCriminal Campaign Collection](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections)** This is a collection of APT and CyberCriminal campaigns. Please fire issue to me if any lost APT/Malware events/campaigns. 
-   [**ATT&CK for Enterprise Software**](https://attack.mitre.org/wiki/Software) is a generic term for custom or commercial code, operating system utilities, open-source software, or other tools used to conduct behavior modeled in ATT&CK. 
-   [**Planning a Red Team exercise**](https://github.com/magoo/redteam-plan) This document helps inform red team planning by contrasting against the very specific red team style described in Red Teams. 
-   **[Awesome Lockpicking](https://github.com/meitar/awesome-lockpicking)** a curated list of awesome guides, tools, and other resources related to the security and compromise of locks, safes, and keys. 
-   **[Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)** a curated list of awesome Threat Intelligence resources. 
-   **[APT Notes](https://github.com/aptnotes/data)** Need some scenario? APTnotes is a repository of publicly-available papers and blogs (sorted by year) related to malicious campaigns/activity/software that have been associated with vendor-defined APT (Advanced Persistent Threat) groups and/or tool-sets. 
-   [**TIBER-EU FRAMEWORK**](http://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf) The European Framework for Threat Intelligence-based Ethical Red Teaming (TIBER-EU), which is the first Europe-wide framework for controlled and bespoke tests against cyber attacks in the financial market.
-   [**CBEST Implementation Guide**](https://www.crest-approved.org/wp-content/uploads/2014/07/CBEST-Implementation-Guide.pdf) CBEST is a framework to deliver controlled, bespoke, intelligence-led cyber security tests. The tests replicate behaviours of threat actors, assessed by the UK Government and commercial intelligence providers as posing a genuine threat to systemically important financial institutions. 
-   [**Red Team: Adversarial Attack Simulation Exercise Guidelines for the Financial Industry in Singapore**](https://abs.org.sg/docs/library/abs-red-team-adversarial-attack-simulation-exercises-guidelines-v1-06766a69f299c69658b7dff00006ed795.pdf) The Association of Banks in Singapore (ABS), with support from the Monetary Authority of Singapore (MAS), has developed a set of cybersecurity assessment guidelines today to strengthen the cyber resilience of the financial sector in Singapore. Known as the Adversarial Attack Simulation Exercises (AASE) Guidelines or “Red Teaming” Guidelines, the Guidelines provide financial institutions (FIs) with best practices and guidance on planning and conducting Red Teaming exercises to enhance their security testing.

**S_ource & Credits: @infosecn1nja_**
