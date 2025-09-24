# ITSEC-Report
Report of a scan conducted on given Targeted website, task given by ACCUKNOX


Vulnerability Report on www.itsecgames.com 

 

Done by 

Nanepalli Leela Murali Krishna 

Task Assigned by 

Accuknox 

 

Date – 23rd September 2025 

 

AIM :- 

As a part of interview process the task assigned to me is to scan and view the vulnerabilities on given web address which is open source for enthusiasts to scan and learn about vulnerabilities, also provide the outputs gathered by the tools used for scanning and get the TLS/SSL Certificate's health . 
The given web address :- http://www.itsecgames.com 
 

PLANNED PROCEDURE:- 

To use Ping and learn the IP address of the website 
To use Nmap to learn about the open Ports  
To use OpenVAS to scan and gather detailed Vulnerability Report 
To use NIKTO to scan for CGI’s 
To use Qualy’s open source tool to get SSL/TLS health 
Pushing the results to GIT 
 

 

 

 

EXECUTION: - (The whole problem is done in Kali LInux) 

 

   Step – 1 

Updated the KALI resources  
Found the IP address for the given target website using ICMP Ping 
 Command Used : ping www.itsecgames.com 
Resulted us with an IPV4 address i.e 31.3.96.40 
 

 Step – 2  

Used Nmap Tool 
 
NMAP BRIEF :  
Nmap (Network Mapper) is an open-source network scanner used to discover hosts and services on a computer network. It maps the network by sending crafted packets and analyzing responses. 

What it does (quick list) 

Host discovery — finds which IPs are up (ping sweeps). 
Port scanning — identifies open/closed/filtered TCP/UDP ports. 
Service/version detection — determines which service (and often its version) is running on an open port. 
OS detection — guesses the target’s operating system and device type. 
Scriptable checks — runs NSE (Nmap Scripting Engine) scripts for vulnerability detection, brute forcing, info gathering, and more. 
Timing & evasion — adjustable timing templates (e.g., -T4) and options to control speed/noisiness. 
Flexible output — plain, greppable, XML, and HTML-friendly outputs for reports. 
 
       
 
 
 
 
  -->  Command i used  
                                                  nmap -p- -sV —script=vuln* ip T4  

         Command Breakdown 

    - nmap – Triggers Nmap Tool  

    - -p- Scans all TCP and UDP ports 

    - -sV scans the versions of the services that are runninng on the Ports 

    - script=vuln* - Runs Nmap Script Engine for finding scripts whose name contain Vuln * means all  

    - T4 – Tells the nmap scan to be aggressive 

 

--> Time Taken – Around 2 Hours 

--> Results are gathered and forwarded to txt file I'e uploaded to this link  

Link : -  https://drive.google.com/drive/folders/15fAC9kJCQuc3O6BInK9m_NAml8XV38de?usp=sharing 

 

Step – 3 

--> Using OpenVAS tool 

OPEN-VAS brief - OpenVAS (Open Vulnerability Assessment System) is an open-source vulnerability scanner that detects security issues in networked systems by running thousands of regularly updated tests (NVTs). It is part of the Greenbone Vulnerability Management (GVM) framework, which includes the scanner, a manager for scheduling and reporting, and a web-based interface (GSA) for easy use. OpenVAS supports both unauthenticated and authenticated scans, allowing it to identify CVEs, misconfigurations, and missing patches, while generating detailed reports with severity scores and remediation advice. Though powerful and free, it can be resource-intensive, produce false positives if not tuned, and must be used only on systems you own or have permission to test. 

--> Used Pre-Installed GVM-Setup 

--> Assigned the task to scan the specified IP address 

--> Started the Task by configuring the scan model  

--> Results are downloaded and saved as reports 

--> Time Taken is around 2 Hours 

Report Link : -  https://drive.google.com/drive/folders/15fAC9kJCQuc3O6BInK9m_NAml8XV38de?usp=sharing 

 

 - Step 4  

Using NIKTO 

 NIKTO brief Nikto is an open-source web vulnerability scanner that tests web servers for security issues such as outdated software, dangerous files, misconfigurations, and common vulnerabilities. It performs comprehensive checks, including identifying default files, CGI scripts, SSL/TLS weaknesses, and server-specific problems. While Nikto is easy to use and effective for quick assessments, it is very noisy, easily detected by intrusion systems, and may generate false positives. It’s best used for initial reconnaissance and should only be run against systems you own or have permission to test. 

--> Here In this problem – I used nikto to Scan for the Common Gateway interfaces to scan for the common directories   

--> Command used – nikto –h ip –cgidirs  

Command BreakDown  

Nikto – Triggers Nikto Tools 

-h – speciffies the host address to the tool 

-cgidirs – scans and share the CGI’s 

 

--> Time taken:- 1 hour 

--> Results are gathered and directed to a text file  
 
Result Link: -  https://drive.google.com/drive/folders/15fAC9kJCQuc3O6BInK9m_NAml8XV38de?usp=sharing 

 

Step – 5 

--> Used an open-source tool called Qualy’s SSL Lab test 

--> This is one of the most famous labs to test SSL/TLS certs  

--> Time Taken – Around 4 Minutes 

--> Results are downloaded through HTML page capture 

Result Link –  https://drive.google.com/drive/folders/15fAC9kJCQuc3O6BInK9m_NAml8XV38de?usp=sharing 

 

 

My Detailed Overview of the Scan 

 

 

 

Executive summary 

Total actionable findings (shown): 6 (0 High, 3 Medium, 3 Low).  
  

Top risks to address immediately: 
Expired SSL/TLS certificate (443/tcp) — breaks trust, prevents secure connections and may allow downgrade attacks or man-in-the-middle in some client setups.  
  

Deprecated TLS protocols enabled (TLS 1.0 / 1.1) (443/tcp) — known crypto weaknesses and compatibility with old attack techniques.  
  

Weak SSH host key algorithm (ssh-dss) (22/tcp) — weak key type; should be removed.  
  

Goal of this report: produce a concise vulnerability inventory (title, severity, description), realistic exploitation scenarios, and precise mitigations prioritized into Immediate / Short-term / Long-term actions, plus monitoring and validation steps. All findings below are taken from the uploaded OpenVAS PDF.  

  

 

Vulnerability inventory (per finding) 

Note: each finding entry includes detection metadata and a practical exploitability + mitigation section. 

 

1) SSL/TLS: Certificate Expired 

Severity: Medium (CVSS ~5.0). 
Service / Port: 443/tcp (HTTPS). 
Detected: Certificate expired 2025-05-22 09:07:54 UTC. Details: RSA 2048-bit, issuer CN=web.mmebvba.com(subject same), SHA-256 signature.  
  

How it can be exploited / risks 

Clients will refuse or warn about the certificate; users may accept insecurely (social engineering). 
Expired certs allow attackers on the network to attempt SSL/TLS downgrade or intercept if clients ignore warnings. 
Browser and API clients may stop connecting, breaking availability and causing data/transaction failures. 
Practical exploitation scenario 

Attacker on same network performs a MitM and leverages client acceptance (or a client with lax validation) to intercept traffic or inject content. Even when the attacker cannot forge a valid cert, many users or automated clients will bypass warnings. 
Recommended mitigation (Immediate) 

Replace the certificate immediately — obtain a new certificate from a trusted CA (e.g., Let's Encrypt) and install it on the webserver. Ensure SANs cover all hostnames used.  
  

Verify full certificate chain and ensure intermediate certs are present. 
Implementation notes / commands (examples) 

Generate CSR & key, install new cert; for Let’s Encrypt use certbot with your webserver plugin (e.g., certbot --apache or --nginx) or ACME client if using another server. 
After installing, restart web server and check with openssl s_client -connect web.mmebvba.com:443 -showcerts and an online SSL checker. 
Validation 

Re-scan after replacement and confirm valid from / valid until dates and chain correct. Test browsers and API clients.  
 

2) SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection 

Severity: Medium (CVSS ~4.3). 
Service / Port: 443/tcp (HTTPS). 
Detected: Server supports TLS 1.0 and/or TLS 1.1 in addition to newer versions.  
  

How it can be exploited / risks 

TLS 1.0/1.1 have multiple known weaknesses (e.g., BEAST, FREAK) and no longer receive updates. Attackers can attempt to downgrade or exploit protocol-specific flaws to decrypt or manipulate traffic. 
Clients negotiating older protocol versions may be downgraded, enabling replay/cryptanalysis attacks or weaker cipher suites. 
Practical exploitation scenario 

Attacker forces protocol downgrade to TLS 1.0 and exploits a known weakness (e.g., BEAST) to recover parts of session plaintext or cookies in custom-attack scenarios. 
Recommended mitigation (Immediate → Short-term) 

Disable TLS 1.0 and TLS 1.1 entirely on the server; allow TLS 1.2 and TLS 1.3 only.  
  

Configure server to prefer strong ciphers (AES-GCM, CHACHA20-POLY1305 for TLS1.2/1.3) and enable forward secrecy (ECDHE). 
Use recommended TLS configuration templates (e.g., Mozilla SSL Configuration Generator) and test with SSL Labs / openssl scans. 
Implementation notes 

For Apache: adjust SSLProtocol -all +TLSv1.2 +TLSv1.3 and update SSLCipherSuite to modern suites. 
For Nginx: ssl_protocols TLSv1.2 TLSv1.3; and set ssl_ciphers appropriately. 
Check load balancers/CDNs if they terminate TLS — make changes there too. 
Validation 

Run an SSL/TLS scan (SSL Labs, testssl.sh) to confirm deprecated versions are disabled and score improves. 
(Detection reference: OpenVAS TLS version detection entry).  

  

 

3) Weak Host Key Algorithm(s) (SSH): ssh-dss 

Severity: Medium (CVSS ~5.3). 
Service / Port: 22/tcp (SSH). 
Detected: SSH server supports ssh-dss (DSA) host key type — considered weak/obsolete.  
  

How it can be exploited / risks 

DSA/ssh-dss uses smaller/legacy parameters that are no longer recommended; may be susceptible to cryptanalytic advances or implementation weaknesses. 
Host authenticity checks could be weakened if clients accept DSA keys, enabling spoofing of host identity if key recovery or collisions become practical. 
Practical exploitation scenario 

An attacker who can intercept SSH handshakes or obtain host key material might attempt to impersonate the server to clients that accept DSA host keys. 
Recommended mitigation (Immediate) 

Remove ssh-dss host keys from server configuration. Do not offer DSA host keys.  
  

Ensure server has at least one modern host key: ecdsa, ed25519, or RSA >= 2048 (prefer ed25519 or RSA 3072/4096). 
On OpenSSH, edit sshd_config to set HostKey lines only for allowed key files and optionally set PubkeyAcceptedKeyTypes / HostKeyAlgorithms to exclude ssh-dss. 
Implementation notes 

Regenerate host keys if needed: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key and restart sshd. 
Notify known clients that host keys changed (or rotate with care — you may experience host key verification warnings). 
Validation 

Re-run SSH algorithm detection (e.g., ssh -Q key remotely with an OpenVAS re-scan) to confirm ssh-dss not advertised. 
(Detection reference: OpenVAS SSH algorithm check).  

  

 

4) Weak MAC Algorithm(s) Supported (SSH): umac-64* 

Severity: Low (CVSS ~2.6). 
Service / Port: 22/tcp (SSH). 
Detected: Server advertises weak MAC algorithms: umac-64-etm@openssh.com, umac-64@openssh.com for both directions.  
  

How it can be exploited / risks 

64-bit MACs (message authentication codes) provide less collision resistance and increase risk for forging or undetected manipulation in extreme cases, particularly for very high-volume or persistent attackers. 
Modern best practice is larger MACs (e.g., HMAC-SHA2-256) or AEAD ciphers (chacha20-poly1305, AES-GCM). 
Practical exploitation scenario 

For a determined attacker with high-volume traffic or specific weaknesses, weaker MACs slightly lower the barrier for forging or recovering integrity data — mostly a long-term risk. 
Recommended mitigation (Short-term) 

Disable 64-bit MAC algorithms and configure server to advertise strong MACs: hmac-sha2-256, hmac-sha2-512or use AEAD ciphers.  
  

On OpenSSH, set MACs in sshd_config to modern values (or leave defaults if current OpenSSH version already prefers secure MACs). 
Validation 

Re-scan SSH algorithms and confirm only strong MACs are advertised. 
(Detection reference: OpenVAS SSH MAC check).  

  

 

5) ICMP Timestamp Reply Information Disclosure 

Severity: Low (CVSS ~2.1). 
Service / Protocol: general/icmp — host responded to ICMP Timestamp (Type 14 reply).  
  

How it can be exploited / risks 

ICMP timestamp replies reveal system time and could assist attackers in fingerprinting OS or computing time-based RNG seeds in vulnerable services. 
Enables passive reconnaissance (uptime, clock skew) and may help in more complex attacks. 
Recommended mitigation (Immediate → Short-term) 

Block or drop ICMP timestamp requests at the host or firewall (especially from untrusted networks).  
  

If ICMP is required for network management, restrict to trusted management networks only. 
Validation 

From an external host, confirm that ICMP timestamp requests no longer get replies. 
(Detection reference: OpenVAS ICMP timestamp detection).  

  

 

6) TCP Timestamps Information Disclosure 

Severity: Low (CVSS ~2.6). 
Service / Protocol: general/tcp — TCP timestamps enabled (RFC1323).  
  

How it can be exploited / risks 

TCP timestamps allow remote calculation of uptime and can aid in host fingerprinting and off-path attacks in some scenarios. They may also enable correlation of connections across NATs. 
Recommended mitigation (Short-term) 

Disable TCP timestamps if not required: on Linux sysctl -w net.ipv4.tcp_timestamps=0 and persist in /etc/sysctl.conf. On Windows modify TCP settings as documented.  
  

If disabling is not possible, use network devices to filter or rate-limit suspicious scan activity. 
Validation 

Confirm via remote TCP probe that timestamp option is not present in responses. 
(Detection reference: OpenVAS TCP timestamp detection).  

  

 

Prioritized remediation plan (actionable) 

Immediate (within 24 hours) 

Replace expired TLS certificate (finding 1). Verify chain and SANs. Test services and clients.  
  

Disable TLS 1.0 / 1.1 on any TLS-terminating host or appliance (finding 2). Apply strong cipher suites.  
  

Short-term (1–7 days) 

Remove ssh-dss host keys and regenerate modern host keys (ed25519 or RSA 3072/4096). Update sshd_configto prohibit ssh-dss. (finding 3).  
  

Disable weak SSH MACs (umac-64) — enforce modern MACs list (finding 4).  
  

Mid-term (1–4 weeks) 

Harden kernel/network settings: disable TCP timestamps if acceptable (finding 6) and block ICMP timestamp replies from untrusted networks (finding 5).  
  

Audit TLS termination points (load balancers, CDN, reverse proxies) to ensure consistent settings across the stack. 
Long-term / ongoing 

Implement automated certificate management (ACME/Let’s Encrypt or enterprise PKI automation) to prevent expiry. 
Create baseline configurations (SSH/TLS/Ciphers) and enforce via IaC (Ansible, Terraform) or configuration management. 
Schedule regular vulnerability scans (monthly) and continuous monitoring for TLS changes / certificate expiry alerts. 
 

Detection & validation checklist (what to run after fixes) 

SSL/TLS: openssl s_client -connect web.mmebvba.com:443 -servername web.mmebvba.com and use SSL Labs / testssl.sh. 
SSH: ssh -vvv user@web.mmebvba.com to see offered host key algorithms; run an OpenVAS/ssh-algorithms scanner. 
ICMP/TCP timestamps: use nmap --script tcp-timestamp / custom ping to confirm replies are suppressed. 
Re-run OpenVAS scan and compare results; confirm the six issues are remediated and no new regressions exist. (Reference: original OpenVAS findings).  
  

 

Monitoring & compensating controls 

WAF / IDS rules: Add signatures to detect TLS downgrade attempts and suspicious SSH handshake anomalies. 
Logging & Alerting: Alert on certificate expiry 30/14/7/1 days before expiry. Alert on SSH host key changes. 
Access controls: Limit SSH access to management networks, use jump hosts, and enforce key-based auth + MFA where supported. 
Patch & config drift: Enforce config drift detection (e.g., use CIS benchmarks + automated remediation). 
 

Appendix — Quick reference (detection metadata) 

Source report: OpenVAS PDF scan of web.mmebvba.com (31.3.96.40), scan window 21 Sep 2025 12:42–13:39 UTC. This PDF contains the detailed plugin outputs used above.  
  

Findings shown in the PDF (selected entries used above): 
Weak Host Key Algorithm(s) (ssh-dss) — 22/tcp.  
  

SSL/TLS: Certificate Expired — certificate expiry date 2025-05-22.  
  

SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection — 443/tcp.  
  

Weak MAC Algorithm(s) Supported (SSH) — umac-64 entries.  
  

ICMP Timestamp Reply — general/icmp.  
  

TCP Timestamps — general/tcp.  
  

 

 

 
     
