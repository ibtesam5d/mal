# Malware Analysis Report
Performed analysis on malware factura.doc which is labeled as “trojan” by VirusTotal. The analysis was done in a sandboxed LAB environment using a linux toolkit called Remnux. After performing static and emulated dynamic analysis, it was found that the malware uses “Microsoft Office Memory Corruption Vulnerability” and has a CVSS base score of 7.8 (High). Once executed the malware can run arbitrary code in the context of the current user. Most common file dropped as a result of execution is aro.exe at the Application Data folder.

## Steps Performed
- Static Analysis
- EEmulated Dynamic Analysis
- VirusTotal Comparison
- Results and Remediations

## Tools used
- Remnux
- rtfdump
- rtfobj
- oledump
- xxd
- scdbg
- VirusTotal

## Rsult and Remediations
After the analysis it is no doubt that the malware sample is highly dangerous with a CVSS score of 7.8. It is a “trojan” which is also threatening to the enterprise environment. Additionally, the malware is associated with Microsoft Office Applications such as Word, Excel etc.

### Findings:
- Malware type: “trojan”
- Files dropped: aro.exe
- Malware Communicated to: seed-bc[.]com
- IP Address: 185.36.74.48
- VirusTotal score: 43/59
- Registry used: Microsoft Equation 3.0
- CVE: 2017-11882, 2018-0802
- SHA256 Hash: 5a31c77293af2920d7020d5d0236691adcea2c57c2716658ce118a5cba9d4913

### Remediations
- All office applications should be updated to the latest version
- IP address should be blocked at the firewall
- DNS of “seed-bc[.]com” should be blacklisted.
- User awareness training should be provided
- IDS/IPS rules should be updated to watch for IOCs

