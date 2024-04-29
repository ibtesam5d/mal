# Malware Analysis Report
Conducted an in-depth analysis of the malware "factura.doc," identified as a "trojan" by VirusTotal. Utilized a sandboxed LAB environment facilitated by the Remnux Linux toolkit to perform comprehensive static and emulated dynamic analyses. Findings revealed the exploitation of the "Microsoft Office Memory Corruption Vulnerability," resulting in a CVSS base score of 7.8 (High). It was determined that upon execution, the malware exhibits the capability to execute arbitrary code within the current user's context. Notably, the most common file dropped post-execution was identified as "aro.exe," typically located in the Application Data folder.
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

