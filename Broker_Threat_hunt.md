# Threat Hunt Report — Operation: The Broker

**Organization:** Ashford Sterling Recruitment  
**Difficulty Rating:** Hard  
**Detection Platform:** Microsoft Defender for Endpoint / Microsoft Sentinel  
**Analyst:** Poshan Bhandari  
**Report Date:** 2026-03-06  

---

## Executive Summary

This report documents a complete adversary intrusion chain uncovered during the *The Broker* Cyber Range threat hunting engagement against Ashford Sterling Recruitment's simulated enterprise environment.

The threat actor demonstrated disciplined, **hands-on-keyboard** tradecraft throughout the operation. Initial access was achieved via a social engineering lure disguised as a recruitment document. From there, the attacker established persistent command-and-control, harvested credentials from local stores, moved laterally across three hosts using valid accounts, and accessed sensitive financial payment data before attempting to clean up forensic traces.

**Key Findings:**
- No single event was individually conclusive — the attack was identified through **behavioral pattern correlation across hosts and time**
- The attacker heavily abused **living-off-the-land binaries (LOLBins)** to blend with normal administrative activity
- **In-memory execution** was used to evade file-based detection and EDR scanning
- The attacker deployed **multiple overlapping persistence mechanisms** across all three endpoints

---

## Environment Overview

| Asset | Role | Primary Account |
|-------|------|----------------|
| AS-PC1 | Workstation | Sophie.Turner |
| AS-PC2 | Workstation | david.mitchell |
| AS-SRV | File Server | david.mitchell |

- **Monitoring Stack:** Microsoft Defender for Endpoint telemetry forwarded to Microsoft Sentinel
- **OS:** Windows enterprise environment (domain-joined)
- **Key Shares:** Financial data hosted on AS-SRV

---

## Attack Timeline

```
[T+0:00]  Double-extension .exe executed on AS-PC1 (Initial Access)
[T+0:02]  C2 beacon established to cloud-endpoint.net
[T+0:10]  Credential dump — SAM + SYSTEM hives staged in C:\Users\Public\
[T+0:15]  Host & network discovery (whoami, net view, net localgroup)
[T+0:25]  AnyDesk downloaded via certutil.exe, deployed to all three hosts
[T+0:40]  Lateral movement attempted via wmic.exe / psexec.exe — FAILED
[T+0:45]  Successful RDP pivot: AS-PC1 → AS-PC2 → AS-SRV
[T+1:00]  Scheduled task created: MicrosoftEdgeUpdateCheck
[T+1:05]  Backdoor account svc_backup created
[T+1:15]  Financial file BACS_Payments_Dec2025.ods accessed and edited
[T+1:20]  Data archived into Shares.7z
[T+1:30]  Security & System event logs cleared
[T+1:32]  SharpChrome loaded reflectively into notepad.exe
```

---

## Section 1: Initial Access

**MITRE ATT&CK:** T1204.002 — User Execution: Malicious File | T1036.007 — Masquerading: Double File Extension

### What Happened

The compromise began when a user on AS-PC1 executed a file named `daniel_richardson_cv.pdf.exe`. The double extension is a classic social engineering technique that exploits Windows' default behavior of hiding known file extensions, making the file appear as a harmless PDF to the victim.

Upon execution, the malware spawned `notepad.exe` with empty arguments as a decoy — simulating a failed document open — while silently establishing its foothold in the background.

### Indicators

| Indicator | Value |
|-----------|-------|
| Filename | `daniel_richardson_cv.pdf.exe` |
| SHA256 | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` |
| Parent Process | `explorer.exe` |
| Decoy Child Process | `notepad.exe ""` |
| Source Directory | `C:\Users\Sophie.Turner\Downloads\` |

### Analyst Notes

The use of a recruitment-themed lure against a recruitment firm is a targeted social engineering approach. The attacker clearly researched the victim organization and crafted a contextually plausible pretext, suggesting **initial reconnaissance** was performed prior to the delivery phase. The decoy Notepad window was intentional — it reassured the victim that nothing happened while the payload ran silently in the background.

---

## Section 2: Command & Control

**MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols | T1583.001 — Acquire Infrastructure: Domains

### What Happened

Following execution, the payload established outbound beaconing to attacker-controlled infrastructure using standard HTTPS traffic over port 443. The use of subdomains mimicking CDN and sync services (`cdn.cloud-endpoint.net`, `sync.cloud-endpoint.net`) was designed to blend into normal enterprise traffic patterns and avoid triggering domain-based detections.

Separate infrastructure at `download.anydesk.com` was used to stage follow-on tooling, demonstrating **operational compartmentalization** — a sign of disciplined adversary tradecraft where C2 and staging infrastructure are deliberately separated.

### Indicators

| Indicator | Value |
|-----------|-------|
| C2 Domain | `cloud-endpoint.net` |
| Observed Subdomains | `cdn.cloud-endpoint.net`, `sync.cloud-endpoint.net` |
| Staging Domain | `download.anydesk.com` |
| Beaconing Process | `daniel_richardson_cv.pdf.exe` |
| Protocol | HTTPS (TCP/443) |

### Analyst Notes

The domain `cloud-endpoint.net` had no legitimate business justification and was not present in the organization's known-good traffic baseline. Beaconing behavior — regular outbound connections at consistent intervals to the same remote destination — is a key behavioral signal that distinguishes C2 traffic from normal browsing. The deliberate choice of subdomain names (`cdn`, `sync`) reflects an attacker who anticipated proxy-based traffic inspection.

---

## Section 3: Credential Access

**MITRE ATT&CK:** T1003.002 — OS Credential Dumping: Security Account Manager

### What Happened

The attacker accessed the Windows registry hives `SAM` and `SYSTEM` to extract local credential material. When combined, these hives allow offline extraction of NTLM password hashes for all local user accounts. The extracted files were staged in `C:\Users\Public\` — a world-writable directory accessible to all accounts, commonly abused by attackers because it requires no elevated file permissions to write to.

### Indicators

| Indicator | Value |
|-----------|-------|
| Registry Targets | `HKLM\SAM`, `HKLM\SYSTEM` |
| Staging Path | `C:\Users\Public\` |
| Execution Context | `Sophie.Turner` |

### Analyst Notes

Accessing SAM and SYSTEM hives requires SYSTEM-level or local Administrator privileges. The fact that `Sophie.Turner` had sufficient rights to dump these hives indicates either the account held local admin rights — a common enterprise misconfiguration — or privilege escalation occurred prior to this step. Staging the hive dumps in `C:\Users\Public\` is a deliberate choice: the attacker needed a location accessible from multiple accounts for later retrieval.

---

## Section 4: Discovery

**MITRE ATT&CK:** T1033 — System Owner/User Discovery | T1135 — Network Share Discovery | T1069.001 — Permission Groups Discovery: Local Groups

### What Happened

Following credential access, the attacker performed standard post-exploitation reconnaissance to map the environment. A short burst of commands confirmed the execution context, identified accessible network resources, and revealed which accounts held local administrator privileges.

### Commands Observed

| Command | Purpose |
|---------|---------|
| `whoami` | Confirm current user and execution context |
| `net view` | Enumerate accessible hosts and network shares |
| `net localgroup administrators` | Identify members of the local Administrators group |

### Analyst Notes

A burst of multiple discovery commands within a short time window is a strong behavioral indicator of hands-on-keyboard adversary activity. Legitimate users rarely chain `whoami`, `net view`, and `net localgroup` in rapid succession. This pattern is consistent with an attacker following a post-exploitation playbook — confirming their position, understanding the network layout, and identifying targets for lateral movement before taking further action.

---

## Section 5: Persistence — Remote Administration Tool

**MITRE ATT&CK:** T1219 — Remote Access Software | T1105 — Ingress Tool Transfer

### What Happened

AnyDesk, a legitimate remote desktop application, was downloaded and deployed across all three endpoints. The download was carried out using `certutil.exe` — a Windows built-in certificate management utility frequently abused to pull files from the internet without triggering standard download alerts. An unattended password was configured in the AnyDesk settings, allowing the attacker to silently connect to any of the three systems without requiring user approval or interaction.

### Indicators

| Indicator | Value |
|-----------|-------|
| Tool | AnyDesk (legitimate software, abused for persistence) |
| SHA256 | `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` |
| Download Method | `certutil.exe` (LOLBin abuse) |
| Unattended Password | `intrud3r!` |
| Config File | `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf` |
| Affected Hosts | AS-PC1, AS-PC2, AS-SRV |

### Analyst Notes

AnyDesk is not inherently malicious — its abuse is a classic **bring-your-own-tool** technique that bypasses many traditional antivirus signatures because the binary itself is legitimate and digitally signed. The key hunting signal is context: AnyDesk downloaded via `certutil.exe`, installed outside standard Program Files directories, configured with an unattended password, and deployed to multiple hosts in quick succession is clearly not authorized IT activity. Deploying across all three hosts ensured the attacker retained access even if one machine was isolated or reimaged.

---

## Section 6: Lateral Movement

**MITRE ATT&CK:** T1021.001 — Remote Services: Remote Desktop Protocol | T1078 — Valid Accounts

### What Happened

The attacker first attempted lateral movement using `wmic.exe` and `psexec.exe` against AS-PC2 — both failed, likely due to host firewall rules or UAC restrictions blocking remote execution. Rather than abandoning the attempt, the attacker adapted and pivoted to interactive RDP using `mstsc.exe` with the `david.mitchell` credentials obtained earlier, successfully traversing AS-PC1 → AS-PC2 → AS-SRV.

Notably, the `david.mitchell` account was re-enabled using the `/active:yes` flag before use, indicating the account had been disabled and was specifically reactivated to support this movement.

### Indicators

| Indicator | Value |
|-----------|-------|
| Failed Attempts | `wmic.exe`, `psexec.exe` → AS-PC2 |
| Successful Method | `mstsc.exe` (Interactive RDP) |
| Movement Path | AS-PC1 → AS-PC2 → AS-SRV |
| Account Used | `david.mitchell` |
| Account Activation Command | `net user david.mitchell /active:yes` |

### Analyst Notes

The failure of `wmic` and `psexec` followed immediately by successful RDP is a tell-tale adaptive sequence — the attacker tried automated execution paths first, and when those failed, switched to interactive access. This kind of real-time adaptation is characteristic of **human-operated attacks** rather than automated malware. The reactivation of a disabled account also suggests the attacker had already enumerated account states during the discovery phase and identified `david.mitchell` as a high-value target worth re-enabling.

---

## Section 7: Persistence — Scheduled Task & Backdoor Account

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job | T1036.003 — Masquerading: Rename System Utilities | T1136.001 — Create Account: Local Account

### What Happened

Two additional persistence mechanisms were deployed on AS-SRV. First, the original payload binary was renamed to `RuntimeBroker.exe` — the name of a legitimate Windows process — and a scheduled task named `MicrosoftEdgeUpdateCheck` was created to execute it automatically. Both names were chosen specifically to blend in with real Windows components and avoid standing out during a casual review of running processes or scheduled tasks.

Second, a new local account named `svc_backup` was created as a fallback access method in case the AnyDesk persistence was discovered and removed.

### Indicators

| Indicator | Value |
|-----------|-------|
| Scheduled Task Name | `MicrosoftEdgeUpdateCheck` |
| Renamed Payload | `RuntimeBroker.exe` |
| SHA256 | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` (matches initial payload) |
| Backdoor Account | `svc_backup` |

### Analyst Notes

Reusing the same payload binary under a masqueraded filename is a detectable technique — **hash-based hunting will identify it regardless of what the file is named**. The scheduled task name `MicrosoftEdgeUpdateCheck` closely mimics Microsoft's legitimate `MicrosoftEdgeUpdate` tasks, but the real version never points to binaries stored in user-writable directories. The creation of `svc_backup` reflects an attacker who anticipated detection — layering multiple independent persistence methods so that removing one does not eliminate access entirely.

---

## Section 8: Data Access & Staging

**MITRE ATT&CK:** T1039 — Data from Network Shared Drive | T1560.001 — Archive Collected Data: Archive via Utility

### What Happened

The attacker accessed a sensitive financial file — `BACS_Payments_Dec2025.ods` — from a shared drive on AS-SRV. The presence of a LibreOffice lock file (`.~lock.BACS_Payments_Dec2025.ods#`) confirms the file was **opened and edited**, not merely copied or viewed. Following access, the data was compressed into an archive named `Shares.7z`, consistent with staging for exfiltration.

### Indicators

| Indicator | Value |
|-----------|-------|
| Sensitive File Accessed | `BACS_Payments_Dec2025.ods` |
| Edit Evidence | `.~lock.BACS_Payments_Dec2025.ods#` (LibreOffice lock file) |
| Access Originated From | AS-PC2 |
| Archive Created | `Shares.7z` |
| Archive SHA256 | `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048` |

### Analyst Notes

The combination of a lock file and archive creation is a high-confidence staging indicator. BACS (Bankers' Automated Clearing System) payment files contain banking transaction data — their modification suggests the attacker's objective may have been **financial fraud**, not just data theft. Defenders should investigate whether any outbound network connections followed the creation of `Shares.7z` to determine if exfiltration was attempted or completed.

---

## Section 9: Anti-Forensics & In-Memory Execution

**MITRE ATT&CK:** T1070.001 — Indicator Removal: Clear Windows Event Logs | T1620 — Reflective Code Loading | T1055 — Process Injection

### What Happened

In the final phase, the attacker cleared the Security and System Windows event logs using `wevtutil.exe`, removing evidence of account logons, privilege use, and service changes from the local system.

Simultaneously, **SharpChrome** — a .NET tool for extracting saved credentials from Google Chrome — was executed entirely in memory via reflective loading, injected into a running `notepad.exe` process. This technique leaves no binary on disk and evades many traditional file-scan-based detections. The `ClrUnbackedModuleLoaded` event type in Microsoft Defender telemetry is the key signal for this activity, capturing .NET modules loaded without a corresponding file on disk.

### Indicators

| Indicator | Value |
|-----------|-------|
| Logs Cleared | Security, System event logs |
| Cleanup Tool | `wevtutil.exe` |
| Reflective Load Telemetry | `ClrUnbackedModuleLoaded` ActionType |
| In-Memory Tool | SharpChrome (.NET credential harvester) |
| Host Process | `notepad.exe` |

### Analyst Notes

Log clearing is a near-unambiguous malicious indicator — there is almost no legitimate administrative reason to clear Security and System event logs in a production environment. However, the attacker's cleanup was only partially effective: **EDR telemetry is forwarded to Sentinel independently of local Windows event logs**, so all process, file, and network activity was already captured before the wipe occurred. The use of SharpChrome also suggests the attacker was harvesting browser-stored credentials, potentially to expand access beyond the current environment or prepare for a follow-on campaign.

---

## MITRE ATT&CK Coverage Map

| Tactic | ID | Technique | Tool / Method |
|--------|----|-----------|---------------|
| Initial Access | T1204.002 | User Execution: Malicious File | Double-extension .exe |
| Execution | T1036.007 | Masquerading: Double Extension | `daniel_richardson_cv.pdf.exe` |
| Command & Control | T1071.001 | Web Protocols | HTTPS to cloud-endpoint.net |
| Command & Control | T1105 | Ingress Tool Transfer | `certutil.exe` download |
| Credential Access | T1003.002 | OS Credential Dumping: SAM | SAM + SYSTEM hive extraction |
| Discovery | T1033 | System Owner/User Discovery | `whoami` |
| Discovery | T1135 | Network Share Discovery | `net view` |
| Discovery | T1069.001 | Local Group Discovery | `net localgroup administrators` |
| Persistence | T1219 | Remote Access Software | AnyDesk |
| Persistence | T1053.005 | Scheduled Task | MicrosoftEdgeUpdateCheck |
| Persistence | T1136.001 | Create Local Account | `svc_backup` |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | `mstsc.exe` |
| Lateral Movement | T1078 | Valid Accounts | `david.mitchell` |
| Collection | T1039 | Data from Network Shared Drive | `BACS_Payments_Dec2025.ods` |
| Collection | T1560.001 | Archive via Utility | `Shares.7z` |
| Defense Evasion | T1070.001 | Clear Windows Event Logs | `wevtutil.exe` |
| Defense Evasion | T1620 | Reflective Code Loading | SharpChrome in `notepad.exe` |
| Defense Evasion | T1036.003 | Rename System Utilities | `RuntimeBroker.exe` |

---

## Detection Opportunities Summary

| Phase | Key Hunting Signal | Priority |
|-------|--------------------|----------|
| Initial Access | Double-extension file executed from Downloads directory | High |
| C2 | Unknown domain beaconing from a non-browser process | High |
| Credential Access | Registry hive access to SAM/SYSTEM | Critical |
| Discovery | Burst of discovery commands within a 5-minute window | Medium |
| Persistence | RMM tool installed via `certutil.exe` outside Program Files | High |
| Lateral Movement | RDP connection following failed `wmic`/`psexec` attempts | High |
| Persistence | Scheduled task pointing to a non-standard binary path | High |
| Data Access | Financial file accessed followed immediately by archive creation | High |
| Anti-Forensics | `wevtutil.exe` clearing Security/System logs | Critical |
| In-Memory | `ClrUnbackedModuleLoaded` event in a non-.NET process | Critical |

---

## Lessons Learned & Recommendations

**1. Block double-extension file execution at the OS level**  
Configure AppLocker or Windows Defender Application Control (WDAC) policies to block execution of files with double extensions from user-writable directories such as Downloads and Desktop.

**2. Alert on certutil.exe network activity**  
`certutil.exe` has no legitimate reason to make outbound HTTP/HTTPS connections in most enterprise environments. Any such activity should generate a high-priority alert for immediate review.

**3. Monitor RMM tool installations outside standard paths**  
Tools like AnyDesk are legitimate but frequently abused. Installation from non-standard directories or via LOLBins should trigger automatic investigation.

**4. Enforce least privilege on workstation accounts**  
`Sophie.Turner` having sufficient rights to dump SAM/SYSTEM hives indicates over-permissioned local accounts. Standard user accounts should not hold local administrator rights.

**5. Protect log integrity through real-time SIEM forwarding**  
Because Defender telemetry was forwarded to Sentinel independently of local Windows event logs, the attacker's log clearing was ineffective. All environments should ensure real-time forwarding so local cleanup does not eliminate evidence.

**6. Hunt for reflective .NET loading in non-.NET processes**  
The `ClrUnbackedModuleLoaded` Defender event is specifically designed to surface this behavior. Detections should fire when this event occurs inside processes such as `notepad.exe` or other applications that have no reason to host managed code.

---

## Conclusion

This engagement demonstrated a realistic, multi-phase intrusion where no single event was decisive on its own. The full attack chain was only confirmed through **cross-host behavioral correlation and timeline-based analysis**. The adversary's use of legitimate tools (AnyDesk, RDP, certutil, reg.exe), valid credentials, and memory-resident execution reflects the tradecraft of a capable threat actor deliberately attempting to blend into normal operational activity.

The investigation validates the value of **behavior-based threat hunting** over signature-only detection. Microsoft Defender's process, file, network, and event-level telemetry provided the depth required to reconstruct the full attack chain — even after the adversary attempted anti-forensic cleanup.

---

*Report prepared as part of The Broker Cyber Range engagement*  
*Platform: Microsoft Defender for Endpoint / Microsoft Sentinel*  
*Hunt Methodology: Behavioral correlation and timeline analysis*

---
*End of Report*
