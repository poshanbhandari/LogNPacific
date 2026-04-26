# SIGNALS_BEFORE_THE_NOISE Threat Hunting Challenge — Full Walkthrough
**Classification:** SOC Investigation Report / CTF Writeup  
**Scope:** Azure Workstation (`azwks-phtg-02`) — Internet-Exposed RDP Endpoint  
**Tooling:** Microsoft Defender for Endpoint (MDE) / KQL via Advanced Hunting

---

## Table of Contents

1. [Part 0 — Mission Brief](#part-0--mission-brief)
2. [Part 01 — Public Exposure](#part-01--public-exposure)
3. [Part 02 — Scanning Telemetry](#part-02--scanning-telemetry)
4. [Part 03 — Authentication Baseline](#part-03--authentication-baseline)
5. [Part 04 — Geographic Anomaly](#part-04--geographic-anomaly)
6. [Part 05 — Post-Access Behaviour](#part-05--post-access-behaviour)
7. [Part 06 — Evasion and Execution](#part-06--evasion-and-execution)
8. [Part 07 — The Baseline Was the Cover](#part-07--the-baseline-was-the-cover)
9. [Summary / Key Findings](#summary--key-findings)

---

## Part 0 — Mission Brief

Before any investigation begins, every good threat hunt starts with a brief — a defined scope and a set of hypotheses to test. This challenge is prefixed under the tag `phtg`, which will appear throughout filenames, folder paths, and artifacts discovered during the investigation. Understanding that tag early helps us pattern-match later when things get murky.

### Q0 — Challenge Tag / Flag Prefix

No query needed. The challenge flag prefix established at the outset is:

**Answer:** `phtg`

---

## Part 01 — Public Exposure

Before a threat actor can attack you, they need to find you. This phase of the investigation focuses on identifying the device that was exposed to the public internet, confirming its external IP address, and understanding the baseline context of why this exposure is problematic. A machine with a publicly routable IP and open management ports is not a hypothesis — it is a target.

### Q1 — Exposed Device Name

The device at the center of this investigation is an Azure-hosted workstation that was directly reachable from the internet. Identifying it by name anchors every subsequent query.

**Answer:** `azwks-phtg-02`

---

### Q2 — Public IP Address of the Exposed Device

The device was assigned a public IP address, making it directly reachable from anywhere on the internet without traversing a VPN or bastion host.

**Answer:** `74.249.82.162`

---

### Q3 — Multiple Choice (Context Question)

**Answer:** `D`

---

### Q4 — Multiple Choice (Context Question)

**Answer:** `C`

---

### Q5 — Multiple Choice (Context Question)

**Answer:** `D`

---

## Part 02 — Scanning Telemetry

With a publicly exposed device identified, the next question is: who noticed it, and what were they looking at? This phase examines network telemetry to identify the most targeted port, the volume of inbound connection attempts from public IP space, and whether any of those connections were successful. The pattern here is classic internet noise — or so it seems.

### Q6 — Most Targeted Local Port

To determine which service was attracting the most attention, we summarize all network events against the device by local port, ordering by volume descending.

```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg"
| summarize TotalEvents = count() by LocalPort
| order by TotalEvents desc
```

This query aggregates all inbound/outbound network activity on the device by destination local port. The top result reveals which service was being hammered the hardest. Unsurprisingly, the winner is RDP — the Windows Remote Desktop Protocol.

**Answer:** `3389` (RDP)

---

### Q7 — RDP Connections from Public IPs

We next scope down exclusively to RDP traffic originating from public (non-RFC1918) IP addresses. This removes internal lateral movement noise and focuses us on external threat actors.

```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where RemoteIPType == "Public"
```

This query filters network events to only those targeting port 3389 from externally routable IP addresses. Every row returned here represents an external party interacting — or attempting to interact — with the device's RDP service.

**Answer:** Raw event list returned for further analysis.

---

### Q8 — Total Events and Unique IPs on RDP from Public Space

Volume and diversity of source IPs tells us a lot about the nature of the scanning. A high count from few IPs suggests a targeted campaign; a high count from many IPs suggests automated internet scanners.

```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LocalPort == 3389
| summarize count(), UniqueIPs = dcount(RemoteIP)
```

This aggregation gives us both the total event count and the distinct IP count in one pass. The `dcount()` function performs an approximate distinct count — efficient at scale. The ratio between total events and unique IPs tells us whether the traffic is distributed or concentrated.

**Answer:** Counts returned; used as baseline for Q9.

---

### Q9 — IPs That Both Attempted AND Succeeded RDP Connections

Not every scanning IP is equally dangerous. Here we narrow the field to only those source IPs that successfully completed an RDP session after having made connection attempts — a key indicator of a successful brute-force or credential-stuffing attack.

```kql
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| summarize 
    Attempted = countif(ActionType has "ConnectionAttempt"),
    Succeeded = countif(ActionType has "InboundConnectionAccepted" or ActionType has "Accepted")
    by RemoteIP
| where Attempted > 0 and Succeeded > 0
| project RemoteIP
```

This query pivots network event data into a per-IP behavioral profile. By counting both attempted and accepted connections per source IP, we can identify IPs that went beyond scanning and achieved an actual session. Any IP appearing in this output warrants deep scrutiny.

**Answer:** A filtered list of IPs that both knocked and got in.

---

### Q10 — Unique Countries with Successful RDP Connections

To understand the geographic spread of successful intrusions, we enrich the IP list with geolocation data using a publicly available GeoIP dataset.

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceNetworkEvents
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| summarize 
    Attempted = countif(ActionType has "ConnectionAttempt"),
    Succeeded = countif(ActionType has "InboundConnectionAccepted" or ActionType has "Accepted")
    by RemoteIP
| where Attempted > 0 and Succeeded > 0
| summarize by RemoteIP
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| extend country_name = tostring(country_name)
| summarize by country_name
```

We load an external GeoIP CIDR table using `externaldata`, then use `ipv4_lookup` to map each successful-connection IP to its originating country. The final `summarize by country_name` gives us the distinct list of countries that achieved RDP sessions.

**Answer:** `11` unique countries successfully connected via RDP.

---

## Part 03 — Authentication Baseline

Network-layer connections tell us who reached the door. Authentication logs tell us who walked through it. This phase shifts focus to `DeviceLogonEvents` to quantify the raw scale of the credential attacks, understand their type, and identify the primary failure reason. This is the brute-force fingerprint.

### Q11 — Total Remote Logon Events from Public IPs

We begin by counting all remote logon events (successes and failures) originating from public IP space. This is the top-line number for the brute-force campaign.

```kql
DeviceLogonEvents
| where DeviceName startswith "azwks-phtg-02"
| where RemoteIP != ""
| where ipv4_is_private(RemoteIP) == false
| summarize count()
```

The `ipv4_is_private()` function natively handles RFC1918 filtering, cleanly excluding all internal traffic. This gives us the total count of authentication events from external actors.

**Answer:** `693` remote logon events from public IPs.

---

### Q12 — Filtered to RDP/Network Logon Types Only

Not all logon types are equal. We narrow the focus to `RemoteInteractive` (RDP sessions) and `Network` logons, which are the types consistent with RDP and SMB-based remote access.

```kql
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where isnotempty(RemoteIP)
| where ipv4_is_private(RemoteIP) == false
| where LogonType in ("RemoteInteractive", "Network")
| summarize count()
```

Adding the `LogonType` filter removes background noise from service accounts, scheduled tasks, and other non-interactive session types, giving us a cleaner picture of human-initiated remote access attempts.

**Answer:** `675` logon events matching RDP/Network logon types.

---

### Q13 — Breakdown by ActionType

Understanding the ratio of failures to successes quantifies the brute-force pressure and identifies whether the campaign was ultimately successful.

```kql
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where isnotempty(RemoteIP)
| where ipv4_is_private(RemoteIP) == false
| where LogonType in ("RemoteInteractive", "Network")
| summarize count() by ActionType
```

This aggregation splits events by outcome — `LogonSuccess` vs `LogonFailed` — giving us a direct read on how effective the credential attacks were. The overwhelming majority of events are failures, consistent with automated brute-force tooling working through a password wordlist.

**Answer:** The vast majority are `LogonFailed`, with a small number of `LogonSuccess` events present.

---

### Q14 — Primary Failure Reason

When logons fail, MDE captures the Windows authentication failure code. Identifying the most common reason helps characterize the attack type.

```kql
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where isnotempty(RemoteIP)
| where ipv4_is_private(RemoteIP) == false
| where LogonType in ("RemoteInteractive", "Network")
| summarize count() by FailureReason
```

Aggregating by `FailureReason` surfaces the Windows error codes being returned. The dominant value here points directly to credential guessing — the attacker didn't have the right password, and kept trying.

**Answer:** `InvalidUserNameOrPassword` — confirming a credential brute-force attack.

---

### Q15 — Unique Countries with Logon Attempts

Using the same GeoIP enrichment technique as Part 02, we map every source IP from the authentication event set to a country of origin.

The query follows the same `ipv4_lookup` pattern against the external GeoIP dataset, applied to the filtered `DeviceLogonEvents` RemoteIP values.

**Answer:** `17` unique countries attempted logons against the device.

---

### Q16 — Countries with Successful Logons

Of those 17 countries throwing credentials at the device, only 2 actually produced successful authentication events. This is a critical narrowing of our suspect pool.

The query adds `ActionType == "LogonSuccess"` to the filter chain before geo-enrichment, isolating only the IPs that completed a valid authentication.

**Answer:** `2` countries produced successful logon events.

---

### Q17 — Which Two Countries Had Successful Logons

**Answer:** `Uruguay` and `United States`

---

## Part 04 — Geographic Anomaly

With two countries producing successful logons, the task becomes understanding which one is expected (or at least explainable) and which represents a genuine anomaly. Geographic context is a powerful first-order triage signal in threat hunting — not definitive evidence, but a meaningful discriminator when combined with behavioral indicators.

### Q18 — Which Country Is Anomalous

Given the organization's known footprint and expected operational geography, one of these two countries stands out as having no legitimate business context.

**Answer:** `Uruguay` — geographically and operationally anomalous.

---

### Q19 — Account Used in the Successful Uruguay Logon

Identifying the account name used in the anomalous logon is critical for understanding whether credentials were compromised, and which account to scope further investigation around.

```kql
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where isnotempty(RemoteIP)
| where ipv4_is_private(RemoteIP) == false
| where LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
```

Reviewing the `AccountName` column in the successful logon events reveals which credential was successfully brute-forced. This account will appear repeatedly in post-access process and file activity.

**Answer:** `vmadminusername`

---

### Q20 — Number of Successful Logons from Suspicious US IPs

Not all US-based logons are benign. Two specific US IP addresses — `173.244.55.128` and `173.244.55.131` — appear in the successful logon set and warrant closer examination. We count their successful sessions.

The query filters `DeviceLogonEvents` to those two specific IPs with `ActionType == "LogonSuccess"`.

**Answer:** `23` successful logons from the two suspicious US IPs.

---

### Q21 — Which IP Logged In First

Temporal ordering of the first successful logons from these two IPs helps establish the sequence of events — specifically, which IP initiated the intrusion.

```kql
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIP in ("173.244.55.128","173.244.55.131")
| where ActionType == "LogonSuccess"
| order by TimeGenerated asc
| project TimeGenerated, RemoteIP, ActionType
```

Sorting the successful logon events ascending by timestamp surfaces the first-in IP. This establishes attribution order and helps correlate with subsequent post-access behaviors.

**Answer:** `173.244.55.131` logged in first.

---

### Q22 — The Primary Attacking IP

Combining the findings from Q20 and Q21 — first actor, highest activity — we identify the primary source IP driving the intrusion.

**Answer:** `173.244.55.131`

---

## Part 05 — Post-Access Behaviour

An attacker with an active RDP session is an attacker operating interactively on the target system. This phase pivots from authentication telemetry to process and file event logs to reconstruct what the threat actor did once inside. The story shifts from "who got in" to "what did they do next."

### Q23 — First Suspicious Process Launched After Access

Immediately following the successful logon, we look at process creation events attributed to the compromised account, filtering out known-good system processes to surface anomalous activity.

The query filters `DeviceProcessEvents` for processes initiated by `vmadminusername` after the confirmed access timestamp, excluding standard OS processes.

**Answer:** `notepad.exe` launched at `2025-12-12 05:47:45`

Notepad being the first process of interest may seem innocuous, but in a threat hunting context, an attacker-initiated text editor session immediately after gaining RDP access warrants scrutiny — especially when we follow where it leads.

---

### Q24 — File Opened in Notepad

Examining the `ProcessCommandLine` field for the Notepad process reveals the exact file path that was opened. This gives us the first artifact — a file the attacker was interacting with.

**Answer:** `notes_sarah.txt` opened at `2025-12-13 13:35:54`

A `.txt` file named after an apparent person of interest. The attacker is reading — or using — content on this machine. This is significant.

---

### Q25 — Renamed File (Suspicious Executable)

Shortly after the Notepad interaction, a file rename event is captured. Renaming files — particularly to executable extensions — is a classic technique for smuggling or staging payloads while avoiding obvious detection.

```kql
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where TimeGenerated > datetime(2025-12-12 13:35:00)
| where InitiatingProcessAccountName == "vmadminusername"
| where ActionType == "FileRenamed"
| project TimeGenerated, DeviceName, ActionType, FileName, PreviousFileName, 
          FolderPath, SHA256, InitiatingProcessAccountName
```

This query searches for file rename operations after the Notepad interaction, scoped to the compromised account. The `FileRenamed` action type captures the metadata of both the new and previous filenames — exposing the attacker's staging maneuver.

**Answer:** `Sarah_Chen_Notes.exe` created at `2025-12-13 10:14:41`

---

### Q26 — Previous Filename Before Rename

The rename operation preserves both the new and old filename in the event telemetry. The prior name is equally revealing.

**Answer:** `Sarah_Chen_Notes.exe.Txt`

The file was previously disguised with a double extension (`.exe.Txt`), a well-known evasion technique that exploits Windows' default behavior of hiding known file extensions. To a casual observer, it would appear to be a text file.

---

### Q27 — SHA256 Hash of the Malicious File

The file hash is the immutable identifier of the payload — it survives renames and moves, and it's what we use to track the artifact across telemetry sources and threat intelligence.

**Answer:** `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`

---

### Q28 — Original Filename Associated with That Hash

Querying `DeviceFileEvents` by the SHA256 hash across the entire dataset reveals the file's original name as it appeared before any renaming — giving us the clearest picture of what was actually dropped on disk.

The query filters `DeviceFileEvents` by `SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"`.

**Answer:** `PHTG.exe` — the original malware binary, named directly after the challenge tag. No coincidence.

---

### Q29 — Malware Classification (AV Detection)

With the hash in hand, we check `DeviceEvents` for any antivirus detection records associated with the file. MDE's antivirus telemetry captures the engine's classification when a file is scanned or flagged.

```kql
DeviceEvents
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project AdditionalFields
```

The `AdditionalFields` column in `DeviceEvents` contains JSON-encoded antivirus metadata, including the threat name assigned by Microsoft Defender. Parsing this field surfaces the formal malware classification.

**Answer:** `Trojan:Win32/Meterpreter.RPZ!MTB`

This is a Meterpreter payload — Metasploit's flagship post-exploitation framework. The attacker isn't just browsing files; they're establishing a full remote command-and-control channel.

---

## Part 06 — Evasion and Execution

A skilled attacker doesn't just drop a payload and hope for the best. They work to disable defensive controls, establish persistence, and blend their C2 traffic into normal-looking patterns. This phase examines how the threat actor attempted to evade detection, how the malware was executed, and where it was calling home.

### Q30 — Antivirus / Tamper Protection Events

We examine all security state change events on the device to understand whether the attacker interfered with defensive controls.

```kql
DeviceEvents
| where DeviceName == "azwks-phtg-02"
| where ActionType has_any ("AntivirusStateChanged", "SenseStatusChanged", 
        "TamperProtectionStateChanged", "AntivirusDetection")
| project TimeGenerated, ActionType, AdditionalFields
| order by TimeGenerated asc
```

This query surfaces four distinct antivirus/tamper event types, ordered chronologically. The timeline of these events relative to the malware staging activity reveals whether the attacker probed or disabled defenses before executing the payload.

**Answer:** AV and tamper protection events present; reviewed for timeline correlation with malware execution.

---

### Q31 — Process Name Used to Execute the Malicious File

We query process execution events filtered by the known malicious SHA256 to confirm exactly how the payload was invoked.

The query filters `DeviceProcessEvents` by `SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"`.

**Answer:** `Sarah_Chen_Notes.exe` — the renamed Meterpreter binary was executed directly under its disguised filename.

---

### Q32 — Parent Process That Launched the Malware

The parent process in a process creation event tells us the execution context — was this launched manually, via a script, a scheduled task, or some other mechanism?

**Answer:** `cmd.exe` — the Windows Command Prompt invoked the malware. This is consistent with scripted or batch-driven execution.

---

### Q33 — Batch File Used for Persistence / Launch

With `cmd.exe` as the parent, we search for batch script invocations that reference command prompt execution to identify the persistence mechanism.

```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| where ProcessCommandLine has "cmd.exe"
| where ProcessCommandLine has ".bat"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

This query scans process command line data for batch file references chained through cmd.exe. The full path of the batch file reveals both the persistence location and the naming convention the attacker used — consistent with a fake legitimate application.

**Answer:** `C:\ProgramData\PHTG\HealthCloud\Launch.bat`

The attacker staged the malware under a path mimicking a legitimate enterprise software product. The `PHTG` subfolder is a direct attacker-controlled artifact; `HealthCloud` is the software being impersonated.

---

### Q34 — C2 (Command & Control) IP Address

Post-execution network events reveal the IP address to which the Meterpreter payload established its outbound C2 channel.

**Answer:** `173.244.55.130`

---

### Q35 — C2 Geographic Location

GeoIP enrichment of the C2 IP confirms the attacker's infrastructure origin.

**Answer:** `Uruguay, South America`

This is a critical link: the anomalous RDP logon originated from Uruguay, and the C2 server resolves to Uruguay as well. The same threat actor controls both the initial access vector and the post-exploitation infrastructure.

---

### Q36 — C2 Port Used

**Answer:** `4444`

Port 4444 is the default Meterpreter reverse TCP listener port. While it can be reconfigured, its presence here is consistent with an attacker using default or minimally customized Metasploit tooling. This is an actionable indicator for firewall blocking and threat intelligence.

---

## Part 07 — The Baseline Was the Cover

Every element of this attack was designed to blend in. The attacker didn't create obvious anomalies — they leveraged legitimate-looking software names, familiar file paths, and benign-appearing usernames. This final phase examines the camouflage used and connects the fake software identity to the actual malicious artifacts.

### Q37 — Fake Legitimate Software Used as a Cover

We trace the full file activity history for the malware binaries across the device to identify the software identity the attacker adopted for their staging path.

```kql
DeviceFileEvents
| where DeviceName startswith "azwks"
| where FileName in ("PHTG.exe", "Sarah_Chen_Notes.exe")
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc
```

This query pulls all file events matching either the original or renamed malware filename across the Azure workstation, ordered chronologically. The `FolderPath` column reveals the attacker's chosen staging directory — and with it, the fictitious application name used as cover.

**Answer:** `Health Cloud`

The attacker created the directory `C:\ProgramData\PHTG\HealthCloud\` and placed their malware and launcher batch file inside it, impersonating a legitimate-sounding enterprise health software product. This path mimics how real enterprise applications install themselves, making it plausible to a cursory review.

---

## Summary / Key Findings

This investigation tells the complete story of a targeted intrusion against an intentionally exposed Azure workstation — from first exposure to active C2 communication.

**The Attack Chain — In Order:**

| Phase | Finding |
|---|---|
| **Exposure** | `azwks-phtg-02` was publicly accessible at `74.249.82.162` with RDP (port 3389) open to the internet |
| **Reconnaissance** | Automated scanners from **11 countries** targeted RDP; **17 countries** submitted authentication attempts |
| **Brute Force** | 675 external RDP/Network logon attempts, dominated by `InvalidUserNameOrPassword` failures |
| **Initial Access** | Credentials for `vmadminusername` successfully brute-forced; primary attacking IP `173.244.55.131` from the US |
| **Anomalous Logon** | A geographically anomalous successful logon from **Uruguay** confirmed attacker access |
| **Staging** | Attacker used Notepad to review `notes_sarah.txt`; dropped malware disguised as `Sarah_Chen_Notes.exe.Txt` |
| **Execution** | Malware (`PHTG.exe` / `Trojan:Win32/Meterpreter.RPZ!MTB`) executed via `cmd.exe` and a persistence batch file |
| **Persistence** | `C:\ProgramData\PHTG\HealthCloud\Launch.bat` used to establish execution persistence under a fake "Health Cloud" software identity |
| **C2 Communication** | Meterpreter beacon established to `173.244.55.130:4444` — a Uruguay-hosted C2 server |
| **Attribution Link** | The Uruguay RDP source and Uruguay C2 infrastructure confirm a single threat actor controlled both ends of the attack |

**Key Indicators of Compromise (IoCs):**

| Type | Value |
|---|---|
| Attacking IP | `173.244.55.131` |
| C2 IP | `173.244.55.130` |
| C2 Port | `4444` |
| Malware Hash (SHA256) | `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` |
| Malware Names | `PHTG.exe`, `Sarah_Chen_Notes.exe`, `Sarah_Chen_Notes.exe.Txt` |
| Persistence Path | `C:\ProgramData\PHTG\HealthCloud\Launch.bat` |
| Compromised Account | `vmadminusername` |
| Malware Classification | `Trojan:Win32/Meterpreter.RPZ!MTB` |

**Analyst Notes:**

The attacker demonstrated a deliberate, multi-stage methodology: mass brute-force credential stuffing to gain initial access, interactive post-exploitation via RDP, careful payload staging using double extensions and innocuous-looking filenames, and a Meterpreter C2 disguised inside a fake enterprise application folder. The consistent use of Uruguay-based infrastructure across both the RDP logon and C2 communications strongly suggests a single, coordinated threat actor. The fake "Health Cloud" software branding adds a layer of operational camouflage that could delay detection in environments without robust file integrity monitoring or process baselining.

**Recommended Remediation:**
- Immediately block `173.244.55.128`, `173.244.55.130`, and `173.244.55.131` at the perimeter firewall.
- Disable direct RDP exposure; require VPN or Azure Bastion for all remote management.
- Rotate all credentials for `vmadminusername` and audit for lateral movement.
- Hunt for `Launch.bat` and the `C:\ProgramData\PHTG\` directory tree across all endpoints in the environment.
- Submit SHA256 `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` to threat intelligence platforms and block at EDR level.

---

*Report generated as part of the PHTG Threat Hunting Challenge. All data sourced from Microsoft Defender for Endpoint Advanced Hunting (KQL).*
