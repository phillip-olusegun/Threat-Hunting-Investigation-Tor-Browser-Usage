# AY-Cyber Project

<img width="1280" height="774" alt="image" src="https://github.com/user-attachments/assets/eb8de679-64e4-4982-b058-1912210b6c7a" />

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Cyber-AY/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for files containing the string “tor” and identified that the suspected user downloaded a TOR installer and executed activities that generated over a dozen TOR-related files. These files were subsequently copied to the local machine’s desktop and stored in a folder named “tor-shopping-list”. Evidence from the event logs indicates that this activity began on 2026-06-06T14:38:21.5657701Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "james-vm"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-06-06T14:38:21.5657701Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```

<img width="1056" height="527" alt="image" src="https://github.com/user-attachments/assets/49edf3fd-615a-49fc-9ffb-cbeda5d3d8d6" />

---

### 2. Searched the `DeviceProcessEvents` Table

Reviewed the above table for any ProcessCommandLine entries containing or starting with the string “tor-browser-windows-x86_64-portable-15.0.15.exe.” Log analysis revealed that at 2026-06-06T14:38:21.5657701Z, the suspected user executed the file “tor-browser-windows-x86_64-portable-15.0.15.exe” from the local machine’s Downloads folder, likely as part of a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where Timestamp > ago (7d)
| where DeviceName == "james-vm"
| where ProcessCommandLine contains 'tor-browser-windows-x86_64-portable-15.0.15.exe'
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```

<img width="1054" height="352" alt="image" src="https://github.com/user-attachments/assets/6015d402-fbbc-4cdb-816c-ed76390951c2" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Review of the DeviceEvents table revealed that the user opened the TOR browser at 2026-06-04T22:35:26.9271459Z. Additional instances of firefox.exe and tor.exe process activity were also observed, as evidenced by the logs in the same table.

**Query used to locate events:**

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == "james-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine

```

<img width="1086" height="512" alt="image" src="https://github.com/user-attachments/assets/efeab8ed-c5fa-4d0c-a857-e7fa48c7a5cb" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

The DeviceNetworkEvents table was analyzed for evidence of TOR browser activity, specifically connections over known TOR ports. On June 6, 2026, at 3:30 PM, the user successfully established a network connection to the external IP address 23.88.122.132 over port 9001 using the TOR process (tor.exe), executed from the TOR Browser directory on the user’s desktop. Additional outbound connections over port 443 were also observed.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName == "james-vm"
| where RemotePort in ("9001", "9030", "9040", "9050", "9851", "9150", "80", "443")
| where InitiatingProcessAccountName != "system"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath

```
<img width="1344" height="763" alt="image" src="https://github.com/user-attachments/assets/0fdbac65-3ba6-4c53-992e-ec9a3d7b2aca" />
---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-06-06T14:38:21.5657701Z`
- **Event:** The user "james" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.15.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `
C:\Users\James\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-06-06T14:48:27.7806001Z`
- **Event:** The user "james" executed the file `tor-browser-windows-x86_64-portable-15.0.15.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.15.exe /S`
- **File Path:** `C:\Users\James\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-06-04T22:35:17.7161971Z`
- **Event:** User opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\James\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-06-06T14:30:38.4147248Z`
- **Event:** A network connection to IP `23.88.122.132 ` on port `9001` by user was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:**  `C:\Users\James\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-06-06T13:57:38.8978272Z` - Connected to `20.42.65.94` on port `443`.
  - `2026-06-06T14:30:41.1692847Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-06-06T15:04:11.0580576Z`
- **Event:** The user created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\James\Desktop\tor-shopping-txt.txt`

---

## Summary

The user on the suspected device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `James-VM` by the user `James`. The device was isolated, and the user's direct manager was notified.

---
