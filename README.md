<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/erickcisneros1/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "erick" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-04-26T18:41:13.0364233Z`. These events began at `2025-04-26T18:35:13.0364233Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ec-win2"
| where InitiatingProcessAccountName == "erick"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-04-26T18:41:13.0364233Z)
| sort by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account = InitiatingProcessAccountName

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/bb46f673-dff5-40fc-a7d7-9a910b94a855">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.exe". Based on the logs returned, at `2025-04-26T18:43:57.5439374Z`, an employee on the "ec-win2" device ran the file `tor-browser-windows-x86_64-portable-14.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ec-win2"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.exe"
| project Timestamp, DeviceName,AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/31ee24eb-f441-4878-991e-90379bcba4b7">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "erick" actually opened the TOR browser. There was evidence that they did open it at `2025-04-26T18:47:55.7902657Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ec-win2"
| where FileName has_any ("tor.exe","firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/116c1805-e663-41fb-9832-11ce7a754287">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-04-26T18:48:13.3851243Z`, an employee on the "ec-win2" device successfully established a connection to the remote IP address `111.69.37.214` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\erick\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ec-win2"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe","firefox.exe")
| where RemotePort in ("9001","9030","9040","9050","9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b05978ee-536a-48e5-9dac-f973103ed558">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-26T18:41:13.0364233Z`
- **Event:** The user "erick" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\erick\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-26T18:43:57.5439374Z`
- **Event:** The user "erick" executed the file `tor-browser-windows-x86_64-portable-14.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.exe /S`
- **File Path:** `C:\Users\erick\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-26T18:47:55.7902657Z`
- **Event:** User "erick" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\erick\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-26T18:48:13.3851243Z`
- **Event:** A network connection to IP `111.69.37.214` on port `9001` by user "erick" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\erick\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-26T18:48:12.7105108Z` - Connected to `216.181.20.35` on port `443`.
  - `2025-04-26T18:48:30.7316229Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "erick" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-26T18:51:13.3851243Z`
- **Event:** The user "erick" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\erick\Desktop\tor-shopping-list.txt`

---

## Summary

The user "erick" on the "ec-win2" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `ec-win2` by the user `erick`. The device was isolated, and the user's direct manager was notified.

---
