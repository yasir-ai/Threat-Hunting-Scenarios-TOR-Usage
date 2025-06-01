<p align="">
  <img src="https://miro.medium.com/v2/resize:fit:1400/1*_SnhthPwhLswXa5B8nXC0g.gif" alt="TOR Threat Hunt Banner" width="30%" height="150px">
</p>

# Threat Hunt Report: Unauthorized TOR Usage
![Platform: Windows](https://img.shields.io/badge/Platform-Windows10-blue)
![EDR: Defender](https://img.shields.io/badge/EDR-Defender-green)
![Language: KQL](https://img.shields.io/badge/KQL-Used-ff69b4)

- [Scenario Creation](https://github.com/yasir-ai/threat-hunting-scenarios-tor-usage/blob/main/scenario-event-creation.md)

## Platforms and Languages Leveraged
- Platform: Windows 10 VMs in Microsoft Azure
- Security Monitoring: Microsoft Defender for Endpoint (EDR)
- Query Language: Kusto Query Language (KQL)
- Target Application: Tor Browser

##  Scenario

Recently, we noticed a pattern of encrypted outbound traffic that looked unusual. Some of it was flagged as connections to known TOR entry nodes. Around the same time, we received anonymous internal reports suggesting that employees might be attempting to bypass network security controls—specifically to access restricted websites during office hours.

Given the nature of TOR and its ability to anonymize traffic and avoid monitoring, we launched a targeted threat hunt to confirm or deny its use on our systems to mitigate and potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan
To determine if TOR was installed or used within the environment, I focused on three key data sources

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events. | Identifies any TOR related executables, such as tor.exe, firefox.exe, or any files containing "tor" in their name during download and file creation.
- **Check `DeviceProcessEvents`** for any signs of installation or usage. | Searches for any process creation events tied to TOR installation or execution.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports. | Discovers network activity for outbound connections to known TOR ports (ex: 9001, 9050, 9150, 443, etc) initiated by TOR.

#### The Goal?

Detect unauthorized TOR usage. Analyze it. Prove it. Report it.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I start with the DeviceFileEvents table. Why? Because if someone’s using TOR, they must have downloaded something. Installed something. Left digital fingerprints of somekind.

I searched for any file that had the string "tor" in it.

I found a user employee downloading tor-browser-windows-x86_64-portable-14.0.1.exe on Feb 3rd. Within 10 minutes, a flood of TOR related files popped up on the desktop, and a file called tor-shopping-list.txt got created.

Timestamp?
2025-02-03T14:03:28Z

This is when the trail begins.
They weren’t just curious, it looks like they had a plan.

**Query used:**

```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName == "employee"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-02-03T13:54:44.0103078Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Next, I hunted through the DeviceProcessEvents table, looking for the silent install.

I searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe".

And I found it.

At 7:57 AM, the user ran the TOR installer from their downlods folding, using the /S silent flag. That means: “Don’t show anyone what I’m doing.”

```command line
tor-browser-windows-x86_64-portable-14.0.1.exe /S
```

Now it’s no longer speculation, this is confirmed to be intentional.


**Query used:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Then I asked: Did they _actually_ use it though?

I searched for any indication that user "employee" actually opened the TOR browser.

Answer is: Yes.

At 13:57:21Z, firefox.exe (TOR browser’s GUI) launched. Then tor.exe fired up right after.

**Query used:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports.

The DeviceNetworkEvents sealed the deal. This wasn’t just a browser opening, this was TOR connecting to the network.

Timestamp: 2025-02-03T13:58:22Z
Remote IP: 176.198.159.33
Port: 9001
Process: tor.exe
Folder:
c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe

They connected to the TOR network successfully. Over multiple known TOR ports (443, 9150). One of them even looped back to 127.0.0.1—that’s a local SOCKS proxy setup for TOR tunneling.

So the TOR browser was actively being used.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-02-03T13:54:44.0103078Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-02-03T14:03:28.0009737Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-02-03T14:04:44.0103078Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-02-03T14:08:22.1676751Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-02-03T14:27:21.6293016Z` - Connected to `194.164.169.85` on port `443`.
  - `2025-02-03T14:57:21.6293016Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-02-03T14:58:22.1676751Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## 📄 The Shopping List File

This file—tor-shopping-list.txt might sound innocent, but context is important.

It was created after TOR was installed and used. It sat right on the desktop. And based on the timing, it wasn’t part of the installation, it was a personally created by the user.

Could be a list of sites. Could be credentials. Could be instructions. 

I'm not sure, I have not opened it.

However, the timing alone is alarming.


---



## Summary

- User employee downloaded, installed, and launched the TOR browser in silent mode.
- Active TOR usage was confirmed via:
  - **File creation events**
  - **Process execution logs**
  - **Network connections to TOR nodes**

- Multiple connections sustained TOR session activity.

- User also left behind a file named _tor-shopping-list.txt_, suggesting ongoing intent or preparation.

  
---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified. Logs were preserved for forensics. Company-wide rule to block TOR was suggested

---
