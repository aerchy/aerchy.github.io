---
title: "HTB - Access (Easy | Windows | Web)"
date: 2026-09-29 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, windows, ftp, ftp-anon, mdbtools, pst, readpst, mutt, telnet, certutil, dpapi]
description: "Anonymous FTP leaks an Access DB and a zipped PST; extract creds with mdbtools/readpst, telnet in as security, then decrypt the DPAPI master key and credential blob for the Administrator password"
image:
  path: /assets/img/access.png
---

## Recon

```bash
nmap -p- -sSCV --open --min-rate 5000 10.129.98.207
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: -1s
```

### Service Discovery Analysis

**Initial Assessment:**

The Nmap scan immediately reveals a **critical misconfiguration**: anonymous FTP access is enabled. This is the entry point. Unlike typical Windows machines with SMB hardening, this one is accessible only through legacy protocols (FTP, Telnet). The machine appears to be Windows Server 2008 R2 SP1 (based on IIS 7.5), an **end-of-life OS from 2008** prone to legacy misconfigurations.

**Port Breakdown:**

- **FTP (Port 21)**: Microsoft ftpd with **anonymous login allowed** — this is our immediate foothold. No credential needed. Red flag: whoever set this up either misconfigured it or left sensitive files exposed intentionally.
    
- **Telnet (Port 23)**: Microsoft Windows telnetd. Telnet transmits credentials in **plain text** over the network — another sign of poor security posture. However, it will allow shell access once we obtain credentials.
    
- **HTTP (Port 80)**: Microsoft IIS 7.5 hosting a "MegaCorp" website. The TRACE method is enabled (rarely needed, potential XSS vector). Initial enumeration with gobuster yields nothing useful — we'll skip deep HTTP recon and focus on FTP.
    

**Why This Works:**

The combination of anonymous FTP + exposed database files + unencrypted cached credentials is a **perfect storm** of misconfigurations. This is what happens when legacy systems meet poor operational security.

### FTP Enumeration

Since FTP allows anonymous connections, we connect with no authentication required:

```bash
ftp anonymous@10.129.98.207
```

Once inside, two folders are immediately visible:

![](/assets/img/access/Pasted_image_20261002001707.png)

**Analysis:** The presence of `Backups` and `Engineer` folders suggests organizational structure. Backups are critical—they often contain full database dumps and configuration files. The `Engineer` folder hints at technical documentation or access control systems.

In the **Backups** folder, find `backup.mdb`:

```bash
cd Backups
get backup.mdb
```

![](/assets/img/access/Pasted_image_20261002001739.png)

**Why This Matters:** `.mdb` files are Microsoft Access database files. These are often used in legacy Windows environments to store application data—including user credentials, configuration, and access logs. The fact that it's in a "Backups" folder with anonymous read access is a **critical oversight**.

In the **Engineer** folder, find `Access Control.zip`:

```bash
cd ../Engineer
get "Access Control.zip"
```

![](/assets/img/access/Pasted_image_20261002001808.png)

**Strategic Observation:** A `.zip` file in the Engineer folder is suspicious. ZIP files often contain email archives, configuration files, or documentation. Combined with the backup database, this suggests we're finding **data exfiltration opportunities** rather than active exploits.

---

## User

### Extract Credentials from backup.mdb

The `backup.mdb` file is a Microsoft Access database—a relic of 1990s-era business applications still used in legacy environments. We need to extract its contents.

Install mdbtools (allows command-line Access database inspection):

```bash
sudo apt update && sudo apt install mdbtools -y
```

List all tables in the database to understand its structure:

```bash
mdb-tables backup.mdb
```

![](/assets/img/access/Pasted_image_20261002002500.png)

**Database Structure Analysis:**

The output shows dozens of tables: `auth_user`, `USERINFO`, `personnel_empchange`, `SystemLog`, etc. This is a **ZKTeco access control system database**—a biometric/RFID access system commonly used in corporate buildings. The `auth_user` table is our target—it typically stores application-level credentials.

Export the `auth_user` table:

```bash
mdb-export backup.mdb auth_user
```

![](/assets/img/access/Pasted_image_20261002002541.png)

**Credential Extraction:**

```bash
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```

**Critical Finding:** Three users with plaintext passwords stored in a backup database:

- `admin:admin` — weak, probably not viable for system access
- `engineer:access4u@security` — **interesting** password pattern suggests a policy (access, security theme)
- `backup_admin:admin` — likely not a system account

The `engineer` credentials stand out. The password `access4u@security` follows a naming pattern matching the machine name "Access" and the ZIP file name. **This is likely the password for the encrypted ZIP file.**

### Decrypt Access Control.zip

The ZIP file is password-protected. Standard `unzip` often fails on Windows-created ZIPs due to compression method incompatibilities. We use `7z` (p7zip), which handles non-standard compression:

```bash
7z x "Access Control.zip"
```

![](/assets/img/access/Pasted_image_20261002003110.png)

Enter password: `access4u@security`

**Why This Works:**

The password we found in the database (`access4u@security`) works—this confirms credential reuse across the system. The ZIP file was likely created by the engineer account and password-protected with their stored credential.

The extracted file is `Access Control.pst` — a **Microsoft Outlook email folder** (OLE compound document format). PST files are backups of an Outlook mailbox and often contain **sensitive information: passwords, system documentation, access instructions sent via email**.

### Extract Email from PST

PST files are binary OLE documents. We need to convert to a plaintext-readable format. Install pst-utils:

```bash
sudo apt install pst-utils -y
```

Convert PST to mbox format (standard Unix email archive):

```bash
readpst Access\ Control.pst
```

Output:

```
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
```

This generates `Access Control.mbox`. mbox is plaintext—we can read it with `cat`, `grep`, or an email client. For structured viewing, use `mutt`:

```bash
mutt -Rf Access\ Control.mbox
```

Where `-R` opens read-only (no accidental modifications) and `-f` specifies the file.

Navigate to the email and view its contents:

![](/assets/img/access/Pasted_image_20261002004125.png)

**Email Analysis:**

The email reveals the password for the "security" account:

```
Hi there,

The password for the "security" account has been changed to 4Cc3ssC0ntr0ller.  
Please ensure this is passed on to your engineers.  

Regards,

John
```

**Critical Insight:** This is an internal communication where an administrator (John) notifies engineers of a password change. The **password is sent via unencrypted email** and **stored in a backup PST file on an anonymous FTP share**. This violates every security best practice:

- Passwords should never be transmitted via email
- Backup files should never be accessible without authentication
- The "security" account is likely a system service account with elevated privileges

**Credentials obtained**: `security:4Cc3ssC0ntr0ller`

### Telnet Shell as security

We have credentials (`security:4Cc3ssC0ntr0ller`) and an open Telnet service. Telnet is **inherently insecure**—it transmits credentials in plaintext over the network. However, it works for shell access.

Connect via Telnet:

```bash
telnet 10.129.98.207
```

![](/assets/img/access/Pasted_image_20261002004300.png)

**Login Flow:**

- Service prompts for username
- Enter: `security`
- Service prompts for password
- Enter: `4Cc3ssC0ntr0ller`
- Telnet presents a Windows command shell

We now have interactive shell access as the `security` user (NT AUTHORITY\security in Windows terminology).

Retrieve the user flag from the Desktop:

```powershell
cd Desktop
type user.txt
```

![](/assets/img/access/Pasted_image_20261002004409.png)

**Current Status:** User-level shell obtained. Next objective: escalate to Administrator.

---

## Root

### Overview - DPAPI (Data Protection API)

**What is DPAPI?**

DPAPI is a Microsoft cryptographic API that encrypts sensitive data at the OS level. When a user logs into Windows interactively (or uses `runas /savecred`), Windows caches the credentials in the user's profile for future automatic authentication.

**Why It's Vulnerable:**

- If we have the user's password (which we do: `security:4Cc3ssC0ntr0ller`)
- We can decrypt the master key using the password + SID
- We can then decrypt any cached credentials for that user
- If Administrator credentials were cached, we get full system access
- 
### DPAPI Credential Extraction

Cached credentials for the Administrator account are stored in DPAPI-encrypted format. Two files are needed:

1. **Master Key**: Located at `C:\Users\security\AppData\Roaming\Microsoft\Protect\[SID]\`
2. **Credential Blob**: Located at `C:\Users\security\AppData\Roaming\Microsoft\Credentials\`

The SID (Security Identifier) is `S-1-5-21-953262931-566350628-63446256-1001` (seen in folder names).

#### Exfiltrate Master Key

Navigate to the DPAPI protect directory:

```powershell
cd C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001
dir /a
```

![](/assets/img/access/Pasted_image_20261002004704.png)

**What We See:**

- `0792c32e-48a5-4fe3-8b43-d93d64590580` — GUID-named file containing the encrypted master key
- `Preferred` — metadata file indicating which master key is active

These GUID names are randomly generated by Windows during profile creation. The actual file is binary and encrypted.

To extract the binary file to our Linux machine, we encode it in base64 (text-safe format):

```powershell
certutil -encode 0792c32e-48a5-4fe3-8b43-d93d64590580 output
type output
```

![](/assets/img/access/Pasted_image_20261002004809.png)

**Why Base64?**

Binary files can't be reliably transmitted through text interfaces (Telnet, paste buffers, etc.). Base64 encoding converts binary to ASCII-printable text. We'll decode it on our Linux machine to restore the binary.

Copy the entire base64 output and paste it into a local file:

```bash
# Paste the base64 output into masterkey.b64, then decode:
cat masterkey.b64 | base64 -d > masterkey
```

Now we have the encrypted binary master key file locally.

#### Exfiltrate Credential Blob

Navigate to the credentials directory:

```powershell
cd C:\Users\security\AppData\Roaming\Microsoft\Credentials
dir /a
```

![](/assets/img/access/Pasted_image_20261002005141.png)

**What We See:**

- `51AB168BE4BDB3A603DADE4F8CA81290` — GUID-named file containing an encrypted credential blob

This is the cached credential data—likely containing Administrator credentials given its size (538 bytes is typical for a domain credential).

Encode it in base64:

```powershell
certutil -encode 51AB168BE4BDB3A603DADE4F8CA81290 output
type output
```

![](/assets/img/access/Pasted_image_20261002005151.png)

Copy to a local file and decode:

```bash
cat cred.b64 | base64 -d > 51AB168BE4BDB3A603DADE4F8CA81290
```

Now we have both encrypted files locally:

- `masterkey` — encrypted master key
- `51AB168BE4BDB3A603DADE4F8CA81290` — encrypted credential blob

Next: decrypt the master key using the security user's password.

### Decrypt Master Key with DPAPI

Now we use impacket's dpapi module on our Linux machine to decrypt the master key. This requires:

- The encrypted master key file
- The security user's password: `4Cc3ssC0ntr0ller`
- The security user's SID: `S-1-5-21-953262931-566350628-63446256-1001`

```bash
impacket-dpapi masterkey -file masterkey -password 4Cc3ssC0ntr0ller -sid S-1-5-21-953262931-566350628-63446256-1001
```

![](/assets/img/access/Pasted_image_20261002010502.png)

**Decryption Process Explained:**

DPAPI derives a key from:

1. User's NTLM hash (derived from password `4Cc3ssC0ntr0ller`)
2. User's SID (identifies which user)
3. Machine secrets stored on the local system

impacket implements this logic and decrypts the master key without needing access to the machine—only the password and SID.

**Output Analysis:**

The tool outputs the decrypted master key (a 256-bit AES key):

```
b360fa5dfea278892070f4d086d47ccf5ae30f7206af0927c33b13957d44f0149a128391c4344a9b7b9c9e2e5351bfaf94a1a715627f27ec9fafb17f9b4af7d2
```

This key is the cryptographic key that protects all cached credentials for this user. With it, we can decrypt the Administrator credentials.

### Decrypt Credentials Blob

Now we use the decrypted master key to unlock the cached Administrator credentials:

```bash
impacket-dpapi credential -file 51AB168BE4BDB3A603DADE4F8CA81290 -key 0xb360fa5dfea278892070f4d086d47ccf5ae30f7206af0927c33b13957d44f0149a128391c4344a9b7b9c9e2e5351bfaf94a1a715627f27ec9fafb17f9b4af7d2
```

![](/assets/img/access/Pasted_image_20261002010546.png)

**Decryption Output Analysis:**

The tool decrypts the credential blob and reveals:

```
TargetName     : Domain:interactive=ACCESS\Administrator
UserName       : ACCESS\Administrator
CredentialBlob : 55Acc3ssS3cur1ty@megacorp
```

**What This Means:**

- **TargetName**: `Domain:interactive=ACCESS\Administrator` — This is an interactive logon (human login, not service). The `Domain:interactive=` prefix indicates cached credentials for interactive use.
- **UserName**: Full credential target is the Administrator account
- **CredentialBlob**: The actual password: `55Acc3ssS3cur1ty@megacorp`


**Credentials obtained**: `Administrator:55Acc3ssS3cur1ty@megacorp`

### Telnet Shell as Administrator

With the Administrator credentials (`Administrator:55Acc3ssS3cur1ty@megacorp`), we connect via Telnet:

```bash
telnet 10.129.98.207
```

At the login prompt:

- Username: `administrator`
- Password: `55Acc3ssS3cur1ty@megacorp`

We now have a shell running as NT AUTHORITY\SYSTEM (or with Administrator privileges).

Retrieve the root flag from the Administrator's Desktop:

```powershell
cd Desktop
type root.txt
```

![](/assets/img/access/Pasted_image_20261002010646.png)

---

## Summary

**Attack Chain & Vulnerability Exploitation:**

1. **Reconnaissance** → Identified FTP with anonymous access (critical misconfiguration), Telnet service, and IIS HTTP
2. **FTP Enumeration** → Downloaded `backup.mdb` and `Access Control.zip` from unauthenticated FTP (data exposure vulnerability)
3. **Database Extraction** → Used mdbtools to enumerate ZKTeco access control database, extracted password `access4u@security` from unencrypted `auth_user` table (credential storage vulnerability)
4. **ZIP Decryption** → Decompressed password-protected `Access Control.zip` using extracted password (credential reuse)
5. **Email Parsing** → Converted PST to mbox format, found sensitive email containing Administrator account password `4Cc3ssC0ntr0ller` (email-based credential transmission vulnerability)
6. **User Shell** → Connected via plaintext Telnet as `security` user with extracted credentials
7. **DPAPI Reconnaissance** → Identified cached Administrator credentials in `C:\Users\security\AppData\Roaming\Microsoft\Credentials\` (credential caching vulnerability)
8. **Master Key Extraction** → Exfiltrated DPAPI master key and encrypted credentials blob via base64 encoding
9. **Master Key Decryption** → Used impacket-dpapi with security user's password to decrypt DPAPI master key
10. **Credential Decryption** → Used decrypted master key to extract plaintext Administrator password from credential blob
11. **Root Shell** → Authenticated as Administrator via Telnet, obtaining full system compromise

