---
title: "HTB - Delivery (Easy | Linux | Web)"
date: 2026-09-21 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, linux, osticket, mattermost, john, best64, mysql, vhost, john-rules]
description: "Abuse osTicket ticket emails to bypass Mattermost verification, grab SSH creds from chat, then crack a MySQL hash with John's best64 rules to escalate to root"
image:
  path: /assets/img/delivery.png
---

## **Recon**


```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome
8065/tcp open  unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.0 200 OK
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Content-Type: text/html; charset=utf-8
|     <title>Mattermost</title>
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Service Discovery Analysis

The Nmap scan reveals three key services running on the target machine:

- **SSH (Port 22):** OpenSSH 7.9p1 on Debian 10
- **HTTP (Port 80):** nginx 1.14.2 hosting a "Welcome" landing page — likely contains subdomain references
- **HTTP (Port 8065):** Mattermost 5.30.0 — the version is exposed in the `X-Version-Id` response header, a critical finding

**OS:** Linux (Debian 10) **Domain:** delivery.htb

Two things immediately stand out: **Mattermost on port 8065** with version 5.30.0 clearly exposed in HTTP headers, and **nginx on port 80** with a generic "Welcome" title that likely contains references to subdomains or other services. The combination of a ticket system and a Mattermost instance will be the core of the attack path — a creative chained exploitation rather than a traditional vulnerability.

We add the domain to `/etc/hosts`:

```bash
echo "<target> delivery.htb" | sudo tee -a /etc/hosts
```

---

## **User**

### Web Enumeration - HTTP (Port 80)

Accessing `http://delivery.htb/` reveals a landing page referencing two services: a **HelpDesk** portal and a **Mattermost** instance. The HelpDesk link points to `helpdesk.delivery.htb` — a new subdomain:

![](/assets/img/delivery/Pasted_image_20260922142456.png)

We add the new subdomain to `/etc/hosts`:

```bash
echo "<target> helpdesk.delivery.htb" | sudo tee -a /etc/hosts
```

### Overview - osTicket

**What is osTicket?** osTicket is a widely used open-source support ticket system. Organizations use it to manage customer or internal support requests. Users can submit tickets via email or web form, and the system automatically assigns them a ticket ID and a dedicated email address for correspondence. Staff can respond to tickets through the panel.

**Why is it relevant here?** osTicket automatically generates a unique email address per ticket in the format `[ticketID]@delivery.htb`. Any email sent to this address is added to the ticket thread and is visible to whoever submitted the ticket — without requiring email authentication. This means if we create a ticket and obtain its auto-generated email address, we can use it to receive verification emails from other services, effectively bypassing email verification requirements.

### osTicket - Ticket Submission for Email Address

Accessing `http://helpdesk.delivery.htb/` reveals an osTicket instance. We fill out the "Open a New Ticket" form with any name, email, and subject. The key goal here is not to actually get support — it's to obtain the ticket's auto-generated `@delivery.htb` email address:

![](/assets/img/delivery/Pasted_image_20260922143509.png)

After submitting the ticket, osTicket provides us with a unique ticket ID and its corresponding internal email address:

**Generated ticket email:** `1696032@delivery.htb`

This email address is the pivot point of the entire attack. Any email sent to `1696032@delivery.htb` will appear in the ticket thread, visible by checking the ticket status with our ticket ID and the email we used to open the ticket.

### Overview - Mattermost Account Verification Bypass

**What is Mattermost?** Mattermost is an open-source, self-hosted team messaging platform. New accounts typically require email verification before they can be used — the system sends a verification link to the provided email address.

**The Attack:** Mattermost requires a valid email to register. Normally, this stops attackers who don't control any `@delivery.htb` addresses. However, since osTicket gave us `1696032@delivery.htb` — and any email sent to it appears in the ticket thread — we can register on Mattermost using this address, then check the osTicket ticket status to retrieve the verification link without ever needing actual email access.

### Mattermost Registration via osTicket Email

We navigate to `http://delivery.htb:8065/` and register a new account using the osTicket-generated email `1696032@delivery.htb` as our address.

After registration, instead of checking an email inbox, we go back to osTicket and click **"Check Ticket Status"**, entering our original ticket ID and contact email. The Mattermost verification email appears inside the ticket thread:

![](/assets/img/delivery/Pasted_image_20260922144834.png)

![](/assets/img/delivery/Pasted_image_20260922144925.png)

We copy the verification link from the ticket thread and visit it in the browser:

![](/assets/img/delivery/Pasted_image_20260922145019.png)

Our Mattermost account is now verified and activated.

### Credential Discovery in Mattermost

Logging into Mattermost reveals internal team channels. In the `internal` channel, a staff member has posted credentials and notes that should never have been shared in a messaging platform:

![](/assets/img/delivery/Pasted_image_20260922145129.png)

**Credentials discovered:**

- `maildeliverer:Youve_G0t_Mail!` — osTicket/system credentials
- `PleaseSubscribe!` — a password hint mentioned alongside a note about using variations of this password for hashing

This second piece of information is especially interesting — the staff notes that the root password is a variation of `PleaseSubscribe!` using hashcat rules. We note this for later.

### SSH Access as maildeliverer

Testing the discovered credentials against SSH:

```bash
ssh maildeliverer@delivery.htb
```

![](/assets/img/delivery/Pasted_image_20260922150241.png)

A shell is established as `maildeliverer`. The user flag can now be retrieved.

---

## **Root**

### MySQL Credential Discovery

During enumeration we find the Mattermost configuration file at `/opt/mattermost/config/config.json`. This file contains the database connection string including MySQL credentials in plaintext:

![](/assets/img/delivery/Pasted_image_20260922153526.png)

Configuration files for self-hosted applications like Mattermost frequently store database credentials in plaintext — a common misconfiguration in production deployments.

### MySQL Enumeration

We connect to the local MySQL instance using the credentials found in `config.json`. The `-h 127.0.0.1` flag specifies the local MySQL server explicitly:

```bash
mysql -u 'mmuser' -p -h 127.0.0.1
```

Once connected, we enumerate the databases and locate the Mattermost database:

```bash
show databases;
use mattermost;
show tables;
SELECT * from Users;
```

![](/assets/img/delivery/Pasted_image_20260922155009.png)

The `Users` table contains bcrypt password hashes for all Mattermost users, including the `root` account. The root hash is extracted for offline cracking.

### Overview -  John Rules for Password Mutation

**What are password rules?** Password cracking tools like Hashcat and John the Ripper support "rules" — pattern transformations applied to a base wordlist to generate password variations. For example, rules can capitalize letters, add numbers, substitute characters (`a→@`, `o→0`, `e→3`), append years, or combine multiple transformations. This dramatically increases cracking efficiency against passwords based on known patterns.

**Why does this work here?** The Mattermost channel message specifically states that the root password is based on `PleaseSubscribe!` with common variations. This is a direct hint to use the known password as a base wordlist and apply mutation rules. John's `best64` ruleset contains 64 of the most commonly used password transformations — covering capitalization changes, number suffixes, character substitutions, and more.

### Password Cracking with John Rules

We create a base wordlist containing the hint password found in Mattermost:

```bash
echo "PleaseSubscribe!" > key.txt
```

We use John's `--stdout` mode with `best64` rules to generate all mutations of `PleaseSubscribe!` without actually cracking — just outputting the wordlist:

```bash
john --wordlist=key.txt --rules=best64 --stdout > wordlist.txt
```

This generates hundreds of variations like `Pleasesubscribe!`, `pleasesubscribe!`, `PleaseSubscribe!1`, `PleaseSubscribe!21`, `Pl3aseSubscrib3!`, etc.

We then use this generated wordlist to crack the root bcrypt hash:

```bash
john hash --wordlist=wordlist.txt
```

![](/assets/img/delivery/Pasted_image_20260922162202.png)

**Root password cracked:** `PleaseSubscribe!21`

### Privilege Escalation to Root

From the `maildeliverer` session, we switch to the root user using the cracked password:

```bash
su root
```

![](/assets/img/delivery/Pasted_image_20260922162319.png)

Full root access is achieved. The root flag can now be retrieved.

---

### Attack Chain Summary

1. **Reconnaissance:** Nmap identified nginx on port 80, and Mattermost 5.30.0 on port 8065 with version exposed in HTTP headers
2. **Subdomain Discovery:** Port 80 landing page referenced `helpdesk.delivery.htb` hosting an osTicket instance
3. **osTicket Ticket Creation:** Submitted a support ticket to obtain a system-generated `@delivery.htb` email address (`1696032@delivery.htb`)
4. **Mattermost Email Bypass:** Registered on Mattermost using the osTicket-generated email; retrieved the verification link from the osTicket ticket thread without needing real email access
5. **Credential Discovery:** Logged into Mattermost and found `maildeliverer:Youve_G0t_Mail!` credentials plus a hint that root's password is a variation of `PleaseSubscribe!`
6. **SSH Access:** Authenticated via SSH as `maildeliverer` using discovered credentials; retrieved user flag
7. **MySQL Enumeration:** Found MySQL credentials in `/opt/mattermost/config/config.json`; connected to local MySQL and extracted bcrypt hash for root from the Mattermost `Users` table
8. **Password Rule Cracking:** Used John the Ripper's `best64` rules on `PleaseSubscribe!` as base word to generate mutations; cracked root's bcrypt hash to `PleaseSubscribe!21`
9. **Root Access:** Used `su root` with cracked password and retrieved root flag