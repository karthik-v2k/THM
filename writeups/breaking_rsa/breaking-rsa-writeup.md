# Breaking RSA - TryHackMe Room Writeup

**Room Link:** https://tryhackme.com/room/breakrsa

---

## Challenge Overview

Breaking RSA is a cryptography challenge focused on exploiting weak RSA key generation. The challenge demonstrates how RSA encryption can be broken when the two prime factors (p and q) used in key generation are very close to each other. This vulnerability can be exploited using **Fermat's Factorization Method**.

---

## Phase I: Active Reconnaissance

### Step 1: Port Scanning

Identify open services running on the target machine using Nmap:

```bash
nmap -A 10.49.170.222
```

**Results:**
- **Port 22/TCP (SSH)**: OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
  - RSA Key Fingerprint: 3072 bits
  - Supports ECDSA and ED25519 keys as well
  
- **Port 80/TCP (HTTP)**: nginx 1.18.0 (Ubuntu)
  - Server running "Jack Of All Trades" application
  
- **Network Distance**: 4 hops
- **Latency**: 0.025 seconds
- **Scan Duration**: 26.76 seconds

**Services Detected:**
- OS: Linux (Ubuntu)
- SSH Protocol: 2.0

---

### Step 2: Web Application Reconnaissance

#### Directory Enumeration

Enumerate web directories to find hidden endpoints:

```bash
gobuster dir --url http://10.49.170.222 -w /home/kvv/SecLists/Discovery/Web-Content/common.txt -t 150
```

**Enumeration Results:**
- **Wordlist Used**: common.txt (4750 entries)
- **Threads**: 150
- **Scan Status**: 100% Complete

**Directories Discovered:**
1. `/development/` (301 Redirect) - Size: 178 bytes
2. `/index.html` (200 OK) - Size: 384 bytes

---

### Step 3: Sensitive File Discovery

The `/development/` directory contains critical files:

**File 1: id_rsa.pub** (4096-bit RSA Public Key)
- Type: OpenSSH format RSA public key
- Key Size: 4096 bits
- Fingerprint (SHA256): DIqTDIhboydTh2QU6i58JP+5aDRnLBPT8GwVun1n0Co
- Algorithm: RSA

**File 2: log.txt** (Contains crucial vulnerability information)
- States that the two RSA prime factors (p and q) are close to each other
- Indicates the key is vulnerable to **Fermat's Factorization Method**

---

## Phase II: Cryptographic Analysis & Exploitation

### Understanding the Vulnerability

**Fermat's Factorization Method** exploits the mathematical property that when p and q are very close to each other:

- The difference (p - q) is small
- The average ((p + q) / 2) is close to √n
- This can be found relatively quickly compared to standard factorization

**Mathematical Formula:**
```
n = p × q
√n ≈ (p + q) / 2
```

### RSA Key Information Extracted

From the public key analysis:
- **Modulus (n)**: 960-digit number (approximately 3200-4000 bits of effective security)
- **Public Exponent (e)**: 65537 (standard value)
- **Prime Factor p (discovered)**: 1024-bit prime number
- **Prime Factor q (discovered)**: 1024-bit prime number
- **Private Exponent (d)**: Calculated from p, q, and e

---

### Step 4: Private Key Extraction

#### Python Script for Key Recovery

Using Fermat's factorization to recover p and q, then generate the private key:

```python
from Cryptodome.PublicKey import RSA
import libnum

def genkey(n, e, d, p, q):
    """Generate RSA private key from components"""
    private_key = RSA.construct((n, e, d, p, q), consistency_check=True)
    private_key = private_key.export_key(format='PEM').decode()
    return private_key

# RSA Key Components
n = 960343778775549488806716229688022562692463185460664314559819511657255292180827209174624059690060629715513180527734160798185034958883650709727032190772084959116259664047922715427522089353727952666824433207585440395813418471678775572995422248008108462980790558476993362919639516120538362516927622315187274971734081435230079153205750751020642956757117030852053008146976560531583447003355135460359928857010196241497604249151374353653491684214813678136396641706949128453526566651123162138806898116027920918258136713427376775618725136451984896300788465604914741872970173868541940675400325006679662030787570986695243903017923121105483935334289783830664260722704673471688470355268898058414366742781725580377180144541978809005281731232604162936015554289274471523038666760994260315829982230640668811250447030003462317740603204577123985618718687833015332554488836087898084147236609893032121172292368637672349405254772581742883431648376052937332995630141793928654990078967475194724151821689117026010445305375748604757116271353498403318409547515058838447618537811182917198454172161072247021099572638700461507432831248944781465511414308770376182766366160748136532693805002316728842876519091399408672222673058844554058431161474308624683491225222383

e = 65537

# Prime Factors (recovered from Fermat's factorization)
p = 30989413979221186440875537962143588279079180657276785773483163084840787431751925008409382782024837335054414229548213487269055726656919580388980384353939415484564294377142773553463724248812140196477077493185374579859773369113593661078143295090153526634169495633688691753691720088511452131593712380121967802013042678209312444897975134224456911144218687330712554564836016616829044029963400114373142702236623994027926718855592051277298418373056707389464234977873660836337340136755093657804153998347162906059312569124331219753644648657722107663012261197728061352359157767204739644300066112274629356310784052940617408518123

q = 30989413979221186440875537962143588279079180657276785773483163084840787431751925008409382782024837335054414229548213487269055726656919580388980384353939415484564294377142773553463724248812140196477077493185374579859773369113593661078143295090153526634169495633688691753691720088511452131593712380121967802013042678209312444897975134224456911144218687330712554564836016616829044029963400114373142702236623994027926718855592051277298418373056707389464234977873660836337340136755093657804153998347162906059312569124331219753644648657722107663012261197728061352359157767204739644300066112274629356310784052940617408516621

# Calculate private exponent
d = libnum.invmod(e, (p-1)*(q-1))

# Generate and export private key
private_key = genkey(n, e, d, p, q)
print(private_key)
```

**Key Parameters:**
- **Modulus (n)**: 16360-bit number (approximately 4900 decimal digits)
- **Public Exponent (e)**: 65537 (0x10001)
- **Prime p**: 1024-bit prime
- **Prime q**: 1024-bit prime (nearly identical to p - vulnerability indicator)
- **Private Exponent (d)**: Calculated using modular inverse

---

## Phase III: Remote Access & Flag Capture

### Step 5: SSH Access Using Recovered Key

With the recovered private key, authenticate to the SSH service as root:

```bash
ssh -i private_rsa root@10.49.170.222
```

**Authentication Details:**
- **User**: root
- **Key File**: private_rsa (generated from recovered parameters)
- **Authentication Method**: RSA Public Key Authentication
- **Connection Status**: ✅ Successful

**System Information:**
- **OS**: Ubuntu 20.04.6 LTS
- **Kernel**: Linux 5.15.0-138-generic (x86_64)
- **SSH Access**: Granted to root user
- **Last Login**: May 11, 2025 from 10.23.8.228
- **System Load**: 0.0
- **Memory Usage**: 15%
- **Disk Usage**: 81.4% of 4.84GB

---

### Step 6: Flag Retrieval

```bash
root@ip-10-49-170-222:~# ls
flag  snap
root@ip-10-49-170-222:~# cat flag
```

**🚩 FLAG CAPTURED:**
```
breakingRSAissuperfun20220809134031
```

---

## Vulnerability Summary

| Component | Details |
|-----------|---------|
| **Vulnerability Type** | Weak RSA Key Generation |
| **Root Cause** | Prime factors p and q are extremely close in value |
| **Exploitation Method** | Fermat's Factorization Algorithm |
| **Key Size** | 4096-bit RSA key |
| **Severity** | 🔴 CRITICAL |
| **Impact** | Complete cryptographic compromise - private key recovery |

---

## Key Takeaways

1. **RSA Security Depends on p ≠ q**: When prime factors are close, factorization becomes feasible
2. **Fermat's Method**: Highly effective against poorly generated RSA keys
3. **Importance of Key Generation**: Cryptographic libraries must use proper randomization
4. **Cryptanalysis Skills**: Understanding mathematical properties of encryption is crucial
5. **Defense-in-Depth**: Strong cryptography alone isn't enough without proper implementation

---

## References

1. **Fermat's Factorization Algorithm**: https://medium.com/@phiphatchomchit/fermat-factorization-algorithm-can-break-poor-rsa-encryption-3c657848cc87
2. **Breaking RSA Implementation**: https://github.com/amnigam/SharedScripts/tree/main/breakingRSA
3. **RSA Cryptography**: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
4. **PyCryptodome Documentation**: https://pycryptodome.readthedocs.io/

---

**Challenge Completed:** ✅ Flag captured successfully  
**Exploitation Chain:** Web Recon → File Discovery → Cryptanalysis → Key Recovery → SSH Access → System Compromise
