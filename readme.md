# WordPress Arbitrary File Upload Vulnerable Environment  
**(Customized Recreation of CVE-2020-25213 for Security Testing)**

This repository provides a controlled vulnerable WordPress environment designed to demonstrate an arbitrary file upload vulnerability.  
The vulnerable behavior is implemented in a custom plugin named **wp-file-manager-unsafe**, which recreates the core insecure functionality seen in **WordPress File Manager Plugin – CVE-2020-25213**, adapted for clarity and ease of testing.

The environment allows testing of arbitrary file upload exploitation, remote code execution (RCE), and exploit automation in a safe, isolated setup.

---

## Objectives

- Recreate an insecure WordPress plugin in a simplified and controlled manner  
- Demonstrate arbitrary file upload leading to RCE  
- Provide a reproducible Docker-based vulnerable environment  
- Supply an exploit script that automates upload and command execution  

---

## Features

- Insecure upload handler with:
  - No MIME validation  
  - No file extension checks  
  - Publicly accessible upload directory  
- Direct PHP payload upload and execution  
- Fully containerized (WordPress + MySQL via Docker Compose)  
- Supports `--url` for targeting remote or custom lab deployments  
- Startup delays included to prevent race conditions during exploitation  

---

## Environment Setup

Pre-run Manual Steps for Automation / Permissions
1. Add current user to Docker group
```bash
sudo usermod -aG docker $USER
```
2. Start Docker daemon if not running
```bash
sudo systemctl start docker
```
3. Activate Docker Group in current session
```bash
newgrp docker
```

Start the Vulnerable Environment (run.sh)
```bash
run.sh
```
What it does
1. Adds a new docker group if the tester has no permission to access Docker.
2. Stops and removes old Wordpress/MySQL containers
3. Starts the MySQL container
4. Waits 15 seconds for initialization
5. Automatically imports wordpress.sqli if present
6. Starts the WordPress container on port 9999
7. Waits 15 seconds for WordPress to boot
8. Copies the vulnereble plugin into the container

After the script completes, Wordpress is available at:
```
http://localhost:9999/wp-admin
```

This repository includes a helper script to quickly start the vulnerable WordPress environment.

Once running, WordPress is accessible at:

```
http://localhost:9999
```

*(Port can be modified inside `docker-compose.yml` if needed.)*

---

## Vulnerable Plugin Overview

The custom plugin `wp-file-manager-unsafe` intentionally enables:

- File uploads without validation  
- Lack of MIME verification  
- Lack of extension filtering  
- Direct write into a web-accessible directory:

```
/wp-content/plugins/wp-file-manager-unsafe/uploads/
```

This design allows uploading `.php` payloads, which can then be executed through the browser, resulting in remote code execution.

---

## Exploit Script (`script.py`)

The exploit script automates uploading a PHP payload and interacting with it.

### Usage

```bash
python3 script.py payload.php --url http://TARGET
```

### What it does

- Uploads the specified payload  
- Identifies and prints the upload location  
- Displays the accessible shell URL  
- Opens an interactive mode to execute commands through the uploaded payload  

---

## Example

```bash
python3 script.py payload.php --url http://localhost:9999
```

---

## Requirements

- Python 3  
- `requests` library  

Install dependency:

```bash
pip install requests
```

---

## Disclaimer

This environment is intended strictly for **authorized security testing, research, and educational use**.  
Do not deploy it in production environments.
