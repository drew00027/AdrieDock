# WordPress Arbitrary File Upload Vulnerable Environment
This project sets up a vulnerable WordPress instance for testing an arbitrary file upload vulnerability in a custom plugin named **wp-file-manager-unsafe**.

The purpose is to demonstrate how an insecure file upload feature can lead to remote code execution (RCE).

---

##  Features
- Vulnerable WordPress plugin with no file-type validation 
- Allows uploading PHP files directly 
- Uploaded files are stored in a web-accessible folder 
- Easy to test RCE payloads 
- Runs on Docker (WordPress + MySQL)

---

##  Setup Instructions

### 1. Start the environment
Make sure Docker is installed, then run:
```bash
sudo usermod -aG docker $USER
```
```bash
sudo chmod 666 /var/run/docker.sock
```
```bash
docker-compose up -d
```
Or
```
docker compose up
```
---

# WordPress File Manager Unsafe Exploit

A simple Python script that uploads a PHP web shell to vulnerable WordPress installations using the `wp-file-manager-unsafe` plugin.

## Usage
```bash
python3 script.py payload.php --url http://target.com
```

## How It Works
1. Uploads a PHP shell to the plugin's upload directory.
2. Prints the final shell URL.
3. Starts an interactive command mode so you can run commands remotely.

## Requirements
- Python 3
- requests library

Install dependency:
```bash
pip install requests
```

## Example
```bash
python3 script.py --url http://localhost:9999 --file payload.php
```

## Disclaimer
For lab and educational use only.
Only works with payload.php provided
