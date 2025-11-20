# WordPress Arbitrary File Upload Vulnerable Environment
This project sets up a vulnerable WordPress instance for testing an arbitrary file upload vulnerability in a custom plugin named **wp-file-manager-unsafe**.

The purpose is to demonstrate how an insecure file upload feature can lead to remote code execution (RCE).

---

## 📌 Features
- Vulnerable WordPress plugin with no file-type validation 
- Allows uploading PHP files directly 
- Uploaded files are stored in a web-accessible folder 
- Easy to test RCE payloads 
- Runs on Docker (WordPress + MySQL)

---

## 🚀 Setup Instructions

### 1. Start the environment
Make sure Docker is installed, then run:

```bash
docker-compose up -d
