# WordPress Arbitrary File Upload Vulnerable Environment

This project sets up a vulnerable WordPress instance designed for testing an arbitrary file upload vulnerability in a custom plugin named **wp-file-manager-unsafe**.
The goal is to demonstrate how insecure upload handling can lead to remote code execution (RCE).

## Features

- Vulnerable WordPress plugin with no file-type validation
- Allows direct PHP file uploads
- Uploaded files are stored in a web-accessible directory
- Easy for testing RCE payloads
- Fully containerized using Docker (WordPress + MySQL)

## Project Structure

```
.
├── docker-compose.yml
├── wp-content/
│   └── plugins/
│       └── wp-file-manager-unsafe/
│           ├── wp-file-manager-unsafe.php
│           └── uploads/
├── script.py
└── payload.php
```

## Installation & Setup

### 1. Start the vulnerable environment

Make sure Docker is installed, then run:

```bash
docker-compose up -d
```

or:

```bash
docker compose up -d
```

WordPress will be available at:

```
http://localhost:9999
```

## Vulnerable Plugin Details

The plugin named `wp-file-manager-unsafe` contains:

- An insecure upload form
- No MIME checking
- No extension restrictions
- Files stored inside:

```
/wp-content/plugins/wp-file-manager-unsafe/uploads/
```

This allows direct upload of `.php` files and enables RCE when accessed through the browser.

## Exploit Script (script.py)

A Python script that uploads a PHP web shell to the vulnerable WordPress installation.

### Usage

```bash
python3 script.py --url http://TARGET --file payload.php
```

### What it does

- Uploads `payload.php` to the plugin upload directory
- Prints the final shell URL
- Starts an interactive command mode that sends commands through the web shell

## Requirements

- Python 3
- `requests` package

Install dependency:

```bash
pip install requests
```

## Example

```bash
python3 script.py payload.php --url http://localhost:9999
```
