#!/bin/bash

# --- Step 0: Remove old containers ---
echo "[*] Removing old containers..."
docker rm -f wp-vuln wp-db 2>/dev/null || true

# --- Step 1: Start MySQL container ---
echo "[*] Starting MySQL container..."
docker run -d --name wp-db -p 3306:3306 drw00027/vuln-mysql:latest

# --- Step 2: Wait for MySQL to initialize ---
echo "[*] Waiting 15 seconds for MySQL..."
sleep 15

# --- Step 3: Restore database if dump exists ---
if [ -f wordpress.sql ]; then
    echo "[*] Importing database dump..."
    docker exec -i wp-db mysql -uroot -proot wordpress < wordpress.sql
else
    echo "[!] No wordpress.sql found, WordPress will prompt for setup."
fi

# --- Step 4: Start WordPress container ---
echo "[*] Starting WordPress container..."
docker run -d --name wp-vuln -p 9999:80 --link wp-db:db drw00027/vuln-wp:latest

# --- Step 5: Wait for WordPress to start ---
echo "[*] Waiting 15 seconds for WordPress..."
sleep 15

# --- Step 6: Copy plugin safely ---
if [ -d ./wp-content/plugins/wp-file-manager-unsafe ]; then
    echo "[*] Copying wp-file-manager-unsafe plugin..."
    docker cp ./wp-content/plugins/wp-file-manager-unsafe wp-vuln:/var/www/html/wp-content/plugins/
    
    # --- Step 7: Fix permissions ---
    echo "[*] Fixing plugin permissions..."
    docker exec wp-vuln chown -R www-data:www-data /var/www/html/wp-content/plugins/wp-file-manager-unsafe
else
    echo "[!] Plugin folder not found, skipping copy."
fi

# --- Step 8: Wait a bit before activating plugin ---
echo "[*] Waiting 15 seconds before activating plugin..."
sleep 15

# --- Step 9: Install WP-CLI if missing ---
docker exec wp-vuln bash -c "command -v wp >/dev/null 2>&1 || (curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp)"

# --- Step 10: Activate plugin ---
docker exec wp-vuln bash -c "wp plugin activate wp-file-manager-unsafe --allow-root || echo '[!] Plugin activation failed. Check headers and permissions.'"

echo "[*] Setup complete! Access WordPress at http://localhost:9999/wp-admin"
