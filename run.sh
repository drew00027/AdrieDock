#!/bin/bash


echo "[*] Removing old containers..."
docker rm -f wp-vuln wp-db 2>/dev/null || true


echo "[*] Starting MySQL container..."
docker run -d --name wp-db -p 3306:3306 drw00027/vuln-mysql:latest


echo "[*] Waiting 10-15 seconds for MySQL to initialize..."
sleep 15


if [ -f wordpress.sql ]; then
    echo "[*] Importing database dump..."
    docker exec -i wp-db mysql -uroot -proot wordpress < wordpress.sql
else
    echo "[!] No wordpress.sql found, WordPress will prompt for setup."
fi


echo "[*] Starting WordPress container..."
docker run -d --name wp-vuln -p 9999:80 --link wp-db:db drw00027/vuln-wp:latest

# Wait a few seconds for WordPress to start
sleep 15


if [ -d ./wp-content/plugins/wp-file-manager-unsafe ]; then
    echo "[*] Copying wp-file-manager-unsafe plugin..."
    docker cp ./wp-content/plugins/wp-file-manager-unsafe wp-vuln:/var/www/html/wp-content/plugins/
else
    echo "[!] Plugin folder not found, skipping copy."
fi


echo "[*] Fixing plugin permissions..."
docker exec wp-vuln bash -c "chown -R www-data:www-data /var/www/html/wp-content/plugins/wp-file-manager-unsafe"
docker exec wp-vuln bash -c "chmod -R 755 /var/www/html/wp-content/plugins/wp-file-manager-unsafe"

echo "[*] Setup complete! Access WordPress at http://localhost:9999/wp-admin"
