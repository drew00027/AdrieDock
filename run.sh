#!/bin/bash

# Ensure Docker is installed
if ! command -v docker >/dev/null 2>&1; then
    echo "[!] Docker is not installed. Please install Docker first."
    exit 1
fi

# Start Docker daemon if not running
if ! docker info >/dev/null 2>&1; then
    echo "[*] Docker daemon not running. Starting..."
    sudo systemctl start docker
    sleep 5
    if ! docker info >/dev/null 2>&1; then
        echo "[!] Failed to start Docker daemon. Exiting."
        exit 1
    fi
fi

# Add current user to docker group (if not already)
if ! groups $USER | grep -qw docker; then
    echo "[*] Adding $USER to docker group..."
    sudo usermod -aG docker $USER
    echo "[*] You may need to log out and log back in for group changes to take effect."
fi

# Switch to docker group for current session
exec newgrp docker

# Stop and remove old containers
echo "[*] Removing old containers..."
docker rm -f wp-vuln wp-db 2>/dev/null || true

# Start MySQL container
echo "[*] Starting MySQL container..."
docker run -d --name wp-db -p 3306:3306 drw00027/vuln-mysql:latest

# Wait for MySQL to initialize
echo "[*] Waiting 15 seconds for MySQL to initialize..."
sleep 15

# Restore database if exists
if [ -f wordpress.sql ]; then
    echo "[*] Importing database dump..."
    docker exec -i wp-db mysql -uroot -proot wordpress < wordpress.sql
else
    echo "[!] No wordpress.sql found, WordPress will prompt for setup."
fi

# Start WordPress container
echo "[*] Starting WordPress container..."
docker run -d --name wp-vuln -p 9999:80 --link wp-db:db drw00027/vuln-wp:latest

# Wait for WordPress to start
sleep 15

# Copy plugin if exists
PLUGIN_DIR="./wp-content/plugins/wp-file-manager-unsafe"
if [ -d "$PLUGIN_DIR" ]; then
    echo "[*] Copying wp-file-manager-unsafe plugin..."
    docker cp "$PLUGIN_DIR" wp-vuln:/var/www/html/wp-content/plugins/
else
    echo "[!] Plugin folder not found, skipping copy."
fi

echo "[*] Setup complete! Access WordPress at http://localhost:9999/wp-admin"
