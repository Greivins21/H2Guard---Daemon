#!/bin/bash
set -e

echo "[*] Setting up NFQUEUE environment..."

# -----------------------------
# 1. Install required packages
# -----------------------------
echo "[*] Installing required packages..."

 apt update

 apt install -y \
build-essential \
rsync \
pkg-config \
libnetfilter-queue-dev \
libnfnetlink-dev \
libmnl-dev \
tcpdump \
nginx \
htop \
iftop \
nload \
sysstat \
net-tools \
iproute2 \
curl \
wget

# -----------------------------
# 2. Load NFQUEUE kernel module
# -----------------------------
echo "[*] Loading nfnetlink_queue module..."

 modprobe nfnetlink_queue

# Verify module
if lsmod | grep -q nfnetlink_queue; then
    echo "[+] Kernel module loaded"
else
    echo "[-] Failed to load nfnetlink_queue"
    exit 1
fi

# -----------------------------
# 3. Create nftables table (if not exists)
# -----------------------------
echo "[*] Creating nftables table if needed..."

 nft list table inet nfqdefense >/dev/null 2>&1 || \
 nft add table inet nfqdefense

# -----------------------------
# 4. Create chain (if not exists)
# -----------------------------
echo "[*] Creating input chain if needed..."

 nft list chain inet nfqdefense input >/dev/null 2>&1 || \
 nft add chain inet nfqdefense input \
'{ type filter hook input priority 0; policy accept; }'

 nft list chain inet nfqdefense output >/dev/null 2>&1 || \
 nft add chain inet nfqdefense output \
'{ type filter hook output priority 0; policy accept; }'

# Create blocked IPs set
 nft add set inet nfqdefense blocked_ips \
'{ type ipv4_addr; flags timeout; }'

# Add rule to drop packets from blocked IPs
 nft add rule inet nfqdefense input ip saddr @blocked_ips drop

# -----------------------------
# 5. Add NFQUEUE rule (if not exists)
# -----------------------------
echo "[*] Checking NFQUEUE rule..."

if  nft list chain inet nfqdefense input | grep -q "tcp dport 443.*queue num 0"; then
    echo "[+] NFQUEUE rule already exists"
else
    echo "[*] Adding NFQUEUE rule for incomingTCP port 443..."

     nft add rule inet nfqdefense input \
    tcp dport 443 queue num 0 bypass

    echo "[+] Rule added"
fi

if  nft list chain inet nfqdefense output | grep -q "tcp sport 443.*queue num 0"; then
    echo "[+] NFQUEUE rule already exists"
else
    echo "[*] Adding NFQUEUE rule for outgoing TCP port 443..."

     nft add rule inet nfqdefense output \
    tcp sport 443 queue num 0 bypass

    echo "[+] Rule added"
fi

# -----------------------------
# 6. Configure nginx to serve the web folder
# -----------------------------
echo "[*] Configuring nginx web server..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_SRC="$SCRIPT_DIR/source/web"
WEB_ROOT="/var/www/http2-rapid-reset"
NGINX_CONF="/etc/nginx/sites-available/http2-rapid-reset"

 mkdir -p "$WEB_ROOT"

if [ ! -d "$WEB_ROOT" ]; then
    echo "[-] Web folder not found at $WEB_ROOT"
    exit 1
fi

 rsync -av --delete "$WEB_SRC/" "$WEB_ROOT/"

 chown -R www-data:www-data "$WEB_ROOT"
 chmod -R 755 "$WEB_ROOT"

 tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    http2 on;
    server_name _;

    root /var/www/http2-rapid-reset;
    index index.html;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~* \.(js|css|svg|png|jpg|jpeg|gif|ico)$ {
        add_header Cache-Control "public, max-age=31536000, immutable";
    }

    location ~ /\.ht {
        deny all;
    }
}
EOF

 mkdir -p /etc/nginx/ssl
 openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt

 ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/http2-rapid-reset
 rm -f /etc/nginx/sites-enabled/default

 nginx -t
 systemctl restart nginx

# -----------------------------
# 7. Show final ruleset
# -----------------------------
echo "[*] Current nftables rules:"
 nft list ruleset

echo "[+] NFQUEUE setup completed successfully"
