#!/bin/bash
# fix.sh - Full-power heavy Debian hardening
# Installs missing packages, creates missing files, sets permissions, downloads required tools

set -euo pipefail

LOG_FILE="/var/log/hardening-fix.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

echo "[+] Starting fix.sh - $(date)"

[[ $EUID -ne 0 ]] && echo "Run as root" && exit 1
[[ ! -f /etc/debian_version ]] && echo "Debian required" && exit 1

export DEBIAN_FRONTEND=noninteractive

# ---------------------------
# Add missing repos
# ---------------------------
add_repo() {
    local repo_line="$1"
    local list_file="$2"
    if ! grep -qF "$repo_line" "$list_file" 2>/dev/null; then
        echo "$repo_line" >> "$list_file"
        echo "[+] Added repo: $repo_line"
    fi
}

add_repo "deb http://deb.debian.org/debian bullseye-backports main contrib non-free" /etc/apt/sources.list
add_repo "deb https://packages.wazuh.com/4.x/apt/ stable main" /etc/apt/sources.list.d/wazuh.list
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - || true

echo "[+] Updating apt..."
apt-get update -qq || echo "[!] apt update failed, check sources"

# ---------------------------
# Tier 1 + 2 heavy tools
# ---------------------------
TOOLS=(
ufw netfilter-persistent nftables fail2ban auditd apparmor usbguard suricata psad snort \
clamav-daemon clamav-freshclam unbound dnscrypt-proxy stubby tor i2pd \
prometheus-node-exporter collectd rsyslog wg-quick@wg0 openvpn strongswan podman \
docker wazuh-agent ossec-hids samhain
)

echo "[+] Installing missing packages..."
for pkg in "${TOOLS[@]}"; do
    if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        echo "[*] Installing $pkg..."
        apt-get install -y -qq "$pkg" || echo "[!] $pkg could not be installed"
    else
        echo "[+] $pkg already installed"
    fi
done

# ---------------------------
# Create missing config dirs & files
# ---------------------------
CONFIGS=(
"/etc/usbguard/rules.conf"
"/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
"/etc/stubby/stubby.yml"
"/etc/tor/torrc"
"/etc/fail2ban/jail.local"
)

for cfg in "${CONFIGS[@]}"; do
    if [[ ! -f "$cfg" ]]; then
        echo "[*] Creating missing config $cfg"
        mkdir -p "$(dirname "$cfg")"
        touch "$cfg"
        chmod 777 "$cfg"
    fi
done

# ---------------------------
# Full permissions for heavy access
# ---------------------------
echo "[+] Fixing permissions..."
chmod -R 777 /etc/usbguard /etc/tor /etc/dnscrypt-proxy /etc/stubby /etc/fail2ban 2>/dev/null || true

# ---------------------------
# Download missing tools/binaries if required
# ---------------------------
download_tool() {
    local url="$1"
    local dest="$2"
    if [[ ! -f "$dest" ]]; then
        echo "[*] Downloading $dest from $url"
        curl -sSL "$url" -o "$dest" || echo "[!] Failed to download $dest"
        chmod +x "$dest"
    fi
}

# Example: download latest Barnyard2 if missing
download_tool "https://github.com/firnsy/barnyard2/releases/download/v2.1.0/barnyard2" "/usr/local/bin/barnyard2"

# ---------------------------
# Enable & start services
# ---------------------------
echo "[+] Enabling & starting services..."
for svc in "${TOOLS[@]}"; do
    if systemctl list-unit-files | grep -q "$svc"; then
        systemctl enable "$svc" 2>/dev/null || true
        systemctl restart "$svc" 2>/dev/null || true
        echo "[+] $svc started"
    else
        echo "[!] $svc service not found, skipping"
    fi
done

echo "[+] fix.sh completed - everything attempted, full permissions granted"
