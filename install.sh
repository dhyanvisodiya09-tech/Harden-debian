#!/bin/bash
#
# install.sh - Heavy Mode VPS Hardening (Tier 1 + Tier 2)
# Debian 11 safe, zero-error, heavy tools installation
#

set -euo pipefail

# Directories
TOOLS_DIR="/opt/security-tools"
CONFIG_DIR="/etc/security-tools"
LOG_FILE="/var/log/hardening-install.log"

exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

log() { echo "[$(date '+%F %T')] $*"; }
die() { log "FATAL: $*"; exit 1; }

# Ensure root
[[ $EUID -ne 0 ]] && die "Must run as root"
[[ ! -f /etc/debian_version ]] && die "Debian required"

# Create folders
mkdir -p "$TOOLS_DIR" "$CONFIG_DIR"
chmod 700 "$TOOLS_DIR" "$CONFIG_DIR"

# Non-interactive
export DEBIAN_FRONTEND=noninteractive

log "Updating apt package lists..."
apt-get update -qq

# Install function (skip errors)
install_pkg() {
    local pkg="$1"
    dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" && return
    log "Installing: $pkg"
    apt-get install -y -qq "$pkg" || log "WARN: $pkg unavailable, skipping..."
}

log "Installing Tier-1 tools (core security)"

# --- Tier 1 ---
for pkg in ufw iptables iptables-persistent nftables ipset conntrack \
           netfilter-persistent fail2ban psad suricata aide auditd \
           apparmor apparmor-utils apparmor-profiles usbguard clamav \
           clamav-daemon clamav-freshclam rkhunter chkrootkit lynis \
           yara tor torsocks dnscrypt-proxy stubby unbound monit; do
    install_pkg "$pkg"
done

log "Installing Tier-2 tools (heavy, optional)"

# --- Tier 2 ---
for pkg in firejail bubblewrap seccomp macchanger privoxy proxychains4 \
           i2pd arpwatch arpalert fwsnort logwatch logrotate borgbackup \
           restic rclone rsync; do
    install_pkg "$pkg"
done

log "Creating empty default config files (if missing)"

mkdir -p /etc/fail2ban /etc/psad /etc/aide /etc/clamav /etc/tor \
         /etc/usbguard /etc/monit /etc/stubby /etc/dnscrypt-proxy

touch /etc/fail2ban/jail.local
touch /etc/psad/psad.conf
touch /etc/aide/aide.conf
touch /etc/clamav/clamd.conf
touch /etc/tor/torrc
touch /etc/usbguard/rules.conf
touch /etc/monit/monitrc
touch /etc/stubby/stubby.yml
touch /etc/dnscrypt-proxy/dnscrypt-proxy.toml

log "Setting 700 permissions for config directories"
chmod -R 700 /etc/fail2ban /etc/psad /etc/aide /etc/clamav \
         /etc/tor /etc/usbguard /etc/monit /etc/stubby /etc/dnscrypt-proxy

log "Tier 1 + 2 installation complete. Run start.sh next to configure kernel and permissions."
