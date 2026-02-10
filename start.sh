#!/bin/bash
#
# start.sh — Universal Security Stack Starter
# Starts & enables all installed Tier‑1 / Tier‑2 / future Tier‑3 tools
#

set -euo pipefail

LOG="/var/log/hardening-start.log"
exec > >(tee -a "$LOG") 2>&1

log() {
  echo "[+] $(date '+%F %T') $*"
}

svc_exists() {
  systemctl list-unit-files | grep -q "^$1"
}

start_svc() {
  local svc="$1"
  if svc_exists "$svc"; then
    systemctl enable "$svc" >/dev/null 2>&1 || true
    systemctl restart "$svc" >/dev/null 2>&1 || true
    log "Started: $svc"
  else
    log "Skipped (not installed): $svc"
  fi
}

log "===== HARDENING START PHASE BEGIN ====="

#
# FIREWALL & NETWORK
#
start_svc ufw
start_svc netfilter-persistent
start_svc nftables

#
# CORE SECURITY
#
start_svc fail2ban
start_svc auditd
start_svc apparmor
start_svc usbguard

#
# IDS / IPS
#
start_svc suricata
start_svc psad
start_svc snort

#
# ANTIVIRUS / MALWARE
#
start_svc clamav-daemon
start_svc clamav-freshclam

#
# DNS / PRIVACY
#
start_svc unbound
start_svc dnscrypt-proxy
start_svc stubby
start_svc tor
start_svc privoxy
start_svc i2pd

#
# MONITORING
#
start_svc monit
start_svc prometheus-node-exporter
start_svc collectd

#
# LOGGING
#
start_svc rsyslog

#
# VPN / TUNNEL
#
start_svc wg-quick@wg0
start_svc openvpn
start_svc strongswan

#
# CONTAINER SECURITY (future)
#
start_svc podman
start_svc docker

#
# IDS / HIDS (future Tier‑3)
#
start_svc wazuh-agent
start_svc ossec-hids
start_svc samhain

#
# FINAL STATUS
#
log "===== HARDENING START PHASE COMPLETE ====="

echo
echo "=== QUICK STATUS ==="
ufw status 2>/dev/null || true
systemctl --no-pager --failed || true
