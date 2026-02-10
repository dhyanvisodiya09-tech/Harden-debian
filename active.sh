#!/bin/bash
#
# active.sh — Universal Security Status Dashboard
# Shows installed tools & service status for Tier‑1/2/3
#

set -euo pipefail

LOG="/var/log/hardening-active.log"
exec > >(tee -a "$LOG") 2>&1

log() { echo "[+] $(date '+%F %T') $*"; }

svc_exists() { systemctl list-unit-files | grep -q "^$1"; }
svc_status() {
    local svc="$1"
    if svc_exists "$svc"; then
        systemctl is-active "$svc" >/dev/null 2>&1 && echo "active" || echo "inactive"
    else
        echo "not installed"
    fi
}

log "===== HARDENING STATUS REPORT ====="

echo
echo "== FIREWALL & NETWORK =="
echo "UFW: $(svc_status ufw)"
echo "netfilter-persistent: $(svc_status netfilter-persistent)"
echo "nftables: $(svc_status nftables)"

echo
echo "== CORE SECURITY =="
echo "AppArmor: $(svc_status apparmor)"
echo "Fail2Ban: $(svc_status fail2ban)"
echo "Auditd: $(svc_status auditd)"
echo "USBGuard: $(svc_status usbguard)"

echo
echo "== IDS / IPS =="
echo "Suricata: $(svc_status suricata)"
echo "PSAD: $(svc_status psad)"
echo "Snort: $(svc_status snort)"
echo "Wazuh-Agent: $(svc_status wazuh-agent)"
echo "OSSEC-HIDS: $(svc_status ossec-hids)"
echo "Samhain: $(svc_status samhain)"

echo
echo "== ANTIVIRUS / MALWARE =="
echo "ClamAV: $(svc_status clamav-daemon)"
echo "FreshClam: $(svc_status clamav-freshclam)"
echo "RKHunter: $(command -v rkhunter >/dev/null && echo 'installed' || echo 'not installed')"
echo "ChkRootkit: $(command -v chkrootkit >/dev/null && echo 'installed' || echo 'not installed')"
echo "Lynis: $(command -v lynis >/dev/null && echo 'installed' || echo 'not installed')"

echo
echo "== DNS & PRIVACY =="
echo "Stubby: $(svc_status stubby)"
echo "DNSCrypt: $(svc_status dnscrypt-proxy)"
echo "Unbound: $(svc_status unbound)"
echo "Tor: $(svc_status tor)"
echo "Privoxy: $(svc_status privoxy)"
echo "I2Pd: $(svc_status i2pd)"

echo
echo "== VPN / TUNNEL =="
echo "WireGuard: $(svc_status wg-quick@wg0)"
echo "OpenVPN: $(svc_status openvpn)"
echo "StrongSwan: $(svc_status strongswan)"

echo
echo "== MONITORING =="
echo "Monit: $(svc_status monit)"
echo "Prometheus Node Exporter: $(svc_status prometheus-node-exporter)"
echo "Collectd: $(svc_status collectd)"
echo "Supervisor: $(svc_status supervisor)"

echo
echo "== LOGGING =="
echo "Rsyslog: $(svc_status rsyslog)"
echo "Logwatch: $(command -v logwatch >/dev/null && echo 'installed' || echo 'not installed')"

echo
echo "== CONTAINER SECURITY =="
echo "Podman: $(svc_status podman)"
echo "Docker: $(svc_status docker)"

echo
echo "== KERNEL HARDENING =="
echo "Kernel Modules blacklist: $( [[ -f /etc/modprobe.d/hardening-blacklist.conf ]] && echo 'configured' || echo 'missing' )"
echo "Sysctl hardening: $( [[ -f /etc/sysctl.d/99-hardening.conf ]] && echo 'configured' || echo 'missing' )"

echo
echo "== FAIL2BAN JAILS =="
if [[ -f /etc/fail2ban/jail.local ]]; then
    grep "^\[" /etc/fail2ban/jail.local | sed 's/\[//;s/\]//' || echo "none"
else
    echo "none"
fi

echo
echo "== QUICK STATUS SUMMARY =="
systemctl --no-pager --failed || echo "All running fine"

log "===== HARDENING STATUS REPORT COMPLETE ====="
