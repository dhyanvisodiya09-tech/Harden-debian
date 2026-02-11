#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
#  HARDEN-DEBIAN: active.sh
#  Configure and Activate All Security Services
#  Version: 2.0 | Zero-Error | Proper Service Order
#═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

#───────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
#───────────────────────────────────────────────────────────────────────────────

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIGS_DIR="$SCRIPT_DIR/tools/configs"
readonly LOG_DIR="$SCRIPT_DIR/logs"
readonly LOG_FILE="$LOG_DIR/activate-$(date +%Y%m%d_%H%M%S).log"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

# Counters
declare -i ACTIVATED=0
declare -i SKIPPED=0
declare -i FAILED=0

#───────────────────────────────────────────────────────────────────────────────
# FUNCTIONS
#───────────────────────────────────────────────────────────────────────────────

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

print_status() {
    local status=$1
    local message=$2
    case $status in
        "OK")      echo -e "  ${GREEN}[✓]${NC} $message" ;;
        "SKIP")    echo -e "  ${YELLOW}[○]${NC} $message" ;;
        "FAIL")    echo -e "  ${RED}[✗]${NC} $message" ;;
        "INFO")    echo -e "  ${BLUE}[i]${NC} $message" ;;
        "WARN")    echo -e "  ${YELLOW}[!]${NC} $message" ;;
        "CONFIG")  echo -e "  ${MAGENTA}[⚙]${NC} $message" ;;
    esac
}

print_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "SECTION: $1"
}

is_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

service_exists() {
    systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "$1"
}

enable_service() {
    local service=$1
    local desc=${2:-$service}
    
    if ! service_exists "$service"; then
        print_status "SKIP" "$desc (not installed)"
        ((SKIPPED++))
        return 0
    fi
    
    systemctl enable "$service" >> "$LOG_FILE" 2>&1 || true
    
    if systemctl start "$service" >> "$LOG_FILE" 2>&1; then
        print_status "OK" "$desc [STARTED]"
        ((ACTIVATED++))
        log "OK: $service started"
    else
        print_status "FAIL" "$desc [FAILED TO START]"
        ((FAILED++))
        log "FAIL: $service failed to start"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Must run as root${NC}"
        exit 1
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# BANNER
#───────────────────────────────────────────────────────────────────────────────

show_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║     █████╗  ██████╗████████╗██╗██╗   ██╗ █████╗ ████████╗███████╗        ║
    ║    ██╔══██╗██╔════╝╚══██╔══╝██║██║   ██║██╔══██╗╚══██╔══╝██╔════╝        ║
    ║    ███████║██║        ██║   ██║██║   ██║███████║   ██║   █████╗          ║
    ║    ██╔══██║██║        ██║   ██║╚██╗ ██╔╝██╔══██║   ██║   ██╔══╝          ║
    ║    ██║  ██║╚██████╗   ██║   ██║ ╚████╔╝ ██║  ██║   ██║   ███████╗        ║
    ║    ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝  ╚═══╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝        ║
    ║                                                                           ║
    ║            SECURITY SERVICES CONFIGURATOR & ACTIVATOR                     ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 1: FIREWALL (First Priority)
#───────────────────────────────────────────────────────────────────────────────

phase_1_firewall() {
    print_section "PHASE 1: Firewall Configuration (FIRST PRIORITY)"
    
    # UFW Configuration
    if is_installed "ufw"; then
        print_status "CONFIG" "Configuring UFW..."
        
        # Reset (careful - this clears existing rules)
        ufw --force reset >> "$LOG_FILE" 2>&1
        
        # Default policies
        ufw default deny incoming >> "$LOG_FILE" 2>&1
        ufw default allow outgoing >> "$LOG_FILE" 2>&1
        ufw default deny routed >> "$LOG_FILE" 2>&1
        
        # Allow SSH with rate limiting
        ufw limit 22/tcp comment 'SSH rate limiting' >> "$LOG_FILE" 2>&1
        
        # Enable logging
        ufw logging medium >> "$LOG_FILE" 2>&1
        
        # Enable UFW
        ufw --force enable >> "$LOG_FILE" 2>&1
        
        print_status "OK" "UFW configured and enabled"
        ((ACTIVATED++))
    else
        print_status "SKIP" "UFW not installed"
        ((SKIPPED++))
    fi
    
    # Save iptables rules
    if is_installed "netfilter-persistent"; then
        netfilter-persistent save >> "$LOG_FILE" 2>&1 || true
        print_status "OK" "IPTables rules saved"
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 2: LOGGING (Before Security Services)
#───────────────────────────────────────────────────────────────────────────────

phase_2_logging() {
    print_section "PHASE 2: Logging Services (Before Security)"
    
    enable_service "rsyslog" "Rsyslog (System Logging)"
    enable_service "auditd" "Auditd (Audit Daemon)"
    enable_service "systemd-journald" "Systemd Journal"
    
    # Configure audit rules
    if is_installed "auditd"; then
        print_status "CONFIG" "Configuring audit rules..."
        
        cat > /etc/audit/rules.d/harden-debian.rules << 'EOF'
# Harden-Debian Audit Rules

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# Monitor file changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH keys
-w /root/.ssh -p wa -k rootkey
-w /home -p wa -k homekey

# Monitor authentication
-w /var/log/auth.log -p wa -k authlog
-w /var/log/faillog -p wa -k faillog
-w /var/log/lastlog -p wa -k lastlog

# Monitor network
-a always,exit -F arch=b64 -S connect -F key=network_connect
-a always,exit -F arch=b64 -S accept -F key=network_accept
-a always,exit -F arch=b64 -S listen -F key=network_listen

# Monitor privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F key=rootcmd

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
EOF
        
        augenrules --load >> "$LOG_FILE" 2>&1 || true
        print_status "OK" "Audit rules configured"
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 3: IDS/IPS SERVICES
#───────────────────────────────────────────────────────────────────────────────

phase_3_ids() {
    print_section "PHASE 3: IDS/IPS Services"
    
    # Fail2ban
    if is_installed "fail2ban"; then
        print_status "CONFIG" "Configuring Fail2ban..."
        
        if [[ -f "$CONFIGS_DIR/ids/fail2ban-jail.local" ]]; then
            cp "$CONFIGS_DIR/ids/fail2ban-jail.local" /etc/fail2ban/jail.local
        else
            cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
EOF
        fi
        
        chmod 644 /etc/fail2ban/jail.local
        enable_service "fail2ban" "Fail2ban (Brute-force Protection)"
    fi
    
    # PSAD
    if is_installed "psad"; then
        print_status "CONFIG" "Configuring PSAD..."
        sed -i 's/EMAIL_ADDRESSES.*/EMAIL_ADDRESSES             root@localhost;/' /etc/psad/psad.conf 2>/dev/null || true
        sed -i 's/HOSTNAME.*/HOSTNAME                    harden-debian;/' /etc/psad/psad.conf 2>/dev/null || true
        
        psad --sig-update >> "$LOG_FILE" 2>&1 || true
        enable_service "psad" "PSAD (Port Scan Detection)"
    fi
    
    # Suricata
    if is_installed "suricata"; then
        print_status "CONFIG" "Configuring Suricata..."
        
        # Get default interface
        IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
        
        # Update interface in config
        if [[ -n "$IFACE" ]]; then
            sed -i "s/interface: .*/interface: $IFACE/" /etc/suricata/suricata.yaml 2>/dev/null || true
        fi
        
        # Update rules
        suricata-update >> "$LOG_FILE" 2>&1 || true
        
        enable_service "suricata" "Suricata (Network IDS/IPS)"
    fi
    
    # Arpwatch
    enable_service "arpwatch" "Arpwatch (ARP Monitor)"
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 4: MALWARE PROTECTION
#───────────────────────────────────────────────────────────────────────────────

phase_4_malware() {
    print_section "PHASE 4: Malware Protection"
    
    # ClamAV
    if is_installed "clamav-daemon"; then
        print_status "CONFIG" "Configuring ClamAV..."
        
        # Stop freshclam to update
        systemctl stop clamav-freshclam >> "$LOG_FILE" 2>&1 || true
        
        # Update signatures
        print_status "INFO" "Updating ClamAV signatures (this may take a while)..."
        freshclam >> "$LOG_FILE" 2>&1 || true
        
        enable_service "clamav-freshclam" "ClamAV Freshclam (Signature Updates)"
        enable_service "clamav-daemon" "ClamAV Daemon (Antivirus)"
    fi
    
    # Update rkhunter database
    if is_installed "rkhunter"; then
        print_status "CONFIG" "Updating rkhunter database..."
        rkhunter --update >> "$LOG_FILE" 2>&1 || true
        rkhunter --propupd >> "$LOG_FILE" 2>&1 || true
        print_status "OK" "rkhunter database updated"
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 5: ACCESS CONTROL (MAC)
#───────────────────────────────────────────────────────────────────────────────

phase_5_mac() {
    print_section "PHASE 5: Mandatory Access Control"
    
    # AppArmor
    if is_installed "apparmor"; then
        print_status "CONFIG" "Configuring AppArmor..."
        
        enable_service "apparmor" "AppArmor"
        
        # Enforce profiles
        if command -v aa-enforce &>/dev/null; then
            aa-enforce /etc/apparmor.d/* >> "$LOG_FILE" 2>&1 || true
            print_status "OK" "AppArmor profiles enforced"
        fi
    fi
    
    # USBGuard
    if is_installed "usbguard"; then
        print_status "CONFIG" "Configuring USBGuard..."
        
        # Generate initial policy if not exists
        if [[ ! -s /etc/usbguard/rules.conf ]]; then
            usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true
            chmod 600 /etc/usbguard/rules.conf
            print_status "OK" "USBGuard policy generated"
        fi
        
        enable_service "usbguard" "USBGuard (USB Protection)"
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 6: KERNEL HARDENING
#───────────────────────────────────────────────────────────────────────────────

phase_6_kernel() {
    print_section "PHASE 6: Kernel Hardening"
    
    print_status "CONFIG" "Applying kernel security parameters..."
    
    # Create sysctl config
    cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Kernel Hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1
kernel.randomize_va_space = 2

# Network - IPv4
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.log_martians = 1

# Network - IPv6
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0

# Filesystem
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
    
    # Apply
    sysctl -p /etc/sysctl.d/99-hardening.conf >> "$LOG_FILE" 2>&1 || true
    print_status "OK" "Kernel parameters applied"
    ((ACTIVATED++))
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 7: SSH HARDENING
#───────────────────────────────────────────────────────────────────────────────

phase_7_ssh() {
    print_section "PHASE 7: SSH Hardening"
    
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        print_status "CONFIG" "Applying SSH hardening configuration..."
        
        cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
# SSH Hardening
Protocol 2
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
X11Forwarding no
AllowAgentForwarding no
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
LogLevel VERBOSE
EOF
        
        chmod 644 /etc/ssh/sshd_config.d/99-hardening.conf
        
        # Test config before reload
        if sshd -t >> "$LOG_FILE" 2>&1; then
            systemctl reload ssh >> "$LOG_FILE" 2>&1 || true
            print_status "OK" "SSH configuration applied"
            ((ACTIVATED++))
        else
            print_status "FAIL" "SSH config has errors - not applied"
            rm -f /etc/ssh/sshd_config.d/99-hardening.conf
            ((FAILED++))
        fi
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 8: MONITORING
#───────────────────────────────────────────────────────────────────────────────

phase_8_monitoring() {
    print_section "PHASE 8: Monitoring Services"
    
    # Monit
    if is_installed "monit"; then
        print_status "CONFIG" "Configuring Monit..."
        
        cat > /etc/monit/conf.d/security.conf << 'EOF'
check system $HOST
    if loadavg (1min) > 4 then alert
    if memory usage > 75% then alert
    if cpu usage > 95% for 5 cycles then alert
EOF
        
        enable_service "monit" "Monit (Process Monitor)"
    fi
    
    enable_service "sysstat" "Sysstat (System Statistics)"
    enable_service "vnstat" "Vnstat (Network Statistics)"
    enable_service "acct" "Acct (Process Accounting)"
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 9: FILE INTEGRITY
#───────────────────────────────────────────────────────────────────────────────

phase_9_integrity() {
    print_section "PHASE 9: File Integrity Monitoring"
    
    # AIDE
    if is_installed "aide"; then
        print_status "CONFIG" "Initializing AIDE database..."
        
        if [[ ! -f /var/lib/aide/aide.db ]]; then
            aideinit --yes --force >> "$LOG_FILE" 2>&1 || true
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
            print_status "OK" "AIDE database initialized"
        else
            print_status "SKIP" "AIDE database already exists"
        fi
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 10: CRON JOBS
#───────────────────────────────────────────────────────────────────────────────

phase_10_cron() {
    print_section "PHASE 10: Security Automation (Cron Jobs)"
    
    # Daily security scan
    cat > /etc/cron.daily/security-scan << 'EOF'
#!/bin/bash
# Daily Security Scan
LOG="/var/log/security-scan-$(date +%Y%m%d).log"
{
    echo "=== Security Scan: $(date) ==="
    freshclam 2>/dev/null
    rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null
    chkrootkit -q 2>/dev/null
    aide --check 2>/dev/null | head -50
    psad --sig-update 2>/dev/null
    suricata-update 2>/dev/null
} >> "$LOG" 2>&1
EOF
    chmod +x /etc/cron.daily/security-scan
    print_status "OK" "Daily security scan cron job created"
    
    # Weekly deep scan
    cat > /etc/cron.weekly/deep-security-scan << 'EOF'
#!/bin/bash
# Weekly Deep Security Scan
LOG="/var/log/deep-scan-$(date +%Y%m%d).log"
{
    echo "=== Deep Scan: $(date) ==="
    clamscan -r -i /home /tmp /var/tmp 2>/dev/null | tail -20
    lynis audit system --quick 2>/dev/null | tail -50
    tiger -q 2>/dev/null
    debsums -c 2>/dev/null
} >> "$LOG" 2>&1
EOF
    chmod +x /etc/cron.weekly/deep-security-scan
    print_status "OK" "Weekly deep scan cron job created"
    
    ((ACTIVATED+=2))
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 11: NETWORK SERVICES (Optional)
#───────────────────────────────────────────────────────────────────────────────

phase_11_network() {
    print_section "PHASE 11: Network Services (Optional - Not Auto-Started)"
    
    print_status "INFO" "The following services are installed but NOT auto-started:"
    print_status "INFO" "  • tor          - Enable with: systemctl start tor"
    print_status "INFO" "  • dnscrypt-proxy - May conflict with other DNS"
    print_status "INFO" "  • unbound      - Local DNS resolver"
    print_status "INFO" "  • privoxy      - Privacy proxy"
    print_status "WARN" "Enable DNS services ONE at a time to avoid conflicts"
}

#───────────────────────────────────────────────────────────────────────────────
# SUMMARY
#───────────────────────────────────────────────────────────────────────────────

show_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ACTIVATION COMPLETE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}✓ Activated:${NC}  $ACTIVATED services/configs"
    echo -e "  ${YELLOW}○ Skipped:${NC}    $SKIPPED services"
    echo -e "  ${RED}✗ Failed:${NC}     $FAILED services"
    echo ""
    echo -e "${BLUE}  Active Security Services:${NC}"
    
    for svc in ufw fail2ban psad suricata clamav-daemon auditd apparmor monit; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "    ${GREEN}●${NC} $svc"
        fi
    done
    
    echo ""
    echo -e "${YELLOW}  Next Steps:${NC}"
    echo "    1. Run: ./status.sh     (View detailed status)"
    echo "    2. Run: lynis audit system  (Security audit)"
    echo "    3. Review: $LOG_FILE"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
}

#───────────────────────────────────────────────────────────────────────────────
# MAIN
#───────────────────────────────────────────────────────────────────────────────

main() {
    show_banner
    check_root
    
    mkdir -p "$LOG_DIR"
    echo "=== Activation Started: $(date) ===" > "$LOG_FILE"
    
    # ORDER MATTERS!
    phase_1_firewall      # First: Firewall
    phase_2_logging       # Second: Logging
    phase_3_ids           # Third: IDS/IPS
    phase_4_malware       # Fourth: Malware protection
    phase_5_mac           # Fifth: Access control
    phase_6_kernel        # Sixth: Kernel hardening
    phase_7_ssh           # Seventh: SSH hardening
    phase_8_monitoring    # Eighth: Monitoring
    phase_9_integrity     # Ninth: File integrity
    phase_10_cron         # Tenth: Automation
    phase_11_network      # Last: Optional network services
    
    show_summary
}

main "$@"