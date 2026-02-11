#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
#  HARDEN-DEBIAN: start.sh
#  Complete Security Toolkit Installer
#  Version: 2.0 | Debian 11 Compatible | Zero-Error | Idempotent
#═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail
IFS=$'\n\t'

#───────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
#───────────────────────────────────────────────────────────────────────────────

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_DIR="$SCRIPT_DIR/logs"
readonly TOOLS_DIR="$SCRIPT_DIR/tools"
readonly CONFIGS_DIR="$TOOLS_DIR/configs"
readonly BACKUP_DIR="/root/harden-backup-$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="$LOG_DIR/install-$(date +%Y%m%d_%H%M%S).log"
readonly EXTERNAL_TOOLS_DIR="/opt/security-tools"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Counters
declare -i INSTALLED=0
declare -i SKIPPED=0
declare -i FAILED=0
declare -i CONFIGURED=0

#───────────────────────────────────────────────────────────────────────────────
# FUNCTIONS
#───────────────────────────────────────────────────────────────────────────────

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Print with color
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

# Print section header
print_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "SECTION" "$1"
}

# Check if package is installed
is_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

# Install package with error handling
install_pkg() {
    local pkg=$1
    local desc=${2:-$pkg}
    
    if is_installed "$pkg"; then
        print_status "SKIP" "$desc (already installed)"
        ((SKIPPED++))
        log "SKIP" "$pkg already installed"
        return 0
    fi
    
    if apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1; then
        print_status "OK" "$desc"
        ((INSTALLED++))
        log "OK" "$pkg installed successfully"
        return 0
    else
        print_status "FAIL" "$desc (check log)"
        ((FAILED++))
        log "FAIL" "$pkg installation failed"
        return 1
    fi
}

# Create directory if not exists
ensure_dir() {
    [[ -d "$1" ]] || mkdir -p "$1"
}

# Backup file before modification
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").bak" 2>/dev/null || true
    fi
}

# Root check
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}╔════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ERROR: This script must be run as root    ║${NC}"
        echo -e "${RED}║  Usage: sudo ./start.sh                    ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════╝${NC}"
        exit 1
    fi
}

# Check Debian version
check_debian() {
    if [[ ! -f /etc/debian_version ]]; then
        echo -e "${RED}ERROR: This script is designed for Debian systems${NC}"
        exit 1
    fi
    local version=$(cat /etc/debian_version | cut -d. -f1)
    if [[ "$version" -lt 11 ]]; then
        echo -e "${YELLOW}WARNING: Script optimized for Debian 11+. You have Debian $version${NC}"
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
    ║   ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗                     ║
    ║   ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║                     ║
    ║   ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║                     ║
    ║   ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║                     ║
    ║   ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║                     ║
    ║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝                     ║
    ║                                                                           ║
    ║   ██████╗ ███████╗██████╗ ██╗ █████╗ ███╗   ██╗                          ║
    ║   ██╔══██╗██╔════╝██╔══██╗██║██╔══██╗████╗  ██║                          ║
    ║   ██║  ██║█████╗  ██████╔╝██║███████║██╔██╗ ██║                          ║
    ║   ██║  ██║██╔══╝  ██╔══██╗██║██╔══██║██║╚██╗██║                          ║
    ║   ██████╔╝███████╗██████╔╝██║██║  ██║██║ ╚████║                          ║
    ║   ╚═════╝ ╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝                          ║
    ║                                                                           ║
    ║                  SECURITY TOOLKIT INSTALLER v2.0                          ║
    ║                     Zero-Error • Idempotent                               ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

#───────────────────────────────────────────────────────────────────────────────
# INITIALIZATION
#───────────────────────────────────────────────────────────────────────────────

initialize() {
    show_banner
    check_root
    check_debian
    
    # Create directories
    ensure_dir "$LOG_DIR"
    ensure_dir "$BACKUP_DIR"
    ensure_dir "$TOOLS_DIR"
    ensure_dir "$CONFIGS_DIR"
    ensure_dir "$EXTERNAL_TOOLS_DIR"
    
    # Start logging
    echo "═══════════════════════════════════════════════════════════════" > "$LOG_FILE"
    echo "  HARDEN-DEBIAN INSTALLATION LOG" >> "$LOG_FILE"
    echo "  Started: $(date)" >> "$LOG_FILE"
    echo "  Host: $(hostname)" >> "$LOG_FILE"
    echo "═══════════════════════════════════════════════════════════════" >> "$LOG_FILE"
    
    print_status "INFO" "Log file: $LOG_FILE"
    print_status "INFO" "Backups: $BACKUP_DIR"
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 0: SYSTEM PREPARATION
#───────────────────────────────────────────────────────────────────────────────

phase_0_preparation() {
    print_section "PHASE 0: System Preparation"
    
    # Backup critical system files
    print_status "INFO" "Creating backups..."
    backup_file "/etc/ssh/sshd_config"
    backup_file "/etc/sysctl.conf"
    backup_file "/etc/fstab"
    
    if [[ -d /etc/iptables ]]; then
        cp -r /etc/iptables "$BACKUP_DIR/" 2>/dev/null || true
    fi
    if [[ -d /etc/ufw ]]; then
        cp -r /etc/ufw "$BACKUP_DIR/" 2>/dev/null || true
    fi
    print_status "OK" "Critical configs backed up"
    
    # Update package lists
    print_status "INFO" "Updating package lists..."
    if apt-get update >> "$LOG_FILE" 2>&1; then
        print_status "OK" "Package lists updated"
    else
        print_status "WARN" "Package update had warnings (continuing)"
    fi
    
    # Upgrade system (optional)
    print_status "INFO" "Upgrading system packages..."
    if apt-get upgrade -y >> "$LOG_FILE" 2>&1; then
        print_status "OK" "System upgraded"
    else
        print_status "WARN" "Upgrade had warnings (continuing)"
    fi
    
    # Install base dependencies
    print_status "INFO" "Installing base dependencies..."
    local base_deps=(
        "software-properties-common"
        "apt-transport-https"
        "ca-certificates"
        "curl"
        "wget"
        "git"
        "gnupg"
        "lsb-release"
        "build-essential"
    )
    
    for dep in "${base_deps[@]}"; do
        install_pkg "$dep"
    done
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 1: CORE SYSTEM HARDENING
#───────────────────────────────────────────────────────────────────────────────

phase_1_core_hardening() {
    print_section "PHASE 1: Core System Hardening (Firewall, Audit, Logging)"
    
    local packages=(
        "ufw:UFW Firewall"
        "iptables:IPTables"
        "iptables-persistent:IPTables Persistent"
        "nftables:NFTables Framework"
        "netfilter-persistent:Netfilter Persistent"
        "ipset:IP Sets"
        "conntrack:Connection Tracking"
        "auditd:Audit Daemon"
        "audispd-plugins:Audit Dispatcher Plugins"
        "rsyslog:System Logging"
        "logrotate:Log Rotation"
        "systemd-coredump:Core Dump Handler"
        "debsums:Debian Checksums"
        "apt-listchanges:APT Change Notifications"
        "needrestart:Restart Checker"
        "unattended-upgrades:Auto Security Updates"
        "apt-show-versions:Package Version Display"
        "debian-goodies:Debian Utilities"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 2: INTRUSION DETECTION / PREVENTION (IDS/IPS)
#───────────────────────────────────────────────────────────────────────────────

phase_2_ids_ips() {
    print_section "PHASE 2: Intrusion Detection & Prevention (IDS/IPS)"
    
    local packages=(
        "fail2ban:Fail2Ban Brute-Force Protection"
        "psad:Port Scan Attack Detector"
        "suricata:Suricata Network IDS/IPS"
        "arpwatch:ARP Traffic Monitor"
        "arpalert:ARP Alerter"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
    
    # Install suricata-update if suricata installed
    if is_installed "suricata"; then
        install_pkg "suricata-update" "Suricata Rule Updater"
    fi
    
    # Optional heavy tools
    echo ""
    print_status "INFO" "Optional IDS tools (not installing by default):"
    print_status "INFO" "  - snort (heavy, noisy)"
    print_status "INFO" "  - fwsnort (firewall + snort rules)"
    print_status "INFO" "To install: apt install snort fwsnort"
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 3: FILE & SYSTEM INTEGRITY
#───────────────────────────────────────────────────────────────────────────────

phase_3_integrity() {
    print_section "PHASE 3: File & System Integrity Monitoring"
    
    local packages=(
        "aide:AIDE File Integrity Checker"
        "aide-common:AIDE Common Files"
        "samhain:Samhain File Integrity"
        "tiger:Tiger Security Scanner"
        "debsums:Debian Package Verification"
        "checksecurity:Security Check Scripts"
        "integrit:File Integrity Verifier"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
    
    print_status "INFO" "Note: Choose AIDE or Tripwire (not both). AIDE is recommended."
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 4: MALWARE & ROOTKIT DEFENSE
#───────────────────────────────────────────────────────────────────────────────

phase_4_malware() {
    print_section "PHASE 4: Malware & Rootkit Defense"
    
    local packages=(
        "clamav:ClamAV Antivirus Engine"
        "clamav-daemon:ClamAV Daemon"
        "clamav-freshclam:ClamAV Signature Updater"
        "rkhunter:Rootkit Hunter"
        "chkrootkit:Rootkit Checker"
        "yara:YARA Pattern Matching"
        "libyara-dev:YARA Development Libraries"
        "unhide:Hidden Process Finder"
        "unhide.rb:Ruby Unhide Script"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 5: MANDATORY ACCESS CONTROL (MAC)
#───────────────────────────────────────────────────────────────────────────────

phase_5_mac() {
    print_section "PHASE 5: Mandatory Access Control & Sandboxing"
    
    local packages=(
        "apparmor:AppArmor Security Module"
        "apparmor-utils:AppArmor Utilities"
        "apparmor-profiles:AppArmor Profiles"
        "apparmor-profiles-extra:Extra AppArmor Profiles"
        "firejail:Firejail Sandbox"
        "firejail-profiles:Firejail Profile Collection"
        "bubblewrap:Bubblewrap Sandbox"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
    
    print_status "WARN" "SELinux not recommended on Debian 11 (use AppArmor instead)"
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 6: DEVICE & KERNEL CONTROL
#───────────────────────────────────────────────────────────────────────────────

phase_6_kernel() {
    print_section "PHASE 6: Device & Kernel Security"
    
    local packages=(
        "usbguard:USB Device Authorization"
        "sysstat:System Statistics"
        "kmod:Kernel Module Tools"
        "libpam-tmpdir:PAM Temp Directory"
        "libpam-pwquality:PAM Password Quality"
        "libpam-cracklib:PAM Password Checking"
        "acct:Process Accounting"
        "sysfsutils:Sysfs Utilities"
        "cpufrequtils:CPU Frequency Utilities"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 7: NETWORK PRIVACY & DNS HARDENING
#───────────────────────────────────────────────────────────────────────────────

phase_7_network() {
    print_section "PHASE 7: Network Privacy & DNS Security"
    
    local packages=(
        "tor:Tor Anonymity Network"
        "torsocks:Tor SOCKS Wrapper"
        "dnscrypt-proxy:DNSCrypt Proxy"
        "stubby:DNS Privacy Stub Resolver"
        "unbound:Unbound DNS Resolver"
        "privoxy:Privacy Enhancing Proxy"
        "proxychains4:Proxy Chain Tool"
        "macchanger:MAC Address Changer"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
    
    print_status "WARN" "DNS services may conflict. Enable only ONE: dnscrypt-proxy OR unbound OR stubby"
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 8: MONITORING & ALERTING
#───────────────────────────────────────────────────────────────────────────────

phase_8_monitoring() {
    print_section "PHASE 8: System Monitoring & Analysis"
    
    local packages=(
        "monit:Process Supervisor"
        "htop:Interactive Process Viewer"
        "iotop:I/O Monitor"
        "iftop:Network Bandwidth Monitor"
        "nethogs:Per-Process Bandwidth"
        "vnstat:Network Traffic Monitor"
        "net-tools:Network Tools"
        "tcpdump:Packet Analyzer"
        "tshark:Wireshark CLI"
        "wireshark-common:Wireshark Common"
        "ngrep:Network Grep"
        "bmon:Bandwidth Monitor"
        "iptraf-ng:IP Traffic Monitor"
        "nload:Network Load Monitor"
        "tcpflow:TCP Flow Recorder"
        "lsof:List Open Files"
        "strace:System Call Tracer"
        "ltrace:Library Call Tracer"
        "psmisc:Process Utilities"
        "procps:Process Tools"
        "atop:Advanced System Monitor"
        "glances:System Monitor"
        "dstat:Resource Statistics"
        "sysdig:System Exploration Tool"
        "ncdu:Disk Usage Analyzer"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 9: CRYPTO / VPN / SECURE COMMUNICATION
#───────────────────────────────────────────────────────────────────────────────

phase_9_crypto() {
    print_section "PHASE 9: Encryption & VPN Tools"
    
    local packages=(
        "wireguard:WireGuard VPN"
        "wireguard-tools:WireGuard Tools"
        "openvpn:OpenVPN"
        "strongswan:strongSwan IPsec"
        "strongswan-pki:strongSwan PKI Tools"
        "libstrongswan-extra-plugins:strongSwan Extra Plugins"
        "cryptsetup:Disk Encryption"
        "cryptsetup-initramfs:Cryptsetup Initramfs"
        "gnupg:GNU Privacy Guard"
        "gnupg2:GnuPG 2"
        "pass:Password Manager"
        "pwgen:Password Generator"
        "apg:Another Password Generator"
        "ecryptfs-utils:eCryptfs Utilities"
        "secure-delete:Secure Deletion"
        "wipe:Secure File Wiper"
        "steghide:Steganography Tool"
        "openssl:OpenSSL Toolkit"
        "gnutls-bin:GnuTLS Tools"
        "age:Modern Encryption Tool"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 10: PENTESTING & SECURITY TOOLS
#───────────────────────────────────────────────────────────────────────────────

phase_10_pentest() {
    print_section "PHASE 10: Pentesting & Security Assessment"
    
    local packages=(
        "nmap:Network Mapper"
        "masscan:Mass IP Port Scanner"
        "hping3:Packet Crafter"
        "fping:Fast Ping"
        "arping:ARP Ping"
        "netcat-traditional:Netcat Traditional"
        "netcat-openbsd:Netcat OpenBSD"
        "socat:Socket Relay"
        "hydra:Network Login Cracker"
        "medusa:Parallel Login Brute-Forcer"
        "john:John the Ripper"
        "hashcat:Advanced Password Recovery"
        "nikto:Web Server Scanner"
        "dirb:Web Content Scanner"
        "gobuster:Directory Buster"
        "wfuzz:Web Fuzzer"
        "sqlmap:SQL Injection Tool"
        "aircrack-ng:Wireless Security"
        "nbtscan:NetBIOS Scanner"
        "smbclient:SMB Client"
        "enum4linux:SMB Enumeration"
        "whois:WHOIS Client"
        "dnsutils:DNS Utilities"
        "traceroute:Traceroute"
        "mtr:Network Diagnostic"
        "ncat:Nmap Netcat"
        "sslyze:SSL/TLS Scanner"
        "testssl.sh:SSL/TLS Testing"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 11: ADMIN & FORENSICS TOOLS
#───────────────────────────────────────────────────────────────────────────────

phase_11_forensics() {
    print_section "PHASE 11: Admin & Forensics Tools"
    
    local packages=(
        "lynis:Security Auditing Tool"
        "logwatch:Log Analyzer"
        "logcheck:Log Checker"
        "syslog-summary:Syslog Summary"
        "multitail:Multiple Log Viewer"
        "ccze:Log Colorizer"
        "lnav:Log Navigator"
        "foremost:File Carving"
        "scalpel:File Carving"
        "binwalk:Firmware Analysis"
        "libimage-exiftool-perl:EXIF Tool"
        "sleuthkit:Forensic Toolkit"
        "dc3dd:Enhanced DD"
        "dcfldd:Forensic DD"
        "testdisk:Partition Recovery"
        "extundelete:Ext File Recovery"
        "photorec:File Recovery"
        "volatility3:Memory Forensics"
    )
    
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg desc <<< "$entry"
        install_pkg "$pkg" "$desc"
    done
}

#───────────────────────────────────────────────────────────────────────────────
# PHASE 12: EXTERNAL TOOLS (GitHub Downloads)
#───────────────────────────────────────────────────────────────────────────────

phase_12_external() {
    print_section "PHASE 12: External Security Tools"
    
    print_status "INFO" "Downloading external tools to $EXTERNAL_TOOLS_DIR"
    
    # LinPEAS
    if [[ ! -f "$EXTERNAL_TOOLS_DIR/linpeas.sh" ]]; then
        print_status "INFO" "Downloading LinPEAS..."
        if wget -q "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" \
            -O "$EXTERNAL_TOOLS_DIR/linpeas.sh" 2>> "$LOG_FILE"; then
            chmod +x "$EXTERNAL_TOOLS_DIR/linpeas.sh"
            print_status "OK" "LinPEAS downloaded"
        else
            print_status "FAIL" "LinPEAS download failed"
        fi
    else
        print_status "SKIP" "LinPEAS (already exists)"
    fi
    
    # LinEnum
    if [[ ! -f "$EXTERNAL_TOOLS_DIR/linenum.sh" ]]; then
        print_status "INFO" "Downloading LinEnum..."
        if wget -q "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" \
            -O "$EXTERNAL_TOOLS_DIR/linenum.sh" 2>> "$LOG_FILE"; then
            chmod +x "$EXTERNAL_TOOLS_DIR/linenum.sh"
            print_status "OK" "LinEnum downloaded"
        else
            print_status "FAIL" "LinEnum download failed"
        fi
    else
        print_status "SKIP" "LinEnum (already exists)"
    fi
    
    # Linux Smart Enumeration
    if [[ ! -f "$EXTERNAL_TOOLS_DIR/lse.sh" ]]; then
        print_status "INFO" "Downloading Linux Smart Enumeration..."
        if wget -q "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" \
            -O "$EXTERNAL_TOOLS_DIR/lse.sh" 2>> "$LOG_FILE"; then
            chmod +x "$EXTERNAL_TOOLS_DIR/lse.sh"
            print_status "OK" "LSE downloaded"
        else
            print_status "FAIL" "LSE download failed"
        fi
    else
        print_status "SKIP" "LSE (already exists)"
    fi
    
    # pspy (process spy)
    if [[ ! -f "$EXTERNAL_TOOLS_DIR/pspy64" ]]; then
        print_status "INFO" "Downloading pspy64..."
        if wget -q "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" \
            -O "$EXTERNAL_TOOLS_DIR/pspy64" 2>> "$LOG_FILE"; then
            chmod +x "$EXTERNAL_TOOLS_DIR/pspy64"
            print_status "OK" "pspy64 downloaded"
        else
            print_status "FAIL" "pspy64 download failed"
        fi
    else
        print_status "SKIP" "pspy64 (already exists)"
    fi
    
    # Linux Exploit Suggester
    if [[ ! -f "$EXTERNAL_TOOLS_DIR/les.sh" ]]; then
        print_status "INFO" "Downloading Linux Exploit Suggester..."
        if wget -q "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" \
            -O "$EXTERNAL_TOOLS_DIR/les.sh" 2>> "$LOG_FILE"; then
            chmod +x "$EXTERNAL_TOOLS_DIR/les.sh"
            print_status "OK" "LES downloaded"
        else
            print_status "FAIL" "LES download failed"
        fi
    else
        print_status "SKIP" "LES (already exists)"
    fi
    
    # Lynis from GitHub (latest)
    if [[ ! -d "$EXTERNAL_TOOLS_DIR/lynis" ]]; then
        print_status "INFO" "Cloning Lynis (latest)..."
        if git clone -q "https://github.com/CISOfy/lynis.git" "$EXTERNAL_TOOLS_DIR/lynis" 2>> "$LOG_FILE"; then
            print_status "OK" "Lynis cloned"
        else
            print_status "FAIL" "Lynis clone failed"
        fi
    else
        print_status "SKIP" "Lynis (already exists)"
    fi
}

#───────────────────────────────────────────────────────────────────────────────
# CREATE CONFIG FILES
#───────────────────────────────────────────────────────────────────────────────

create_configs() {
    print_section "Creating Configuration Files"
    
    # Create config directories
    ensure_dir "$CONFIGS_DIR/firewall"
    ensure_dir "$CONFIGS_DIR/ids"
    ensure_dir "$CONFIGS_DIR/integrity"
    ensure_dir "$CONFIGS_DIR/malware"
    ensure_dir "$CONFIGS_DIR/mac"
    ensure_dir "$CONFIGS_DIR/kernel"
    ensure_dir "$CONFIGS_DIR/network"
    ensure_dir "$CONFIGS_DIR/monitoring"
    ensure_dir "$CONFIGS_DIR/vpn/wireguard"
    ensure_dir "$CONFIGS_DIR/vpn/openvpn"
    ensure_dir "$CONFIGS_DIR/ssh"
    
    #─────────────────────────────────────────────────────────────────
    # FAIL2BAN CONFIG
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/ids/fail2ban-jail.local" << 'EOF'
# Harden-Debian Fail2Ban Configuration
# /etc/fail2ban/jail.local

[DEFAULT]
# Ban duration (1 hour)
bantime = 3600

# Time window for failures
findtime = 600

# Max retries before ban
maxretry = 3

# Use systemd backend
backend = systemd

# Email for notifications
destemail = root@localhost
sender = fail2ban@localhost
mta = sendmail

# Action with email
action = %(action_mwl)s

# Ignore local IPs
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[sshd-ddos]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 10
findtime = 60
bantime = 7200

[apache-auth]
enabled = false
port = http,https
logpath = /var/log/apache2/error.log

[apache-badbots]
enabled = false
port = http,https
logpath = /var/log/apache2/access.log

[nginx-http-auth]
enabled = false
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = false
port = http,https
logpath = /var/log/nginx/error.log

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime = 86400
findtime = 86400
maxretry = 5
EOF
    print_status "CONFIG" "fail2ban-jail.local created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # PSAD CONFIG
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/ids/psad.conf" << 'EOF'
# Harden-Debian PSAD Configuration
# Apply to /etc/psad/psad.conf

EMAIL_ADDRESSES             root@localhost;
HOSTNAME                    harden-debian;
HOME_NET                    any;
EXTERNAL_NET                any;

ENABLE_PSADWATCHD           Y;
ENABLE_AUTO_IDS             Y;
ENABLE_AUTO_IDS_EMAILS      Y;

AUTO_IDS_DANGER_LEVEL       3;
AUTO_BLOCK_TIMEOUT          3600;

DANGER_LEVEL1               5;
DANGER_LEVEL2               15;
DANGER_LEVEL3               25;
DANGER_LEVEL4               50;
DANGER_LEVEL5               1000;

PORT_RANGE_SCAN_THRESHOLD   1;
PROTOCOL_SCAN_THRESHOLD     5;

ENABLE_PERSISTENCE          Y;
MAX_SCAN_IP_PAIRS           50000;
ENABLE_WHOIS_LOOKUPS        Y;

ALERTING_METHODS            ALL;
IGNORE_PROTOCOLS            igmp;

ENABLE_MAC_ADDR_REPORTING   Y;
ENABLE_SYSLOG_FILE          Y;
EOF
    print_status "CONFIG" "psad.conf created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # SURICATA CONFIG (Basic)
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/ids/suricata-custom.yaml" << 'EOF'
# Harden-Debian Suricata Custom Configuration
# Append to /etc/suricata/suricata.yaml or use as reference

%YAML 1.1
---

# Network interface
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

# Logging
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: yes
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
        - files:
            force-magic: no
        - ssh
        - flow

# Detect engine settings
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

# Stream engine
stream:
  memcap: 256mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 512mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

# Enable rules
rule-files:
  - suricata.rules
  - /var/lib/suricata/rules/suricata.rules
EOF
    print_status "CONFIG" "suricata-custom.yaml created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # SYSCTL KERNEL HARDENING
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/kernel/sysctl-hardening.conf" << 'EOF'
# Harden-Debian Kernel Hardening Parameters
# Install to: /etc/sysctl.d/99-hardening.conf

#═══════════════════════════════════════════════════════════════════════════════
# KERNEL SECURITY
#═══════════════════════════════════════════════════════════════════════════════

# Restrict kernel log access
kernel.dmesg_restrict = 1

# Hide kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace scope (0=classic, 1=parent, 2=admin, 3=none)
kernel.yama.ptrace_scope = 2

# Disable unprivileged BPF
kernel.unprivileged_bpf_disabled = 1

# Harden BPF JIT compiler
net.core.bpf_jit_harden = 2

# Disable kexec
kernel.kexec_load_disabled = 1

# Enable ASLR (2 = full randomization)
kernel.randomize_va_space = 2

# Reboot on panic after 60 seconds
kernel.panic = 60
kernel.panic_on_oops = 1

# Restrict SysRq key
kernel.sysrq = 0

# Restrict perf_event
kernel.perf_event_paranoid = 3

# Disable loading of kernel modules (enable after boot if needed)
# kernel.modules_disabled = 1

#═══════════════════════════════════════════════════════════════════════════════
# NETWORK SECURITY - IPv4
#═══════════════════════════════════════════════════════════════════════════════

# Enable reverse path filtering (prevent IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable send redirects (for non-routers)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable accept redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Enable SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Disable TCP timestamps (reduces information leakage)
net.ipv4.tcp_timestamps = 0

# Limit SYN retries
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# Increase SYN backlog
net.ipv4.tcp_max_syn_backlog = 4096

# Disable IP forwarding (enable for routers/VPNs)
net.ipv4.ip_forward = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP echo requests (optional - uncomment for stealth)
# net.ipv4.icmp_echo_ignore_all = 1

#═══════════════════════════════════════════════════════════════════════════════
# NETWORK SECURITY - IPv6
#═══════════════════════════════════════════════════════════════════════════════

# Disable IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable IPv6 source routing
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable IPv6 forwarding
net.ipv6.conf.all.forwarding = 0

# Disable IPv6 completely (uncomment if not using IPv6)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

#═══════════════════════════════════════════════════════════════════════════════
# MEMORY & PROCESS SECURITY
#═══════════════════════════════════════════════════════════════════════════════

# Reduce swappiness (prefer RAM)
vm.swappiness = 10

# Don't panic on OOM
vm.panic_on_oom = 0

# Overcommit mode (0=heuristic, 1=always, 2=never)
vm.overcommit_memory = 0
vm.overcommit_ratio = 50

# Restrict memory mapping
vm.mmap_min_addr = 65536

#═══════════════════════════════════════════════════════════════════════════════
# FILE SYSTEM SECURITY
#═══════════════════════════════════════════════════════════════════════════════

# Disable core dumps for SUID binaries
fs.suid_dumpable = 0

# Protect symlinks and hardlinks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# Protect FIFOs and regular files
fs.protected_fifos = 2
fs.protected_regular = 2

# Restrict creation of files
# fs.protected_chdirlinks = 1

#═══════════════════════════════════════════════════════════════════════════════
# NETWORK PERFORMANCE (with security)
#═══════════════════════════════════════════════════════════════════════════════

# TCP keepalive settings
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3

# TCP memory settings
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.udp_mem = 65536 131072 262144

# Increase socket buffer sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Increase connection handling
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
EOF
    print_status "CONFIG" "sysctl-hardening.conf created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # SSH HARDENING CONFIG
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/ssh/sshd_hardening.conf" << 'EOF'
# Harden-Debian SSH Configuration
# Install to: /etc/ssh/sshd_config.d/99-hardening.conf

#═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL & BASIC SETTINGS
#═══════════════════════════════════════════════════════════════════════════════

# SSH Protocol version
Protocol 2

# Listen address (customize as needed)
# Port 22
# ListenAddress 0.0.0.0

#═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION
#═══════════════════════════════════════════════════════════════════════════════

# Root login (prohibit-password = key only, no = completely disabled)
PermitRootLogin prohibit-password

# Public key authentication
PubkeyAuthentication yes

# Disable password authentication (ENABLE ONLY AFTER SETTING UP KEYS!)
PasswordAuthentication no

# Disable empty passwords
PermitEmptyPasswords no

# Disable challenge-response
ChallengeResponseAuthentication no

# Use PAM
UsePAM yes

# Authentication limits
MaxAuthTries 3
MaxSessions 10

# Login grace time
LoginGraceTime 60

#═══════════════════════════════════════════════════════════════════════════════
# ACCESS CONTROL
#═══════════════════════════════════════════════════════════════════════════════

# Restrict users (uncomment and customize)
# AllowUsers admin operator
# AllowGroups ssh-users

# Deny groups
DenyGroups nogroup

#═══════════════════════════════════════════════════════════════════════════════
# SECURITY OPTIONS
#═══════════════════════════════════════════════════════════════════════════════

# Disable X11 forwarding
X11Forwarding no

# Disable agent forwarding
AllowAgentForwarding no

# Disable TCP forwarding (enable if needed for tunnels)
AllowTcpForwarding no

# Disable stream local forwarding
AllowStreamLocalForwarding no

# Disable gateway ports
GatewayPorts no

# Disable tunnel device forwarding
PermitTunnel no

# Strict mode
StrictModes yes

# Ignore rhosts
IgnoreRhosts yes

# Disable host-based authentication
HostbasedAuthentication no

# Disable user environment
PermitUserEnvironment no

#═══════════════════════════════════════════════════════════════════════════════
# KEEP-ALIVE & TIMEOUTS
#═══════════════════════════════════════════════════════════════════════════════

# Client alive interval (5 minutes)
ClientAliveInterval 300
ClientAliveCountMax 2

# TCP keep-alive
TCPKeepAlive yes

#═══════════════════════════════════════════════════════════════════════════════
# LOGGING
#═══════════════════════════════════════════════════════════════════════════════

# Logging
LogLevel VERBOSE

# Print last login
PrintLastLog yes
PrintMotd no

#═══════════════════════════════════════════════════════════════════════════════
# CRYPTOGRAPHY (Modern & Secure)
#═══════════════════════════════════════════════════════════════════════════════

# Key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr

# MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Host key algorithms
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

#═══════════════════════════════════════════════════════════════════════════════
# MISCELLANEOUS
#═══════════════════════════════════════════════════════════════════════════════

# Compression (delayed = after auth)
Compression delayed

# Disable DNS lookups
UseDNS no

# Subsystem for SFTP
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# Banner
Banner none
EOF
    print_status "CONFIG" "sshd_hardening.conf created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # MONIT CONFIG
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/monitoring/monit.conf" << 'EOF'
# Harden-Debian Monit Configuration
# Install to: /etc/monit/conf.d/security.conf

#═══════════════════════════════════════════════════════════════════════════════
# SYSTEM MONITORING
#═══════════════════════════════════════════════════════════════════════════════

check system $HOST
    if loadavg (1min) > 4 then alert
    if loadavg (5min) > 2 then alert
    if memory usage > 75% then alert
    if swap usage > 25% then alert
    if cpu usage > 95% for 5 cycles then alert

#═══════════════════════════════════════════════════════════════════════════════
# FILESYSTEM MONITORING
#═══════════════════════════════════════════════════════════════════════════════

check filesystem rootfs with path /
    if space usage > 80% then alert
    if inode usage > 80% then alert

check filesystem varfs with path /var
    if space usage > 85% then alert
    if inode usage > 85% then alert

#═══════════════════════════════════════════════════════════════════════════════
# SECURITY SERVICE MONITORING
#═══════════════════════════════════════════════════════════════════════════════

check process sshd with pidfile /var/run/sshd.pid
    start program = "/usr/bin/systemctl start ssh"
    stop program = "/usr/bin/systemctl stop ssh"
    if failed port 22 protocol ssh then restart
    if 5 restarts within 5 cycles then alert

check process fail2ban with pidfile /var/run/fail2ban/fail2ban.pid
    start program = "/usr/bin/systemctl start fail2ban"
    stop program = "/usr/bin/systemctl stop fail2ban"
    if 5 restarts within 5 cycles then alert

check process auditd with pidfile /var/run/auditd.pid
    start program = "/usr/bin/systemctl start auditd"
    stop program = "/usr/bin/systemctl stop auditd"
    if 5 restarts within 5 cycles then alert

check process rsyslog with pidfile /var/run/rsyslogd.pid
    start program = "/usr/bin/systemctl start rsyslog"
    stop program = "/usr/bin/systemctl stop rsyslog"
    if 5 restarts within 5 cycles then alert

#═══════════════════════════════════════════════════════════════════════════════
# NETWORK MONITORING
#═══════════════════════════════════════════════════════════════════════════════

check network eth0 with interface eth0
    if failed link then alert
    if saturation > 90% then alert
    if download > 500 MB/s then alert
    if upload > 500 MB/s then alert
EOF
    print_status "CONFIG" "monit.conf created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # RKHUNTER CONFIG
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/malware/rkhunter.conf" << 'EOF'
# Harden-Debian rkhunter Configuration
# Additions for /etc/rkhunter.conf

# Enable email alerts
MAIL-ON-WARNING=root@localhost

# Update mirrors
UPDATE_MIRRORS=1
MIRRORS_MODE=0
WEB_CMD=wget

# Auto-update database
PKGMGR=DPKG
ENABLE_TESTS=ALL

# Allow certain scripts
SCRIPTWHITELIST=/usr/bin/egrep
SCRIPTWHITELIST=/usr/bin/fgrep
SCRIPTWHITELIST=/usr/bin/which
SCRIPTWHITELIST=/usr/bin/ldd

# Allow /dev files
ALLOWDEVFILE=/dev/shm/pulse-shm-*
ALLOWDEVFILE=/dev/shm/sem.*

# Whitelist hidden directories
ALLOWHIDDENDIR=/etc/.java
ALLOWHIDDENDIR=/dev/.udev

# Auto-accept changes after apt updates
PKGMGR_NO_VRFY=0
EOF
    print_status "CONFIG" "rkhunter.conf created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # CLAMAV SCAN CONFIG
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/malware/clamav-scan.conf" << 'EOF'
# Harden-Debian ClamAV Scan Configuration
# Use with: clamscan -c /path/to/this/file

# Recursive scan
--recursive=yes

# Skip self
--exclude-dir="^/proc"
--exclude-dir="^/sys"
--exclude-dir="^/dev"

# Performance
--max-filesize=100M
--max-scansize=400M
--max-recursion=15
--max-dir-recursion=20

# Reporting
--infected
--log=/var/log/clamav/scan.log

# Actions (uncomment to enable)
# --remove=yes
# --move=/var/quarantine
EOF
    print_status "CONFIG" "clamav-scan.conf created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # USBGUARD RULES
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/kernel/usbguard-rules.conf" << 'EOF'
# Harden-Debian USBGuard Rules Template
# Install to: /etc/usbguard/rules.conf
# Generate current devices with: usbguard generate-policy

# Block all by default, then whitelist
# This is a TEMPLATE - run 'usbguard generate-policy' for your devices

# Allow hubs
allow with-interface equals { 09:*:* }

# Allow keyboards
# allow with-interface one-of { 03:01:01 }

# Allow mice
# allow with-interface one-of { 03:01:02 }

# Block everything else by default
# (usbguard default is implicit deny)
EOF
    print_status "CONFIG" "usbguard-rules.conf created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # AIDE CONFIG
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/integrity/aide-custom.conf" << 'EOF'
# Harden-Debian AIDE Custom Configuration
# Additions for /etc/aide/aide.conf

# Custom groups
NORMAL = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha256
DIR = p+i+n+u+g+acl+selinux+xattrs
LOG = p+u+g+i+n+S+acl+selinux+xattrs

# Critical directories
/etc NORMAL
/bin NORMAL
/sbin NORMAL
/lib NORMAL
/lib64 NORMAL
/usr/bin NORMAL
/usr/sbin NORMAL
/usr/lib NORMAL

# Log files (only check permissions, not content)
/var/log LOG
!/var/log/.*\.gz

# Exclude temporary files
!/tmp
!/var/tmp
!/run
!/proc
!/sys
!/dev
!/var/cache
!/var/lib/apt
EOF
    print_status "CONFIG" "aide-custom.conf created"
    ((CONFIGURED++))
    
    #─────────────────────────────────────────────────────────────────
    # DNSCRYPT-PROXY CONFIG
    #─────────────────────────────────────────────────────────────────
    cat > "$CONFIGS_DIR/network/dnscrypt-proxy.toml" << 'EOF'
# Harden-Debian dnscrypt-proxy Configuration
# Install to: /etc/dnscrypt-proxy/dnscrypt-proxy.toml

listen_addresses = ['127.0.0.1:53', '[::1]:53']
max_clients = 250
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = true
force_tcp = false
timeout = 2500
keepalive = 30

# Servers
server_names = ['cloudflare', 'google', 'quad9-dnscrypt-ip4-nofilter-pri']

# Fallback
fallback_resolvers = ['9.9.9.9:53', '8.8.8.8:53']
ignore_system_dns = true

# Cache
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

# Logging
log_level = 2
use_syslog = true
log_files_max_size = 10
log_files_max_age = 7
log_files_max_backups = 1

[query_log]
file = '/var/log/dnscrypt-proxy/query.log'
format = 'tsv'

[nx_log]
file = '/var/log/dnscrypt-proxy/nx.log'
format = 'tsv'

[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
EOF
    print_status "CONFIG" "dnscrypt-proxy.toml created"
    ((CONFIGURED++))
    
    print_status "OK" "All configuration files created in $CONFIGS_DIR"
}

#───────────────────────────────────────────────────────────────────────────────
# CREATE HELPER SCRIPTS
#───────────────────────────────────────────────────────────────────────────────

create_scripts() {
    print_section "Creating Helper Scripts"
    
    ensure_dir "$TOOLS_DIR/scripts"
    
    #─────────────────────────────────────────────────────────────────
    # UPDATE SIGNATURES SCRIPT
    #─────────────────────────────────────────────────────────────────
    cat > "$TOOLS_DIR/scripts/update-signatures.sh" << 'EOF'
#!/bin/bash
# Update all security signatures
# Run as root: sudo ./update-signatures.sh

set -e

echo "═══════════════════════════════════════════════════════════════"
echo "  UPDATING SECURITY SIGNATURES"
echo "═══════════════════════════════════════════════════════════════"

# ClamAV
echo "[1/5] Updating ClamAV..."
systemctl stop clamav-freshclam 2>/dev/null || true
freshclam
systemctl start clamav-freshclam

# rkhunter
echo "[2/5] Updating rkhunter..."
rkhunter --update
rkhunter --propupd

# Suricata
echo "[3/5] Updating Suricata rules..."
suricata-update || echo "Suricata update failed (may not be installed)"

# PSAD
echo "[4/5] Updating PSAD signatures..."
psad --sig-update || echo "PSAD update failed (may not be installed)"

# AIDE
echo "[5/5] Updating AIDE database..."
aide -c /etc/aide/aide.conf --update || echo "AIDE update failed"
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true

echo ""
echo "✓ All signatures updated!"
EOF
    chmod +x "$TOOLS_DIR/scripts/update-signatures.sh"
    print_status "OK" "update-signatures.sh created"
    
    #─────────────────────────────────────────────────────────────────
    # SCAN NOW SCRIPT
    #─────────────────────────────────────────────────────────────────
    cat > "$TOOLS_DIR/scripts/scan-now.sh" << 'EOF'
#!/bin/bash
# Run immediate security scan
# Run as root: sudo ./scan-now.sh

set -e

LOG="/var/log/security-scan-$(date +%Y%m%d_%H%M%S).log"

echo "═══════════════════════════════════════════════════════════════" | tee "$LOG"
echo "  SECURITY SCAN - $(date)" | tee -a "$LOG"
echo "═══════════════════════════════════════════════════════════════" | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "[1/6] Running rkhunter..." | tee -a "$LOG"
rkhunter --check --skip-keypress --report-warnings-only 2>&1 | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "[2/6] Running chkrootkit..." | tee -a "$LOG"
chkrootkit -q 2>&1 | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "[3/6] Running AIDE check..." | tee -a "$LOG"
aide --check 2>&1 | head -50 | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "[4/6] Running lynis quick audit..." | tee -a "$LOG"
lynis audit system --quick --quiet 2>&1 | tail -30 | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "[5/6] Running ClamAV scan on /home and /tmp..." | tee -a "$LOG"
clamscan -r -i /home /tmp /var/tmp 2>&1 | tail -20 | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "[6/6] Checking for listening services..." | tee -a "$LOG"
ss -tulpn | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "═══════════════════════════════════════════════════════════════" | tee -a "$LOG"
echo "  SCAN COMPLETE - Log: $LOG" | tee -a "$LOG"
echo "═══════════════════════════════════════════════════════════════" | tee -a "$LOG"
EOF
    chmod +x "$TOOLS_DIR/scripts/scan-now.sh"
    print_status "OK" "scan-now.sh created"
    
    #─────────────────────────────────────────────────────────────────
    # BACKUP SCRIPT
    #─────────────────────────────────────────────────────────────────
    cat > "$TOOLS_DIR/scripts/backup.sh" << 'EOF'
#!/bin/bash
# Backup security configurations
# Run as root: sudo ./backup.sh

set -e

BACKUP_DIR="/root/harden-backup-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "═══════════════════════════════════════════════════════════════"
echo "  BACKING UP SECURITY CONFIGS"
echo "═══════════════════════════════════════════════════════════════"

# SSH
cp -r /etc/ssh "$BACKUP_DIR/" 2>/dev/null || true

# Firewall
cp -r /etc/ufw "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/iptables "$BACKUP_DIR/" 2>/dev/null || true

# IDS/IPS
cp -r /etc/fail2ban "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/psad "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/suricata "$BACKUP_DIR/" 2>/dev/null || true

# Kernel
cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/sysctl.d "$BACKUP_DIR/" 2>/dev/null || true

# AppArmor
cp -r /etc/apparmor "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/apparmor.d "$BACKUP_DIR/" 2>/dev/null || true

# Create tarball
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
rm -rf "$BACKUP_DIR"

echo ""
echo "✓ Backup created: $BACKUP_DIR.tar.gz"
EOF
    chmod +x "$TOOLS_DIR/scripts/backup.sh"
    print_status "OK" "backup.sh created"
    
    #─────────────────────────────────────────────────────────────────
    # RESTORE SCRIPT
    #─────────────────────────────────────────────────────────────────
    cat > "$TOOLS_DIR/scripts/restore.sh" << 'EOF'
#!/bin/bash
# Restore security configurations from backup
# Run as root: sudo ./restore.sh /path/to/backup.tar.gz

set -e

if [[ -z "$1" ]]; then
    echo "Usage: $0 /path/to/backup.tar.gz"
    exit 1
fi

BACKUP_FILE="$1"

if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  RESTORING SECURITY CONFIGS FROM: $BACKUP_FILE"
echo "═══════════════════════════════════════════════════════════════"

# Extract
TEMP_DIR=$(mktemp -d)
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

BACKUP_DIR=$(ls "$TEMP_DIR")

# Restore
echo "Restoring SSH..."
cp -r "$TEMP_DIR/$BACKUP_DIR/ssh"/* /etc/ssh/ 2>/dev/null || true

echo "Restoring firewall..."
cp -r "$TEMP_DIR/$BACKUP_DIR/ufw"/* /etc/ufw/ 2>/dev/null || true
cp -r "$TEMP_DIR/$BACKUP_DIR/iptables"/* /etc/iptables/ 2>/dev/null || true

echo "Restoring IDS/IPS..."
cp -r "$TEMP_DIR/$BACKUP_DIR/fail2ban"/* /etc/fail2ban/ 2>/dev/null || true
cp -r "$TEMP_DIR/$BACKUP_DIR/psad"/* /etc/psad/ 2>/dev/null || true
cp -r "$TEMP_DIR/$BACKUP_DIR/suricata"/* /etc/suricata/ 2>/dev/null || true

echo "Restoring kernel settings..."
cp "$TEMP_DIR/$BACKUP_DIR/sysctl.conf" /etc/ 2>/dev/null || true
cp -r "$TEMP_DIR/$BACKUP_DIR/sysctl.d"/* /etc/sysctl.d/ 2>/dev/null || true

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "✓ Restore complete. Restart services to apply changes."
EOF
    chmod +x "$TOOLS_DIR/scripts/restore.sh"
    print_status "OK" "restore.sh created"
}

#───────────────────────────────────────────────────────────────────────────────
# SUMMARY
#───────────────────────────────────────────────────────────────────────────────

show_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLATION COMPLETE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}✓ Installed:${NC}    $INSTALLED packages"
    echo -e "  ${YELLOW}○ Skipped:${NC}      $SKIPPED packages (already installed)"
    echo -e "  ${RED}✗ Failed:${NC}       $FAILED packages"
    echo -e "  ${MAGENTA}⚙ Configured:${NC}   $CONFIGURED config files"
    echo ""
    echo -e "${BLUE}  Locations:${NC}"
    echo "    Log file:       $LOG_FILE"
    echo "    Backups:        $BACKUP_DIR"
    echo "    Configs:        $CONFIGS_DIR"
    echo "    External tools: $EXTERNAL_TOOLS_DIR"
    echo ""
    echo -e "${YELLOW}  Next Steps:${NC}"
    echo "    1. Run: ./active.sh    (Configure & activate services)"
    echo "    2. Run: ./status.sh    (Check system status)"
    echo "    3. Review logs: tail -f $LOG_FILE"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
    
    log "COMPLETE" "Installed: $INSTALLED, Skipped: $SKIPPED, Failed: $FAILED, Configured: $CONFIGURED"
}

#───────────────────────────────────────────────────────────────────────────────
# MAIN
#───────────────────────────────────────────────────────────────────────────────

main() {
    initialize
    
    phase_0_preparation
    phase_1_core_hardening
    phase_2_ids_ips
    phase_3_integrity
    phase_4_malware
    phase_5_mac
    phase_6_kernel
    phase_7_network
    phase_8_monitoring
    phase_9_crypto
    phase_10_pentest
    phase_11_forensics
    phase_12_external
    
    create_configs
    create_scripts
    
    show_summary
}

# Run main
main "$@"