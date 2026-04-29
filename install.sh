#!/usr/bin/env bash
# fufu-sec v3.11.2 — local installer
# Installs all dependencies and sets up a local Python venv.
# Nothing is installed globally outside of apt packages.
# Delete this folder to remove fufu-sec completely.
# Usage: sudo bash install.sh

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}${BOLD}━━━ $* ━━━${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"
command -v apt-get &>/dev/null || error "apt-get not found. Requires Kali / Parrot / Debian / Ubuntu."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "fufu-sec directory: $SCRIPT_DIR"

# ── System packages ───────────────────────────────────────────────────────────
section "Core wireless tools"
apt-get update -qq

info "Installing aircrack-ng suite, capture tools, and crackers..."
apt-get install -y --no-install-recommends \
    iw wireless-tools net-tools rfkill \
    aircrack-ng \
    mdk4 \
    reaver bully pixiewps \
    hcxdumptool hcxtools \
    tcpdump tshark \
    hashcat john crunch \
    hostapd dnsmasq iptables \
    python3 python3-pip python3-venv \
    wireshark-common \
    wordlists 2>/dev/null || true

# aireplay-ng ships with aircrack-ng
if ! command -v aireplay-ng &>/dev/null; then
    warn "aireplay-ng not found — retrying..."
    apt-get install -y --no-install-recommends aircrack-ng 2>/dev/null || true
fi

# hcxtools provides hcxpcapngtool (cap → hashcat 22000 converter)
apt-get install -y --no-install-recommends hcxtools 2>/dev/null || true

section "Optional tools"
for pkg in ettercap-text-only hostapd-wpe asleap bettercap lighttpd; do
    apt-get install -y --no-install-recommends "$pkg" 2>/dev/null \
        && info "  installed: $pkg" || warn "  skipped (not available): $pkg"
done

section "Wordlists"
if [[ -f /usr/share/wordlists/rockyou.txt.gz && ! -f /usr/share/wordlists/rockyou.txt ]]; then
    info "Decompressing rockyou.txt..."
    gunzip /usr/share/wordlists/rockyou.txt.gz && info "rockyou.txt ready"
elif [[ -f /usr/share/wordlists/rockyou.txt ]]; then
    info "rockyou.txt already present"
else
    warn "rockyou.txt not found — install wordlists package or place it manually"
fi

section "Python environment"
VENV="$SCRIPT_DIR/.venv"
[[ ! -d "$VENV" ]] && python3 -m venv "$VENV" && info "Created .venv"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet --upgrade flask flask-cors
info "Flask ready"

mkdir -p /tmp/fufu-sec "$SCRIPT_DIR/logs"

section "Tool check"
ESSENTIAL=(airmon-ng airodump-ng aircrack-ng aireplay-ng iw mdk4)
OPTIONAL_CHECK=(hashcat john crunch reaver bully hcxdumptool hcxpcapngtool tshark tcpdump hostapd dnsmasq wash ettercap bettercap)

echo ""
echo -e "  ${BOLD}Essential:${NC}"
all_ok=true
for t in "${ESSENTIAL[@]}"; do
    if command -v "$t" &>/dev/null; then
        echo -e "    ${GREEN}OK${NC}  $t"
    else
        echo -e "    ${RED}MISSING${NC}  $t"
        all_ok=false
    fi
done

echo ""
echo -e "  ${BOLD}Optional:${NC}"
for t in "${OPTIONAL_CHECK[@]}"; do
    if command -v "$t" &>/dev/null; then
        echo -e "    ${GREEN}OK${NC}  $t"
    else
        echo -e "    ${YELLOW}--${NC}  $t"
    fi
done

echo ""
$all_ok && info "All essential tools present ✓" \
         || warn "Some essential tools missing — check above"

section "Ready"
echo ""
info "fufu-sec v3.11.2 installed. To start:"
echo ""
echo -e "    ${CYAN}cd $SCRIPT_DIR${NC}"
echo -e "    ${CYAN}sudo .venv/bin/python3 server.py${NC}"
echo ""
echo "    Open  http://localhost:5000  in your browser."
echo ""
warn "ADAPTER: Intel (iwlwifi) and most Realtek built-in adapters do NOT support"
warn "         packet injection. Use: Alfa AWUS036ACH / AWUS036ACS / TP-Link TL-WN722N v1"
warn "PASSIVE MODE: Without injection, start capture and reconnect a device to the AP"
warn "              (turn WiFi off/on) — fufu-sec detects the handshake automatically."
warn "UNINSTALL: delete the fufu-sec/ folder — nothing was installed globally."
echo ""
