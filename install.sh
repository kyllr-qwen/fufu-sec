#!/usr/bin/env bash
# fufu-sec — local installer
# Sets up a local venv. Nothing is installed globally.
# Delete this folder to uninstall completely.
# Usage: sudo bash install.sh

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"
command -v apt-get &>/dev/null || error "apt-get not found. Requires Kali / Parrot / Debian / Ubuntu."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "fufu-sec dir: $SCRIPT_DIR"

# ── System packages ───────────────────────────────────────────────────────────
info "Installing system packages..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    iw wireless-tools net-tools \
    aircrack-ng \
    reaver bully pixiewps \
    hcxdumptool hcxtools \
    mdk4 \
    tcpdump tshark \
    hashcat john crunch \
    hostapd dnsmasq iptables \
    wordlists 2>/dev/null || true

# ── Rockyou ──────────────────────────────────────────────────────────────────
[[ -f /usr/share/wordlists/rockyou.txt.gz && ! -f /usr/share/wordlists/rockyou.txt ]] && \
    gunzip /usr/share/wordlists/rockyou.txt.gz && info "rockyou.txt decompressed"

# ── Local Python venv (stays inside this folder) ─────────────────────────────
VENV="$SCRIPT_DIR/.venv"
[[ ! -d "$VENV" ]] && python3 -m venv "$VENV" && info "Created .venv"
"$VENV/bin/pip" install --quiet --upgrade flask flask-cors
info "Flask installed in .venv"

# ── Runtime dirs ─────────────────────────────────────────────────────────────
mkdir -p /tmp/fufu-sec "$SCRIPT_DIR/logs"

echo ""
info "Done. To start fufu-sec:"
echo ""
echo "    cd $SCRIPT_DIR"
echo "    sudo .venv/bin/python3 server.py"
echo ""
echo "    Open  http://localhost:5000  in your browser."
echo ""
warn "To uninstall: delete the fufu-sec folder. Nothing was installed globally."
