#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║   fufu-sec · AirWeb WiFi Security Suite                                   ║
# ║   Install Script v3.2                                                     ║
# ║   https://github.com/kyllr-qwen/fufu-sec                                  ║
# ║                                                                           ║
# ║   Based on airgeddon v11.61 by v1s1t0r                                    ║
# ║                                                                           ║
# ║   ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY                             ║
# ║      Unauthorized interception of network traffic is illegal.            ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Terminal colours ──────────────────────────────────────────────────────────
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
C='\033[0;36m'
W='\033[1;37m'
M='\033[0;35m'
N='\033[0m'

# ── Config ────────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/kyllr-qwen/fufu-sec.git"
INSTALL_DIR="/opt/fufu-sec"
LAUNCHER="/usr/local/bin/fufu-sec"
SERVICE_FILE="/etc/systemd/system/fufu-sec.service"
LOG_DIR="/var/log/airweb"
TMP_DIR="/tmp/airweb"
VENV_DIR="$INSTALL_DIR/.venv"

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
  clear
  echo -e "${C}"
  echo "  ███████╗██╗   ██╗███████╗██╗   ██╗      ███████╗███████╗ ██████╗"
  echo "  ██╔════╝██║   ██║██╔════╝██║   ██║      ██╔════╝██╔════╝██╔════╝"
  echo "  █████╗  ██║   ██║█████╗  ██║   ██║█████╗███████╗█████╗  ██║     "
  echo "  ██╔══╝  ██║   ██║██╔══╝  ██║   ██║╚════╝╚════██║██╔══╝  ██║     "
  echo "  ██║     ╚██████╔╝██║     ╚██████╔╝      ███████║███████╗╚██████╗"
  echo "  ╚═╝      ╚═════╝ ╚═╝      ╚═════╝       ╚══════╝╚══════╝ ╚═════╝"
  echo -e "${N}"
  echo -e "  ${W}AirWeb WiFi Security Suite${N} · Based on airgeddon v11.61 by v1s1t0r"
  echo -e "  ${M}https://github.com/kyllr-qwen/fufu-sec${N}"
  echo ""
  echo -e "  ${Y}⚠  FOR AUTHORIZED PENETRATION TESTING ONLY${N}"
  echo -e "  ${R}   Unauthorized use is illegal in most jurisdictions.${N}"
  echo ""
  echo -e "  ${C}══════════════════════════════════════════════════════${N}"
  echo ""
}

info()    { echo -e "  ${C}[*]${N} $*"; }
ok()      { echo -e "  ${G}[✓]${N} $*"; }
warn()    { echo -e "  ${Y}[!]${N} $*"; }
err()     { echo -e "  ${R}[✗]${N} $*"; }
section() { echo -e "\n  ${W}━━ $* ━━${N}"; }
die()     { err "$*"; exit 1; }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
check_root() {
  if [[ $EUID -ne 0 ]]; then
    die "This installer must be run as root.  →  sudo bash install.sh"
  fi
  ok "Running as root"
}

check_os() {
  section "System check"
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-unknown}"
    case "$DISTRO_ID" in
      kali)    ok "Kali Linux detected — optimal environment" ;;
      parrot)  ok "Parrot OS detected — optimal environment" ;;
      ubuntu)  ok "Ubuntu detected" ;;
      debian)  ok "Debian detected" ;;
      linuxmint|pop|zorin) ok "$DISTRO_NAME detected" ;;
      *)
        warn "Untested OS: $DISTRO_NAME"
        warn "Kali Linux or Parrot OS are recommended."
        read -rp "  Continue anyway? [y/N] " YN
        [[ "${YN,,}" == "y" ]] || die "Installation aborted."
        ;;
    esac
  else
    warn "Cannot detect OS — proceeding cautiously."
  fi

  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  ok "Architecture: x86_64" ;;
    aarch64) ok "Architecture: ARM64 (Raspberry Pi 4+ / Apple M-series VM)" ;;
    armv7l)  warn "Architecture: ARMv7 — hashcat GPU cracking unavailable" ;;
    *)       warn "Unknown architecture: $ARCH" ;;
  esac

  KERNEL=$(uname -r)
  info "Kernel: $KERNEL"

  # Python version check
  if command -v python3 &>/dev/null; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 8 ]]; then
      ok "Python $PY_VER"
    else
      die "Python 3.8+ required. Found: $PY_VER"
    fi
  else
    die "Python3 not found — install it first: apt-get install python3"
  fi
}

# ── Package installation ──────────────────────────────────────────────────────
install_packages() {
  section "System packages"
  info "Updating apt package list..."
  apt-get update -qq 2>/dev/null

  # Helper: install single package silently
  apt_install() {
    local pkg="$1"
    local label="${2:-$pkg}"
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
      ok "$label  (already installed)"
    else
      info "Installing $label..."
      if apt-get install -y -qq "$pkg" 2>/dev/null; then
        ok "$label"
      else
        warn "$label — not available, some features may be limited"
      fi
    fi
  }

  echo ""
  info "Core / Python"
  apt_install git
  apt_install python3
  apt_install python3-pip "python3-pip"
  apt_install python3-venv "python3-venv"

  echo ""
  info "Network / Interface tools"
  apt_install iw
  apt_install wireless-tools "wireless-tools (iwconfig)"
  apt_install iproute2
  apt_install net-tools
  apt_install pciutils
  apt_install ethtool

  echo ""
  info "Wireless capture & injection (aircrack-ng suite)"
  apt_install aircrack-ng "aircrack-ng / airodump-ng / aireplay-ng / airmon-ng"

  echo ""
  info "WPS attack tools"
  apt_install reaver
  apt_install bully
  apt_install pixiewps

  echo ""
  info "PMKID capture tools"
  apt_install hcxdumptool
  apt_install hcxtools "hcxtools (hcxpcapngtool)"

  echo ""
  info "DoS / flood tools"
  apt_install mdk4

  echo ""
  info "Packet capture"
  apt_install tcpdump
  apt_install tshark

  echo ""
  info "Password cracking"
  apt_install hashcat
  apt_install john "john (John the Ripper)"
  apt_install crunch

  echo ""
  info "Evil Twin / AP tools"
  apt_install hostapd
  apt_install dnsmasq
  apt_install iptables
  apt_install nftables

  # rockyou.txt
  echo ""
  info "Wordlists"
  ROCKYOU="/usr/share/wordlists/rockyou.txt"
  if [[ -f "$ROCKYOU" ]]; then
    ok "rockyou.txt already present"
  elif dpkg -s wordlists &>/dev/null 2>&1; then
    info "wordlists installed but rockyou.txt is compressed — extracting..."
    gunzip -fk "/usr/share/wordlists/rockyou.txt.gz" 2>/dev/null || true
    [[ -f "$ROCKYOU" ]] && ok "rockyou.txt extracted" || warn "Could not extract rockyou.txt"
  else
    info "Installing wordlists package..."
    if apt-get install -y -qq wordlists 2>/dev/null; then
      gunzip -fk "/usr/share/wordlists/rockyou.txt.gz" 2>/dev/null || true
      [[ -f "$ROCKYOU" ]] && ok "rockyou.txt ready" || warn "wordlists installed but rockyou.txt not found"
    else
      warn "wordlists package unavailable — you can add wordlists manually to /usr/share/wordlists/"
    fi
  fi
}

# ── Clone / update repo ───────────────────────────────────────────────────────
install_repo() {
  section "Installing fufu-sec"

  if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository already exists at $INSTALL_DIR — updating..."
    git -C "$INSTALL_DIR" pull --ff-only \
      && ok "Updated to latest commit" \
      || warn "git pull failed — using existing files"

  elif [[ -d "$INSTALL_DIR" ]] && [[ -f "$INSTALL_DIR/server.py" ]]; then
    info "Found existing files at $INSTALL_DIR (not a git repo)"
    ok "Using existing installation"

  else
    [[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR"
    info "Cloning $REPO_URL → $INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR" \
      && ok "Repository cloned" \
      || die "git clone failed — check your internet connection"
  fi

  # Verify critical files exist
  [[ -f "$INSTALL_DIR/server.py" ]]    || die "server.py not found in $INSTALL_DIR"
  [[ -f "$INSTALL_DIR/dashboard.html" ]] || die "dashboard.html not found in $INSTALL_DIR"
  ok "server.py and dashboard.html verified"
}

# ── Python virtual environment ────────────────────────────────────────────────
setup_python() {
  section "Python environment"

  if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created"
  else
    ok "Virtual environment already exists"
  fi

  info "Upgrading pip..."
  "$VENV_DIR/bin/pip" install --upgrade pip -q

  info "Installing Flask + flask-cors..."
  "$VENV_DIR/bin/pip" install flask flask-cors -q
  ok "Flask + flask-cors installed"

  # Record installed version for diagnostics
  FLASK_VER=$("$VENV_DIR/bin/pip" show flask 2>/dev/null | grep ^Version | awk '{print $2}')
  info "Flask version: ${FLASK_VER:-unknown}"
}

# ── Directories and permissions ───────────────────────────────────────────────
setup_dirs() {
  section "Directories and permissions"

  mkdir -p "$TMP_DIR" "$LOG_DIR"
  chmod 755 "$TMP_DIR" "$LOG_DIR"
  ok "Created $TMP_DIR"
  ok "Created $LOG_DIR"

  # Make server.py executable
  chmod +x "$INSTALL_DIR/server.py"
  ok "server.py marked executable"
}

# ── CLI launcher ──────────────────────────────────────────────────────────────
write_launcher() {
  section "CLI launcher"

  cat > "$LAUNCHER" << LAUNCH_EOF
#!/usr/bin/env bash
# fufu-sec — AirWeb launcher
# Usage: sudo fufu-sec [--port PORT] [--host HOST] [--no-browser]

INSTALL_DIR="/opt/fufu-sec"
VENV="\$INSTALL_DIR/.venv"
PORT=5000
HOST="0.0.0.0"
OPEN_BROWSER=true

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --port)   PORT="\$2"; shift 2 ;;
    --host)   HOST="\$2"; shift 2 ;;
    --no-browser) OPEN_BROWSER=false; shift ;;
    --help|-h)
      echo "Usage: sudo fufu-sec [--port PORT] [--host HOST] [--no-browser]"
      echo "  --port PORT      Port to listen on (default: 5000)"
      echo "  --host HOST      Bind address (default: 0.0.0.0)"
      echo "  --no-browser     Do not attempt to open the dashboard in a browser"
      exit 0 ;;
    *) echo "Unknown option: \$1"; exit 1 ;;
  esac
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ \$EUID -ne 0 ]]; then
  echo "fufu-sec must be run as root (aircrack-ng suite requires raw socket access)."
  echo "  sudo fufu-sec"
  exit 1
fi

# ── Sanity checks ─────────────────────────────────────────────────────────────
[[ -f "\$INSTALL_DIR/server.py" ]]       || { echo "server.py not found at \$INSTALL_DIR"; exit 1; }
[[ -f "\$VENV/bin/python3" ]]            || { echo "Virtual environment missing — re-run install.sh"; exit 1; }

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║  AirWeb WiFi Security Suite  [v3.2]       ║"
echo "  ║  Based on airgeddon v11.61 by v1s1t0r     ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""
echo "  Dashboard  →  http://localhost:\$PORT"
echo "  API        →  http://localhost:\$PORT/api/status"
echo "  Logs       →  /var/log/airweb/airweb.log"
echo "  Tmp files  →  /tmp/airweb/"
echo ""
echo "  Press Ctrl+C to stop."
echo ""

# Open browser after 2-second delay (best-effort)
if [[ "\$OPEN_BROWSER" == true ]]; then
  ( sleep 2; xdg-open "http://localhost:\$PORT" 2>/dev/null \
    || sensible-browser "http://localhost:\$PORT" 2>/dev/null \
    || true ) &
fi

cd "\$INSTALL_DIR"
exec "\$VENV/bin/python3" server.py --port "\$PORT" --host "\$HOST" 2>&1
LAUNCH_EOF

  chmod +x "$LAUNCHER"
  ok "Launcher written to $LAUNCHER  →  run with: sudo fufu-sec"
}

# ── systemd service (optional) ────────────────────────────────────────────────
write_service() {
  section "systemd service (optional auto-start)"

  read -rp "  Install as a systemd service (auto-start on boot)? [y/N] " YN
  if [[ "${YN,,}" != "y" ]]; then
    info "Skipping systemd service."
    return
  fi

  cat > "$SERVICE_FILE" << SERVICE_EOF
[Unit]
Description=AirWeb WiFi Security Suite (fufu-sec)
After=network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=/opt/fufu-sec
ExecStart=/opt/fufu-sec/.venv/bin/python3 /opt/fufu-sec/server.py
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/airweb/airweb.log
StandardError=append:/var/log/airweb/airweb.log
Environment=PYTHONUNBUFFERED=1

# Security hardening (still needs root for wireless tools)
PrivateTmp=false
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
SERVICE_EOF

  systemctl daemon-reload
  ok "Service file written to $SERVICE_FILE"
  echo ""
  echo -e "  ${W}systemd commands:${N}"
  echo "    sudo systemctl enable  fufu-sec   # start on boot"
  echo "    sudo systemctl start   fufu-sec   # start now"
  echo "    sudo systemctl stop    fufu-sec   # stop"
  echo "    sudo systemctl status  fufu-sec   # check status"
  echo "    sudo journalctl -u fufu-sec -f    # follow logs"
}

# ── Verify injection capability (advisory) ───────────────────────────────────
check_wireless() {
  section "Wireless adapter check (advisory)"

  # List interfaces in monitor mode
  IFACES=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | tr '\n' ' ')
  if [[ -z "$IFACES" ]]; then
    warn "No wireless interfaces detected."
    warn "Plug in a monitor-mode capable adapter (Alfa AWUS036ACH recommended)."
  else
    ok "Wireless interfaces found: $IFACES"
    info "To enable monitor mode after launch:"
    echo "         sudo airmon-ng check kill"
    echo "         sudo airmon-ng start <iface>"
  fi
}

# ── Print final summary ───────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo -e "  ${C}╔═══════════════════════════════════════════════════════════╗${N}"
  echo -e "  ${C}║${G}  ✓  fufu-sec installation complete!                       ${C}║${N}"
  echo -e "  ${C}╚═══════════════════════════════════════════════════════════╝${N}"
  echo ""
  echo -e "  ${W}How to run:${N}"
  echo ""
  echo -e "    ${G}sudo fufu-sec${N}"
  echo -e "    ${C}# Then open:  http://localhost:5000${N}"
  echo ""
  echo -e "  ${W}Options:${N}"
  echo "    sudo fufu-sec --port 8080        # custom port"
  echo "    sudo fufu-sec --no-browser       # headless / SSH"
  echo "    sudo fufu-sec --help             # show all options"
  echo ""
  echo -e "  ${W}Quick-start steps inside the dashboard:${N}"
  echo "    1. Interface  → Enable Monitor Mode"
  echo "    2. Interface  → Test Injection  (verify adapter works)"
  echo "    3. Scanner    → Scan  →  click Use on target"
  echo "    4. Handshake  → Start Capture"
  echo "    5. Cracker    → List Caps  →  Crack"
  echo ""
  echo -e "  ${W}Logs:${N}    /var/log/airweb/airweb.log"
  echo -e "  ${W}Tmp:${N}     /tmp/airweb/"
  echo -e "  ${W}Install:${N} $INSTALL_DIR"
  echo ""
  echo -e "  ${Y}⚠  Use only on networks you own or have explicit permission to test.${N}"
  echo ""
}

# ── Uninstaller helper ────────────────────────────────────────────────────────
uninstall() {
  echo -e "  ${R}This will remove fufu-sec completely.${N}"
  read -rp "  Are you sure? [y/N] " YN
  [[ "${YN,,}" == "y" ]] || { info "Aborted."; exit 0; }

  systemctl stop  fufu-sec 2>/dev/null || true
  systemctl disable fufu-sec 2>/dev/null || true
  rm -f "$SERVICE_FILE" "$LAUNCHER"
  rm -rf "$INSTALL_DIR"
  rm -rf "$LOG_DIR" "$TMP_DIR"
  systemctl daemon-reload 2>/dev/null || true
  ok "fufu-sec removed."
  exit 0
}

# ── Entry point ───────────────────────────────────────────────────────────────
case "${1:-install}" in
  install)
    banner
    check_root
    check_os
    install_packages
    clone_repo
    setup_python
    setup_dirs
    write_launcher
    write_service
    check_wireless
    print_summary
    ;;
  uninstall|remove)
    check_root
    uninstall
    ;;
  update)
    check_root
    section "Updating fufu-sec"
    git -C "$INSTALL_DIR" pull --ff-only && ok "Updated"
    "$VENV_DIR/bin/pip" install --upgrade flask flask-cors -q && ok "Python deps updated"
    ;;
  --help|-h|help)
    echo "Usage: sudo bash install.sh [install|uninstall|update]"
    echo ""
    echo "  install    Install fufu-sec (default)"
    echo "  uninstall  Remove fufu-sec completely"
    echo "  update     Pull latest code and update Python deps"
    ;;
  *)
    echo "Unknown command: $1"
    echo "Usage: sudo bash install.sh [install|uninstall|update]"
    exit 1
    ;;
esac
