# fufu-sec · AirWeb WiFi Security Suite

> **Framework for Uninvited Frequency Usage**
> A web-based wireless security auditing platform based on [airgeddon v11.61](https://github.com/v1s1t0r1sh3r3/airgeddon) by v1s1t0r.

> ⚠ **AUTHORIZED USE ONLY.** This tool is for penetration testing on networks you own or have explicit written permission to test. Unauthorized interception of wireless traffic is illegal in most jurisdictions.

---

## What is fufu-sec?

fufu-sec is a browser-based frontend for the aircrack-ng/airgeddon wireless security toolkit. Instead of running airgeddon's terminal menus, you get a full dashboard UI that exposes the same capabilities — handshake capture, PMKID attack, WPS cracking, DoS/deauth, Evil Twin, and password cracking — all in one place with live progress, a real-time activity log, and a light/dark mode interface.

The backend (`server.py`) is a Flask REST API that wraps the standard Linux wireless tools. The frontend (`dashboard.html`) is a single HTML file that speaks to the API and runs entirely in your browser.

---

## Features

| Category | What's included |
|---|---|
| **Interface** | Monitor mode toggle, channel lock, MAC spoof, TX power, injection test |
| **Scanner** | airodump-ng network scan, WPS scan (wash), band filter, one-click target fill |
| **Handshake / PMKID** | 4-way handshake capture with live deauth, PMKID capture (hcxdumptool), verify, convert |
| **WPS** | Reaver, Bully, Pixie Dust, PIN database, null PIN, custom PIN |
| **DoS** | aireplay-ng deauth, mdk4 beacon flood / deauth amok / auth DoS / WIDS / Michael TKIP |
| **Evil Twin** | hostapd rogue AP, dnsmasq DHCP, credential capture |
| **Password Cracker** | aircrack-ng, hashcat GPU (mode 22000), John the Ripper, crunch wordlist generator, PMKID cracking |
| **WEP** | Fake auth, ARP replay, ChopChop, Fragmentation, Caffe Latte, Hirte, Besside-ng |
| **System** | CPU/RAM/disk dashboard, audit log, rate limiting, path traversal guards |
| **UI** | Light & dark mode, fully responsive (mobile/tablet), real-time terminal output |

---

## Requirements

### Hardware
- Linux PC or VM (x86_64, ARM64, or ARMv7)
- A wireless adapter that supports **monitor mode** and **packet injection**
  - Recommended: **Alfa AWUS036ACH** (dual-band, excellent driver support)
  - Not recommended: Built-in Intel/Realtek adapters (injection often fails)

### OS
- **Kali Linux** ← best supported
- **Parrot OS** ← best supported
- Ubuntu 20.04+ / Debian 11+

### Software (installed automatically by `install.sh`)
- Python 3.8+
- Flask + flask-cors
- aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng)
- hcxdumptool + hcxtools
- reaver, bully, pixiewps, mdk4
- hashcat, john, crunch
- hostapd, dnsmasq, tcpdump, tshark

---

## Installation

### One-line install

```bash
git clone https://github.com/kyllr-qwen/fufu-sec.git
cd fufu-sec
sudo bash install.sh
```

The script will:
1. Check your OS and Python version
2. Install all required system packages via `apt-get`
3. Clone the repo to `/opt/fufu-sec`
4. Create a Python virtual environment with Flask
5. Write the `fufu-sec` launcher to `/usr/local/bin/fufu-sec`
6. Optionally create a systemd service for auto-start on boot
7. Set up log and temp directories
8. Print a summary with quick-start steps

### Manual install (no installer)

```bash
# 1. Install system packages
sudo apt-get update
sudo apt-get install -y \
  git python3 python3-pip python3-venv iw wireless-tools \
  aircrack-ng reaver bully pixiewps hcxdumptool hcxtools \
  mdk4 tcpdump tshark hashcat john crunch \
  hostapd dnsmasq iptables wordlists

# 2. Extract rockyou.txt
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# 3. Clone the repo
git clone https://github.com/kyllr-qwen/fufu-sec.git /opt/fufu-sec
cd /opt/fufu-sec

# 4. Create virtual environment and install Flask
python3 -m venv .venv
.venv/bin/pip install flask flask-cors

# 5. Create temp and log directories
sudo mkdir -p /tmp/airweb /var/log/airweb
```

---

## Running fufu-sec

### Start the server

```bash
sudo fufu-sec
```

Then open your browser and go to:

```
http://localhost:5000
```

The dashboard opens automatically (unless you're on a headless/SSH system).

### Options

```bash
sudo fufu-sec --port 8080          # use a different port
sudo fufu-sec --host 127.0.0.1     # bind to localhost only
sudo fufu-sec --no-browser         # don't auto-open the browser (SSH/headless)
sudo fufu-sec --help               # show all options
```

### Run directly (without the launcher)

```bash
cd /opt/fufu-sec
sudo .venv/bin/python3 server.py
```

---

## Quick-start workflow

Follow these steps in the dashboard after launching:

```
1. Interface  → Enable Monitor Mode
               Select your wireless adapter → click Enable Monitor

2. Interface  → Test Injection
               Confirm "Injection is working!" before capturing

3. Scanner    → Start Scan
               Wait 15–30s → click Use on your target network
               (BSSID, Channel, SSID auto-fill on all pages)

4. Handshake  → Start Capture
               A deauth burst fires automatically every 12s
               Wait for a client to reconnect → banner shows ✓ HANDSHAKE CAPTURED

5. Cracker    → aircrack-ng tab
               Cap file is auto-filled → select a wordlist → Crack
```

For PMKID (no clients needed):

```
1. Interface  → Enable Monitor Mode
2. Handshake  → PMKID tab → enter BSSID + Channel → Capture PMKID (45s)
3. Cracker    → PMKID Hash tab → Inspect → hashcat → Crack with hashcat
```

---

## Updating

```bash
sudo bash install.sh update
```

Or manually:

```bash
cd /opt/fufu-sec
git pull
.venv/bin/pip install --upgrade flask flask-cors
```

---

## Uninstalling

```bash
sudo bash install.sh uninstall
```

This removes `/opt/fufu-sec`, the launcher at `/usr/local/bin/fufu-sec`, the systemd service, and the log directory.

---

## Running as a systemd service

If you chose to install the service during setup:

```bash
sudo systemctl enable  fufu-sec   # start automatically on boot
sudo systemctl start   fufu-sec   # start now
sudo systemctl stop    fufu-sec   # stop
sudo systemctl restart fufu-sec   # restart
sudo systemctl status  fufu-sec   # check if running
sudo journalctl -u fufu-sec -f    # follow live logs
```

Access the dashboard at `http://localhost:5000` after starting the service.

---

## File structure

```
/opt/fufu-sec/
├── server.py          ← Flask REST API backend (all wireless tool logic)
├── dashboard.html     ← Single-file web dashboard (open in browser)
├── .venv/             ← Python virtual environment (Flask + flask-cors)
└── LICENSE            ← Apache-2.0

/tmp/airweb/           ← Capture files (.cap, .pcapng, .csv), temp files
/var/log/airweb/       ← airweb.log (rotating, 5 MB × 5), audit.log
/usr/local/bin/fufu-sec ← CLI launcher
```

---

## API endpoints (for scripting)

The backend exposes a REST API on `http://localhost:5000`. Every endpoint returns JSON.

```
GET  /api/status               server + interface status
GET  /api/health               disk/RAM/tool health check
GET  /api/interfaces           list wireless interfaces

POST /api/monitor/enable       start monitor mode
POST /api/monitor/disable      stop monitor mode

POST /api/scan/start           start airodump-ng scan
GET  /api/scan/results         get scan results
POST /api/scan/stop            stop scan

POST /api/handshake/capture    start handshake capture
GET  /api/handshake/log        live worker log + result
POST /api/handshake/verify     verify a .cap file
GET  /api/handshake/list       list all cap files

POST /api/pmkid/capture        start PMKID capture (hcxdumptool)

POST /api/deauth               send deauth frames
POST /api/injection/test       test packet injection

POST /api/crack/aircrack       crack with aircrack-ng
POST /api/crack/hashcat        crack with hashcat
POST /api/crack/convert        convert .cap → hashcat 22000 format

POST /api/exec                 run arbitrary shell command (filtered)
GET  /api/audit/log            view audit log entries
```

---

## Troubleshooting

**"airodump-ng exited immediately"**
Your interface name changed after enabling monitor mode. Go to Interface page and manually enter the monitor interface name shown by `iw dev`.

**"aireplay-ng exited immediately — check injection support"**
Your adapter does not support packet injection or needs a driver that does. Run: `sudo aireplay-ng --test <iface>`. Use an Alfa AWUS036ACH for reliable injection.

**"No handshake captured" after timeout**
- PMF/802.11w is enabled on the AP (WPA3 or WPA2-PMF) — deauth is cryptographically blocked. Wait for a natural client reconnect.
- No active clients on the AP at the time of capture.
- Try increasing the timeout to 60–90 seconds.

**"hcxdumptool failed"**
hcxdumptool 6.3.0+ requires BPF mode (channel + BSSID both required). Make sure you fill in the Channel field on the PMKID page. Install tcpdump if missing: `sudo apt-get install tcpdump`.

**PMKID hash file is empty**
Not all APs broadcast PMKID. Try a handshake capture instead.

**hashcat: "No devices found / OpenCL error"**
Install OpenCL runtime: `sudo apt-get install ocl-icd-opencl-dev pocl-opencl-icd`

**rockyou.txt not found**
`sudo apt-get install wordlists && sudo gunzip /usr/share/wordlists/rockyou.txt.gz`

---

## Known limitations

- Requires root — aircrack-ng suite needs raw socket access.
- Evil Twin feature requires a second wireless adapter (one for deauth, one for the AP).
- hashcat GPU cracking only works with a compatible GPU and driver (NVIDIA CUDA or AMD ROCm).
- Some Intel/Realtek built-in adapters do not support packet injection regardless of driver.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Based on [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) by v1s1t0r, licensed under GPL-3.0.

---

*fufu-sec — Framework for Uninvited Frequency Usage*
