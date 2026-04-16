# fufu-sec

**Framework for Uninvited Frequency Usage**
A browser-based wireless security auditing tool by [kyllr-qwen](https://github.com/kyllr-qwen/fufu-sec).

> ⚠ Authorized use only. Only test networks you own or have explicit written permission to audit.

---

## What it does

fufu-sec is a web dashboard for wireless security testing. It wraps the standard Linux aircrack-ng toolset into a single-page UI with live terminal output, real-time progress, and light/dark mode.

**Capabilities:** monitor mode, network scanner, 4-way handshake capture, PMKID attack, WPS brute-force (Reaver / Bully / Pixie Dust), DoS/deauth, Evil Twin AP, WEP attacks, and password cracking (aircrack-ng / hashcat / John).

---

## Requirements

- Linux — Kali or Parrot OS recommended
- A wireless adapter that supports **monitor mode + packet injection** (Alfa AWUS036ACH recommended)
- Python 3.8+

---

## Installation

```bash
git clone https://github.com/kyllr-qwen/fufu-sec.git
cd fufu-sec
sudo bash install.sh
```

That's it. Nothing is installed globally — everything stays inside the `fufu-sec/` folder.
To uninstall, delete the folder.

---

## Usage

```bash
cd fufu-sec
sudo .venv/bin/python3 server.py
```

Open **http://localhost:5000** in your browser.

### Workflow

```
1. Interface  → Enable Monitor Mode  (select your adapter)
2. Interface  → Test Injection       (must pass before capturing)
3. Scanner    → Scan                 (click Use on your target)
4. Handshake  → Start Capture        (wait for ✓ HANDSHAKE CAPTURED)
5. Cracker    → Crack                (wordlist auto-filled)
```

### Options

```bash
sudo .venv/bin/python3 server.py --port 8080        # custom port
sudo .venv/bin/python3 server.py --host 127.0.0.1   # localhost only
sudo .venv/bin/python3 server.py --no-browser       # headless / SSH
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `airodump-ng exited immediately` | Interface renamed after monitor enable — re-enter the exact name shown by `iw dev` |
| `aireplay-ng exited — check injection` | Adapter does not support injection — run `aireplay-ng --test <iface>` to confirm |
| `No handshake captured` | AP has PMF/802.11w enabled, or no active clients — wait longer or target a specific client MAC |
| `hcxdumptool failed` | Fill in the Channel field on the PMKID page; install tcpdump if missing |
| `hashcat: no devices` | `sudo apt-get install ocl-icd-opencl-dev pocl-opencl-icd` |
| `rockyou.txt not found` | `sudo gunzip /usr/share/wordlists/rockyou.txt.gz` |

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
