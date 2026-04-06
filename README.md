# 🔍 Network Scanner

![Bash](https://img.shields.io/badge/language-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![nmap](https://img.shields.io/badge/tool-nmap-0E83CD?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

A Bash-based local network scanner that discovers active hosts, enumerates open TCP ports, and identifies running service versions — built as a hands-on cybersecurity portfolio project.

---

## 📸 Preview

```
[+] Detected network: 192.168.1.0/24 (interface: eth0)

══════════════════════════════════════════
  Phase 1 — Host Discovery
══════════════════════════════════════════
[+] Found 4 live host(s):

  ● 192.168.1.1    router.local
  ● 192.168.1.5    desktop.local
  ● 192.168.1.12   N/A
  ● 192.168.1.20   raspberrypi.local

══════════════════════════════════════════
  Phase 2 — Port & Version Scan
══════════════════════════════════════════
[1/4] Scanning: 192.168.1.1
  PORT                 STATE      SERVICE            VERSION
  ────────────────────────────────────────────────────────
  22/tcp               open       ssh                OpenSSH 8.9p1
  80/tcp               open       http               lighttpd 1.4.59
  443/tcp              open       https              lighttpd 1.4.59
```

---

## ✨ Features

- **Host discovery** — fast ping sweep to find all live hosts on the network
- **Port scanning** — scans well-known ports (1–1024) or a custom range
- **Version detection** — identifies service names and version banners using `nmap -sV`
- **OS detection** — detects the operating system of each host (requires root)
- **Auto network detection** — automatically detects your local subnet if no target is specified
- **Save results** — export full scan output to a timestamped `.txt` file with `-o`
- **Coloured output** — clean, readable terminal output with phase separators
- **Flexible options** — customisable ports, timing, verbosity, and target range

---

## 🛠️ Requirements

| Tool | Install |
|------|---------|
| `nmap` | `sudo apt install nmap` / `brew install nmap` |
| `bash` | Pre-installed on Linux and macOS |
| `ip` / `ifconfig` | Pre-installed on most systems |

> **Note:** Run with `sudo` to enable SYN scanning and OS detection. The script works without root but with reduced capability.

---

## 🚀 Usage

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/network-scanner.git
cd network-scanner

# Make the script executable
chmod +x network_scanner.sh

# Auto-detect your network and scan
sudo ./network_scanner.sh

# Scan a specific CIDR range
sudo ./network_scanner.sh -t 192.168.1.0/24

# Scan specific ports only
sudo ./network_scanner.sh -t 192.168.1.0/24 -p "22,80,443,3306,8080"

# Save results to a file
sudo ./network_scanner.sh -t 192.168.1.0/24 -o

# Scan all 65535 ports (thorough but slower)
sudo ./network_scanner.sh -t 192.168.1.0/24 -p "1-65535"

# Verbose output
sudo ./network_scanner.sh -t 192.168.1.0/24 -v
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t <target>` | Target IP, range, or CIDR | Auto-detected |
| `-p <ports>` | Port range or comma-separated list | `1-1024` |
| `-o` | Save output to a timestamped `.txt` file | Off |
| `-T <0-5>` | nmap timing template (0=slowest, 5=fastest) | `3` |
| `-v` | Verbose — show raw nmap output per host | Off |
| `-h` | Show help message | — |

---

## 📁 Project Structure

```
network-scanner/
├── network_scanner.sh   # Main scanner script
├── README.md            # Project documentation
└── LICENSE              # MIT License
```

---

## 🔬 How It Works

The script runs in three phases:

**Phase 1 — Host Discovery**
Uses `nmap -sn` (ping scan) to sweep the target range and identify which hosts are online without touching any ports.

**Phase 2 — Port & Version Scan**
For each live host, runs `nmap -sV` with optional `-O` (OS detection) to enumerate open ports and pull service version banners.

**Phase 3 — Summary**
Prints a clean summary including total hosts found, ports scanned, and scan duration. Optionally writes results to disk.

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes** and **authorised network testing only**.

> Only scan networks you own or have explicit written permission to test.
> Unauthorised scanning may be illegal in your jurisdiction.

---

## 👤 Author

**Stephen Mungai Muchiri**
- TryHackMe: Jr Penetration Tester path graduate
- Cybersecurity Certificate — Afrihackon Academy
- GitHub: https://github.com/stev-gif

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
