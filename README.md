# 🦅 ALKASER — Bug Bounty Recon & Exploitation Pipeline

> A fully-automated, cross-platform Bug Bounty reconnaissance and exploitation pipeline built in Python 3.  
> Chains **subfinder → httpx → ffuf → katana → waybackurls → uro → gf → nuclei → sqlmap → XSStrike** and consolidates every finding into a clean Markdown report with optional Discord / Telegram alerting.

```
     █████╗ ██╗     ██╗  ██╗ █████╗ ███████╗███████╗██████╗ 
    ██╔══██╗██║     ██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔══██╗
    ███████║██║     █████╔╝ ███████║███████╗█████╗  ██████╔╝
    ██╔══██║██║     ██╔═██╗ ██╔══██║╚════██║██╔══╝  ██╔══██╗
    ██║  ██║███████╗██║  ██╗██║  ██║███████║███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

![GitHub stars](https://img.shields.io/github/stars/alkaserGG/Alkaser-Recon-Pipeline) ![GitHub license](https://img.shields.io/github/license/alkaserGG/Alkaser-Recon-Pipeline) ![Python version](https://img.shields.io/badge/python-3.8+-blue) [![Facebook](https://img.shields.io/badge/Facebook-Abdo%20Alkaser-1877F2?style=flat&logo=facebook)](https://www.facebook.com/abdo.alkaser.5)

---

## 📋 Table of Contents

- [Features](#-features)
- [Pipeline Overview](#-pipeline-overview)
- [Output Structure](#-output-structure)
- [Installation](#-installation)
  - [Linux (Kali / Ubuntu / Parrot)](#linux-kali--ubuntu--parrot)
  - [Windows 10 / 11](#windows-10--11)
- [Usage](#-usage)
- [CLI Reference](#-cli-reference)
- [Smart Rate Limiting & Auto-Skip Logic](#-smart-rate-limiting--auto-skip-logic)
- [Notifications](#-notifications-discord--telegram)
- [Responsible Disclosure](#-responsible-disclosure)
- [License](#-license)

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🔍 Subdomain Enumeration | `subfinder` with passive OSINT sources |
| 🌐 Alive Filtering | `httpx` — fast, concurrent HTTP probing |
| 📁 Directory Brute-Force | `ffuf` with smart auto-skip threshold |
| 🕷️ Crawling & Spidering | `katana` + `waybackurls` running in parallel |
| 🔗 Parameter Deduplication | `uro` removes duplicate endpoints |
| 🎯 Pattern Filtering | `gf` extracts SQLi and XSS candidate URLs |
| 💣 Vulnerability Scanning | `nuclei` — feeds directly from `httpx` alive hosts |
| ⚡ Dynamic Rate Limiting | Nuclei concurrency + rate auto-scales by host count |
| 🗄️ SQL Injection | `sqlmap` — automated, batch mode, BEUST techniques |
| ✴️ Cross-Site Scripting | `XSStrike` — crawl + skip interactive mode |
| 📝 Markdown Report | All findings in one clean `.md` file |
| 🔔 Notifications | Discord webhook or Telegram bot |
| 🖥️ Cross-Platform | Linux & Windows, OS-aware binary resolution |
| 🛡️ Dependency Checker | Friendly error table listing every missing tool |

---

## 🔄 Pipeline Overview

```
target.com
    │
    ▼
[1] subfinder          → subdomains.txt
    │
    ▼
[2] httpx              → alive.txt          (live hosts only)
    │
    ├─────────────────────────────────────────────────────────┐
    ▼                                                         ▼
[3] ffuf               → recon/ffuf/        [4a] katana       → crawl/katana.txt
    (auto-skipped if                         [4b] waybackurls → crawl/wayback.txt
     hosts > threshold)                      (run in parallel)
                                                       │
                                                       ▼
                                             [5] uro + gf
                                                  ├── sqli_urls.txt
                                                  └── xss_urls.txt
    │
    ▼
[6] nuclei             → vulns/nuclei.txt
    (reads alive.txt directly, dynamic rate limit)
    │
    ├─────────────────────────────────────────────────────────┐
    ▼                                                         ▼
[7] sqlmap             → exploit/sqlmap/    [8] XSStrike  → exploit/xsstrike.txt
    │
    ▼
[9] Markdown report + Discord/Telegram notification
```

> **Note:** Nuclei runs directly from `httpx` output (`alive.txt`), not from `uro`.  
> This prevents scanning thousands of deduplicated URLs unnecessarily and keeps scan time controlled.

---

## 📂 Output Structure

```
results/
└── target.com/
    ├── recon/
    │   ├── subdomains.txt        # Raw subfinder output
    │   ├── alive.txt             # Live URLs from httpx
    │   ├── nuclei_input.txt      # Auto-created if hosts > --nuclei-limit
    │   └── ffuf/                 # One JSON file per host
    ├── crawl/
    │   ├── katana.txt
    │   ├── wayback.txt
    │   ├── all_urls.txt          # Merged crawl results
    │   ├── uro_deduped.txt       # After deduplication
    │   ├── sqli_urls.txt         # gf sqli output
    │   └── xss_urls.txt          # gf xss output
    ├── vulns/
    │   └── nuclei.txt            # All nuclei findings (single file)
    ├── exploit/
    │   ├── sqlmap/               # sqlmap output per target
    │   └── xsstrike.txt
    └── report.md                 # ← Final consolidated report
```

---

## 🛠️ Installation

### Linux (Kali / Ubuntu / Parrot)

#### 1 — Python 3 and pip

```bash
sudo apt update && sudo apt install -y python3 python3-pip git
```

#### 2 — Python dependencies

```bash
git clone https://github.com/alkaserGG/Alkaser-Recon-Pipeline.git
cd Alkaser-Recon-Pipeline
pip3 install -r requirements.txt
```

#### 3 — Go (required for the Go-based tools)

```bash
go version   # check if already installed

# If not:
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### 4 — Go-based tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/s0md3v/uro@latest
go install -v github.com/tomnomnom/gf@latest
```

#### 5 — ffuf

```bash
go install github.com/ffuf/ffuf/v2@latest
# Or via apt on Kali:
sudo apt install ffuf -y
```

#### 6 — gf patterns

```bash
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
# Or from tomnomnom:
mkdir -p ~/.gf
git clone https://github.com/tomnomnom/gf /tmp/gf && cp /tmp/gf/examples/*.json ~/.gf/
```

#### 7 — sqlmap

```bash
sudo apt install sqlmap -y
# Or from source:
git clone https://github.com/sqlmapproject/sqlmap.git ~/tools/sqlmap
sudo ln -s ~/tools/sqlmap/sqlmap.py /usr/local/bin/sqlmap
```

#### 8 — XSStrike

```bash
git clone https://github.com/s0md3v/XSStrike.git ~/tools/XSStrike
cd ~/tools/XSStrike
pip3 install -r requirements.txt
sudo ln -s ~/tools/XSStrike/xsstrike.py /usr/local/bin/xsstrike
chmod +x ~/tools/XSStrike/xsstrike.py
```

#### 9 — Verify everything is in PATH

```bash
python3 main.py -d test.com --skip-missing   # shows dependency table
```

---

### Windows 10 / 11

#### 1 — Python 3

Download from [python.org](https://www.python.org/downloads/) — tick **"Add Python to PATH"** during setup.

```powershell
pip install -r requirements.txt
```

#### 2 — Go

Download the Windows installer from [go.dev/dl](https://go.dev/dl/). Verify with `go version`.

#### 3 — Go-based tools (PowerShell)

```powershell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/s0md3v/uro@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

Make sure `%USERPROFILE%\go\bin` is in your `PATH`.

#### 4 — gf patterns

```powershell
git clone https://github.com/1ndianl33t/Gf-Patterns $env:USERPROFILE\.gf
```

#### 5 — sqlmap

```powershell
git clone https://github.com/sqlmapproject/sqlmap.git C:\tools\sqlmap
# Add C:\tools\sqlmap to PATH
```

#### 6 — XSStrike

```powershell
git clone https://github.com/s0md3v/XSStrike.git C:\tools\XSStrike
cd C:\tools\XSStrike
pip install -r requirements.txt
# Create xsstrike.bat: @python "C:\tools\XSStrike\xsstrike.py" %*
```

---

## 🚀 Usage

### Minimal run

```bash
python3 main.py -d target.com
```

### With a custom wordlist

```bash
python3 main.py -d target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
```

### Recon only (skip exploitation)

```bash
python3 main.py -d target.com --skip-exploit
```

### Skip directory brute-force entirely

```bash
python3 main.py -d target.com --skip-fuzz
```

### Auto-skip ffuf only when hosts are many (default threshold = 20)

```bash
# ffuf will auto-skip if alive hosts > 20; override with --force-fuzz
python3 main.py -d target.com --fuzz-threshold 10
python3 main.py -d target.com --force-fuzz          # force ffuf regardless
```

### Control how many hosts Nuclei scans

```bash
python3 main.py -d target.com --nuclei-limit 50     # default is 75
```

### With Discord notification

```bash
python3 main.py -d target.com --discord "https://discord.com/api/webhooks/XXXX/YYYY"
```

### With Telegram notification

```bash
python3 main.py -d target.com \
  --telegram-token "123456:ABCdef..." \
  --telegram-chat  "-1001234567890"
```

### Continue if some tools are missing

```bash
python3 main.py -d target.com --skip-missing
```

### Limit XSStrike to first 10 XSS candidates

```bash
python3 main.py -d target.com --xss-limit 10
```

---

## 📖 CLI Reference

```
usage: alkaser [-h] -d DOMAIN [-w WORDLIST] [-o OUTPUT]
               [--discord DISCORD]
               [--telegram-token TOKEN] [--telegram-chat CHAT_ID]
               [--skip-missing] [--skip-exploit] [--skip-fuzz]
               [--xss-limit N] [--no-notify]
               [--fuzz-threshold N] [--force-fuzz] [--nuclei-limit N]
               [--threads N] [--rate-limit N] [--timeout N] [--ports PORTS]

options:
  -h, --help                    Show help and exit

target:
  -d DOMAIN, --domain DOMAIN    Target domain (required)  e.g. example.com

output:
  -w WORDLIST, --wordlist       Wordlist for ffuf (auto-detected if omitted)
  -o OUTPUT,   --output         Base output directory (default: results/)

notifications:
  --discord DISCORD             Discord webhook URL
  --telegram-token TOKEN        Telegram bot token
  --telegram-chat CHAT_ID       Telegram chat / channel ID
  --no-notify                   Suppress all webhook notifications

control flags:
  --skip-missing                Continue even if some tools are absent
  --skip-exploit                Skip sqlmap + XSStrike stages
  --skip-fuzz                   Skip ffuf entirely (manual override)
  --xss-limit N                 Max URLs sent to XSStrike (default: 20)
  --fuzz-threshold N            Auto-skip ffuf if alive hosts exceed N (default: 20)
  --force-fuzz                  Force ffuf even if alive hosts exceed --fuzz-threshold
  --nuclei-limit N              Max hosts passed to Nuclei (default: 75)

probing options:
  --threads N                   httpx thread count (default: 30)
  --rate-limit N                Max requests/sec for httpx & Nuclei baseline (default: 50)
  --timeout N                   httpx timeout in seconds (default: 3)
  --ports PORTS                 Ports to probe (default: 80,443)
```

---

## ⚡ Smart Rate Limiting & Auto-Skip Logic

### ffuf Auto-Skip

ffuf can be extremely slow on large scopes. ALKASER handles this automatically:

| Alive hosts | Behavior |
|---|---|
| ≤ `--fuzz-threshold` (default 20) | ffuf runs normally |
| > threshold | Auto-skipped with warning |
| Any count + `--force-fuzz` | ffuf runs regardless |
| Any count + `--skip-fuzz` | ffuf always skipped |

### Nuclei Dynamic Rate Limiting

Nuclei feeds directly from `httpx` alive hosts (not from `uro`) to prevent scanning thousands of URLs unnecessarily. Rate limits scale automatically:

| Alive hosts | Concurrency (`-c`) | Rate limit (`-rl`) |
|---|---|---|
| 10 | 10 | ~100 req/s |
| 30 | 30 | ~150 req/s |
| 75 (default limit) | 30 | 300 req/s |

If alive hosts exceed `--nuclei-limit`, only the first N hosts are scanned and a `recon/nuclei_input.txt` is created automatically.

---

## 🔔 Notifications (Discord / Telegram)

### Discord

1. Open your Discord server → **Edit Channel → Integrations → Webhooks → New Webhook**.
2. Copy the URL and pass it via `--discord`.

```bash
python3 main.py -d target.com --discord "https://discord.com/api/webhooks/111/xxx"
```

### Telegram

1. Message [@BotFather](https://t.me/BotFather) to create a bot — copy the token.
2. Add the bot to your group/channel and get the Chat ID via `getUpdates`.

```bash
python3 main.py -d target.com \
  --telegram-token "7123456789:AAFexample" \
  --telegram-chat  "-1001234567890"
```

---

## ⚖️ Responsible Disclosure

> **ALKASER is intended for authorized security testing only.**  
> Always obtain explicit written permission from the target organization before running any automated scans.  
> Unauthorized use is illegal and unethical. The authors bear no responsibility for misuse.

This tool is designed for:
- Bug bounty programs where you have in-scope authorization
- Penetration testing engagements with a signed Statement of Work
- Testing your **own** infrastructure

---

## 📄 License

MIT © 2026 — Abdo Alkaser  
See [LICENSE](LICENSE) for full terms.

---

## 🤝 Contributing

Pull requests and issue reports are welcome. Please open an issue first for major changes.

```bash
git clone https://github.com/alkaserGG/Alkaser-Recon-Pipeline.git
cd Alkaser-Recon-Pipeline
git checkout -b feature/my-improvement
```

---

_Made with ❤️ for the bug bounty community._
