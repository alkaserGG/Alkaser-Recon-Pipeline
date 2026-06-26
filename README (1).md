# 🦅 ALKASER — Bug Bounty Recon & Exploitation Pipeline

> A fully-automated, cross-platform Bug Bounty reconnaissance and exploitation pipeline built in Python 3.  
> Chains **subfinder → httpx → ffuf → katana → waybackurls → uro → gf → nuclei → sqlmap → XSStrike** and consolidates every finding into a clean Markdown report with optional Discord / Telegram alerting.

BANNER = r"""
[bold red]
     █████╗ ██╗     ██╗  ██╗ █████╗ ███████╗███████╗██████╗ 
    ██╔══██╗██║     ██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔══██╗
    ███████║██║     █████╔╝ ███████║███████╗█████╗  ██████╔╝
    ██╔══██║██║     ██╔═██╗ ██╔══██║╚════██║██╔══╝  ██╔══██╗
    ██║  ██║███████╗██║  ██╗██║  ██║███████║███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝[/bold red]
[bold white]          [ Autonomous Recon & Exploitation Pipeline ][/bold white]
[bold red]                 << GG : SECURITY GAME OVER >>[/bold red]
"""

def print_banner() -> None:
    console.print(BANNER)
    console.rule(style="dim cyan")


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
- [Notifications](#-notifications-discord--telegram)
- [Responsible Disclosure](#-responsible-disclosure)
- [License](#-license)

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🔍 Subdomain Enumeration | `subfinder` with passive OSINT sources |
| 🌐 Alive Filtering | `httpx` — fast, concurrent HTTP probing |
| 📁 Directory Brute-Force | `ffuf` matching HTTP 200 & 403 |
| 🕷️ Crawling & Spidering | `katana` + `waybackurls` running in parallel |
| 🔗 Parameter Deduplication | `uro` removes duplicate endpoints |
| 🎯 Pattern Filtering | `gf` extracts SQLi and XSS candidate URLs |
| 💣 Vulnerability Scanning | `nuclei` (critical / high / medium templates) |
| 🗄️ SQL Injection | `sqlmap` — automated, batch mode |
| ✴️ Cross-Site Scripting | `XSStrike` — crawl + skip interactive mode |
| 📝 Markdown Report | All findings in one clean `.md` file |
| 🔔 Notifications | Discord webhook or Telegram bot |
| 🖥️ Cross-Platform | Linux & Windows, OS-aware binary resolution |
| ⚡ Concurrency | Nuclei + Katana run in parallel via `ThreadPoolExecutor` |
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
    ├──────────────────────────────────────────────────────┐
    ▼                                                      ▼
[3] ffuf               → recon/ffuf/        [4a] katana    → crawl/katana.txt
    (dir brute-force)                        [4b] waybackurls → crawl/wayback.txt
                                            (run in parallel)
                                                      │
                                                      ▼
                                            [5] uro + gf
                                                 ├── sqli_urls.txt
                                                 └── xss_urls.txt
    │
    ▼
[6] nuclei             → vulns/nuclei.txt   (runs parallel with crawl)
    │
    ├─────────────────────────────────────────────────────┐
    ▼                                                     ▼
[7] sqlmap             → exploit/sqlmap/    [8] XSStrike  → exploit/xsstrike.txt
    │
    ▼
[9] Markdown report + Discord/Telegram notification
```

---

## 📂 Output Structure

```
results/
└── target.com/
    ├── recon/
    │   ├── subdomains.txt      # Raw subfinder output
    │   ├── alive.txt           # Live URLs from httpx
    │   └── ffuf/               # One JSON file per host
    ├── crawl/
    │   ├── katana.txt
    │   ├── wayback.txt
    │   ├── all_urls.txt        # Merged crawl results
    │   ├── uro_deduped.txt     # After deduplication
    │   ├── sqli_urls.txt       # gf sqli output
    │   └── xss_urls.txt        # gf xss output
    ├── vulns/
    │   └── nuclei.txt
    ├── exploit/
    │   ├── sqlmap/             # sqlmap output per target
    │   └── xsstrike.txt
    └── report.md               # ← Final consolidated report
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
git clone https://github.com/your-handle/alkaser.git
cd alkaser
pip3 install -r requirements.txt
```

#### 3 — Go (required for the Go-based tools)

```bash
# Check if Go is already installed
go version

# If not, install it
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### 4 — Go-based tools (one-liner block)

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
# Clone the popular gf-patterns repo
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
# Or from tomnomnom
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

Download from [python.org](https://www.python.org/downloads/) and tick **"Add Python to PATH"** during setup.

```powershell
pip install -r requirements.txt
```

#### 2 — Go

Download the Windows installer from [go.dev/dl](https://go.dev/dl/).  
Verify with `go version` in a new PowerShell window.

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

Make sure `%USERPROFILE%\go\bin` is in your `PATH` (System → Advanced → Environment Variables).

#### 4 — gf patterns (PowerShell)

```powershell
git clone https://github.com/1ndianl33t/Gf-Patterns $env:USERPROFILE\.gf
```

#### 5 — sqlmap (Python, cross-platform)

```powershell
git clone https://github.com/sqlmapproject/sqlmap.git C:\tools\sqlmap
# Add C:\tools\sqlmap to PATH, or call via python C:\tools\sqlmap\sqlmap.py
```

#### 6 — XSStrike (Python, cross-platform)

```powershell
git clone https://github.com/s0md3v/XSStrike.git C:\tools\XSStrike
cd C:\tools\XSStrike
pip install -r requirements.txt
# Add C:\tools\XSStrike to PATH and rename/copy xsstrike.py as xsstrike.bat:
# @python "C:\tools\XSStrike\xsstrike.py" %*
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
              [--telegram-token TELEGRAM_TOKEN] [--telegram-chat TELEGRAM_CHAT]
              [--skip-missing] [--skip-exploit] [--xss-limit XSS_LIMIT] [--no-notify]

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

control flags:
  --skip-missing                Continue even if some tools are absent
  --skip-exploit                Skip sqlmap + XSStrike stages
  --xss-limit N                 Max URLs sent to XSStrike (default: 20)
  --no-notify                   Suppress all webhook notifications
```

---

## 🔔 Notifications (Discord / Telegram)

### Discord

1. Open your Discord server → **Edit Channel → Integrations → Webhooks → New Webhook**.
2. Copy the URL and pass it via `--discord`.

```bash
python3 main.py -d target.com --discord "https://discord.com/api/webhooks/111/xxx"
```

### Telegram

1. Message [@BotFather](https://t.me/BotFather) to create a bot → copy the token.
2. Add the bot to your group/channel and get the Chat ID (e.g. via `getUpdates`).

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

MIT © 2025 — Your Name  
See [LICENSE](LICENSE) for full terms.

---

## 🤝 Contributing

Pull requests and issue reports are welcome.  
Please open an issue first for major changes.

```bash
git clone https://github.com/your-handle/alkaser.git
cd alkaser
git checkout -b feature/my-improvement
```

---

_Made with ❤️ for the bug bounty community._
