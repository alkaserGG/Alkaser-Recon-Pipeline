#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║        ALKASER-GG — Bug Bounty Recon & Exploitation Pipeline  ║
║               github.com/your-handle/alkaser                  ║
╚═══════════════════════════════════════════════════════════════╝

A fully-automated, cross-platform Bug Bounty reconnaissance and
exploitation pipeline.  Chains subfinder → httpx → ffuf → katana
→ waybackurls → uro → gf → nuclei → sqlmap → XSStrike and
consolidates every finding into a Markdown report.

Author  : Abdo Mohamed
License : MIT
"""

from __future__ import annotations

import argparse
import json                          
import platform
import shutil
import subprocess
import sys
import textwrap
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

import requests                     
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.theme import Theme

# ─── Console theme ──────────────────────────────────────────────────────────
THEME = Theme(
    {
        "info":    "bold cyan",
        "success": "bold green",
        "warn":    "bold yellow",
        "error":   "bold red",
        "step":    "bold magenta",
        "dim":     "dim white",
        "header":  "bold white on dark_blue",
    }
)
console = Console(theme=THEME)

REQUIRED_TOOLS = [
    "subfinder",
    "httpx",
    "ffuf",
    "katana",
    "waybackurls",
    "uro",
    "gf",
    "nuclei",
    "sqlmap",
    "xsstrike",   
]

IS_WINDOWS = platform.system() == "Windows"

BANNER = r"""
[bold red]
     █████╗ ██╗     ██╗  ██╗ █████╗ ███████╗███████╗██████╗ 
    ██╔══██╗██║     ██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔══██╗
    ███████║██║     ██████╔╝ ███████║███████╗█████╗  ██████╔╝
    ██╔══██║██║     ██╔═██╗ ██╔══██║╚════██║██╔══╝  ██╔══██╗
    ██║  ██║███████╗██║  ██╗██║  ██║███████║███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝[/bold red]
[bold white]           [ Autonomous Recon & Exploitation Pipeline ][/bold white]
[bold red]                 << GG : SECURITY GAME OVER >>[/bold red]
"""

def print_banner() -> None:
    console.print(BANNER)
    console.rule(style="dim cyan")


# ─────────────────────────────────────────────────────────────────────────────
# 1.  Dependency Checker
# ─────────────────────────────────────────────────────────────────────────────

def resolve_tool_name(name: str) -> str:
    if IS_WINDOWS:
        return f"{name}.exe"
    return name


def check_dependencies(skip_missing: bool = False) -> bool:
    console.print("\n[step][ ⚙ ] Checking dependencies …[/step]")

    table = Table(
        "Tool", "Status", "Path",
        box=box.SIMPLE_HEAD, show_header=True,
        header_style="header", show_lines=False,
    )

    missing: list[str] = []
    aliases = {"xsstrike": ["xsstrike", "XSStrike"]}

    for tool in REQUIRED_TOOLS:
        candidates = aliases.get(tool.lower(), [tool])
        found_path: Optional[str] = None

        for candidate in candidates:
            binary = resolve_tool_name(candidate)
            found_path = shutil.which(binary)
            if not found_path and IS_WINDOWS:
                found_path = shutil.which(candidate)
            if found_path:
                break

        if found_path:
            table.add_row(tool, "[success]✔  Found[/success]", found_path)
        else:
            table.add_row(tool, "[error]✘  Missing[/error]", "—")
            missing.append(tool)

    console.print(table)

    if missing:
        console.print(
            f"\n[error][ ✘ ] Missing tools: {', '.join(missing)}[/error]\n"
            "[warn]Please install them and make sure they are in your PATH.\n"
            "See the README for installation instructions.[/warn]"
        )
        if not skip_missing:
            return False

    console.print("[success][ ✔ ] Dependency check complete.[/success]\n")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 2.  Directory Layout
# ─────────────────────────────────────────────────────────────────────────────

class OutputLayout:
    def __init__(self, target: str, base: str = "results") -> None:
        self.target = target
        self.root   = Path(base) / target
        self.recon  = self.root / "recon"
        self.vulns  = self.root / "vulns"
        self.crawl  = self.root / "crawl"
        self.exploit= self.root / "exploit"

        self.subdomains        = self.recon / "subdomains.txt"
        self.alive             = self.recon / "alive.txt"
        self.ffuf_dir          = self.recon / "ffuf"
        self.katana_out        = self.crawl / "katana.txt"
        self.wayback_out       = self.crawl / "wayback.txt"
        self.all_urls          = self.crawl / "all_urls.txt"
        self.uro_out           = self.crawl / "uro_deduped.txt"
        self.sqli_urls         = self.crawl / "sqli_urls.txt"
        self.xss_urls          = self.crawl / "xss_urls.txt"
        self.nuclei_out        = self.vulns / "nuclei.txt"
        self.sqlmap_out        = self.exploit / "sqlmap"
        self.xsstrike_out      = self.exploit / "xsstrike.txt"
        self.report            = self.root / "report.md"

    def create(self) -> None:
        for d in [
            self.recon, self.vulns, self.crawl,
            self.exploit, self.ffuf_dir, self.sqlmap_out,
        ]:
            d.mkdir(parents=True, exist_ok=True)
        console.print(f"[success][ ✔ ] Output directory: [bold]{self.root}[/bold][/success]")


# ─────────────────────────────────────────────────────────────────────────────
# 3.  Shell helper
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(
    cmd: list[str],
    output_file: Optional[Path] = None,
    stdin_data: Optional[str]   = None,
    label: str = "",
    capture: bool = False,
    silent: bool = False, 
) -> subprocess.CompletedProcess:
    if not silent:
        console.print(f"[dim]   $ {' '.join(str(c) for c in cmd)}[/dim]")

    kwargs: dict = dict(
        args=cmd,
        text=True,
        input=stdin_data,
        stderr=subprocess.PIPE,
        errors="ignore",
    )

    f_handle = None
    if output_file:
        f_handle = open(output_file, "w", encoding="utf-8", errors="ignore")
        kwargs["stdout"] = f_handle
    elif capture:
        kwargs["stdout"] = subprocess.PIPE
    else:
        kwargs["stdout"] = subprocess.DEVNULL

    try:
        return subprocess.run(**kwargs)  
    except FileNotFoundError:
        console.print(f"[error][ ✘ ] '{cmd[0]}' not found. Is it installed and in PATH?[/error]")
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="")
    except Exception as exc:
        console.print(f"[error][ ✘ ] {label} failed: {exc}[/error]")
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="")
    finally:
        if f_handle:
            f_handle.close()


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# 4.  Pipeline Steps
# ─────────────────────────────────────────────────────────────────────────────

class Pipeline:
    def __init__(self, target: str, layout: OutputLayout, args: argparse.Namespace) -> None:
        self.target = target
        self.layout = layout
        self.args   = args
        self.stats: dict[str, int | str] = {}
        self._current_progress: Optional[Progress] = None
        self._current_task = None

    def _advance_stage(self, label: str) -> None:
        if self._current_progress and self._current_task is not None:
            self._current_progress.advance(self._current_task)
        console.print(f"[step][ ★ ] Stage complete: {label}[/step]")

    def step_subfinder(self) -> None:
        console.print(Panel(f"[+] Running Subfinder on [bold]{self.target}[/bold]", style="step", expand=False))
        cmd = ["subfinder", "-d", self.target, "-silent", "-o", str(self.layout.subdomains)]
        run_cmd(cmd, label="subfinder")
        count = len(read_lines(self.layout.subdomains))
        self.stats["subdomains"] = count
        console.print(f"[success][ ✔ ] Subfinder found {count} subdomains.[/success]")

    def step_httpx(self) -> None:
        console.print(Panel("[+] Filtering alive hosts with httpx", style="step", expand=False))
        subdomains = read_lines(self.layout.subdomains)
        if not subdomains:
            console.print("[warn][ ! ] No subdomains to probe. Skipping httpx.[/warn]")
            return

        httpx_bin = shutil.which("httpx")
        if not httpx_bin:
            console.print("[error][ ✘ ] httpx binary could not be found in PATH.[/error]")
            return

        cmd = [
            httpx_bin, "-list", str(self.layout.subdomains), "-silent",
            "-threads", str(self.args.threads), "-rl", str(self.args.rate_limit),
            "-timeout", str(self.args.timeout), "-ports", self.args.ports,
            "-random-agent", "-o", str(self.layout.alive),
        ]
        run_cmd(cmd, label="httpx")
        count = len(read_lines(self.layout.alive))
        self.stats["alive"] = count
        console.print(f"[success][ ✔ ] httpx found {count} live hosts.[/success]")

    def _run_single_ffuf(self, host: str, url: str, wordlist: str, lock: threading.Lock, state: dict) -> None:
        out = self.layout.ffuf_dir / f"{host}.json"
        cmd = [
            "ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist,
            "-ac", "-t", "20", "-o", str(out), "-of", "json", "-s",
        ]
        run_cmd(cmd, label=f"ffuf:{host}", silent=True)

        if out.exists():
            try:
                data = json.loads(out.read_text(encoding="utf-8", errors="ignore"))
                results = data.get("results", [])
                findings = len(results)
                
                with lock:
                    state["total_findings"] += findings
                    for res in results:
                        u = res.get("url")
                        if u: state["urls"].append(u)
                        
                console.print(f"  [dim]{host}: {findings} paths found[/dim]")
            except Exception:
                pass

    def step_ffuf(self) -> None:
        if self.args.skip_fuzz:
            self.stats["ffuf_paths"] = "Skipped (--skip-fuzz)"
            return

        console.print(Panel("[+] Directory brute-forcing with ffuf (Parallel)", style="step", expand=False))
        alive_urls = read_lines(self.layout.alive)

        if not alive_urls:
            console.print("[warn][ ! ] No alive URLs. Skipping ffuf.[/warn]")
            self.stats["ffuf_paths"] = "Skipped/No alive hosts"
            return

        if not self.args.force_fuzz and len(alive_urls) > self.args.fuzz_threshold:
            console.print(
                f"[warn][ ! ] {len(alive_urls)} alive hosts found — "
                f"exceeds threshold ({self.args.fuzz_threshold}). "
                f"Auto-skipping ffuf to save time. "
                f"Use --force-fuzz to override.[/warn]"
            )
            self.stats["ffuf_paths"] = (
                f"Auto-skipped ({len(alive_urls)} hosts > threshold {self.args.fuzz_threshold})"
            )
            return

        wordlist = self.args.wordlist or _default_wordlist()
        if not wordlist or not Path(wordlist).exists():
            console.print("[warn][ ! ] No wordlist found for ffuf. Skipping stage.[/warn]")
            self.stats["ffuf_paths"] = "Skipped/No wordlist"
            return

        unique_targets: dict[str, str] = {}
        for url in alive_urls:
            host = urlparse(url).netloc or url
            if host not in unique_targets:
                unique_targets[host] = url

        ffuf_lock  = threading.Lock()
        ffuf_state = {"urls": [], "total_findings": 0}

        workers = min(4, len(unique_targets))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._run_single_ffuf, host, url, wordlist, ffuf_lock, ffuf_state)
                for host, url in unique_targets.items()
            ]
            for fut in as_completed(futures):
                pass

        ffuf_master = self.layout.recon / "ffuf_urls.txt"
        ffuf_master.write_text("\n".join(ffuf_state["urls"]), encoding="utf-8")
        self.stats["ffuf_paths"] = ffuf_state["total_findings"]
        console.print(f"[success][ ✔ ] ffuf completed. {ffuf_state['total_findings']} paths found.[/success]")

    def _run_katana(self) -> None:
        console.print("[info] [→] Katana crawler starting ...[/info]")
        cmd = ["katana", "-list", str(self.layout.alive), "-silent", "-d", "5", "-o", str(self.layout.katana_out)]
        run_cmd(cmd, label="katana")

    def _fetch_single_wayback(self, sub: str) -> list[str]:
        """Helper to run waybackurls securely without any blocking hazards using atomic process tracking."""
        cmd = ["waybackurls", sub]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="ignore", timeout=120)
            if res.stdout:
                return [line.strip() for line in res.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            console.print(f"[warn]  [ ! ] waybackurls timed out (120s limit) for subdomain: {sub}[/warn]")
        except Exception:
            pass
        return []

    def _run_waybackurls(self) -> None:
        console.print("[info]  [→] Waybackurls starting …[/info]")
        subdomains = sorted(list(set(read_lines(self.layout.subdomains))))
        urls: list[str] = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._fetch_single_wayback, sub): sub for sub in subdomains}
            for fut in as_completed(futures):
                try:
                    urls.extend(fut.result())
                except Exception as exc:
                    sub = futures[fut]
                    console.print(f"[warn]  [ ! ] Waybackurls failed for {sub}: {exc}[/warn]")

        self.layout.wayback_out.write_text("\n".join(u for u in urls if u.strip()), encoding="utf-8")

    def step_crawl(self) -> None:
        console.print(Panel("[+] Crawling endpoints (Katana + Waybackurls)", style="step", expand=False))
        if not read_lines(self.layout.alive):
            console.print("[warn][ ! ] No alive URLs. Skipping crawl.[/warn]")
            return

        with ThreadPoolExecutor(max_workers=2) as ex:
            futures = {
                ex.submit(self._run_katana):      "katana",
                ex.submit(self._run_waybackurls): "waybackurls",
            }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    fut.result()
                    console.print(f"[success]  [ ✔ ] {name} done.[/success]")
                except Exception as exc:
                    console.print(f"[error]  [ ✘ ] {name} error: {exc}[/error]")

        all_urls: set[str] = set()
        for src in [self.layout.katana_out, self.layout.wayback_out, self.layout.recon / "ffuf_urls.txt"]:
            all_urls.update(read_lines(src))

        self.layout.all_urls.write_text("\n".join(sorted(all_urls)), encoding="utf-8")
        self.stats["crawled_urls"] = len(all_urls)
        console.print(f"[success][ ✔ ] {len(all_urls)} total endpoints collected.[/success]")

    def step_filter_params(self) -> None:
        console.print(Panel("[+] Deduplication (uro) + Pattern filtering (gf)", style="step", expand=False))
        all_urls = read_lines(self.layout.all_urls)
        if not all_urls:
            console.print("[warn][ ! ] No URLs to filter. Skipping.[/warn]")
            return

        uro_input = "\n".join(all_urls)
        result = run_cmd(["uro"], stdin_data=uro_input, capture=True, label="uro")
        
        if result.returncode != 0:
            console.print("[warn][ ! ] uro tool failed during filtering process. Falling back to un-deduplicated URL mapping.[/warn]")
            deduped = uro_input
        else:
            deduped = result.stdout or uro_input          
            
        self.layout.uro_out.write_text(deduped, encoding="utf-8")

        deduped_lines = [l for l in deduped.splitlines() if l.strip()]
        self.stats["deduped_urls"] = len(deduped_lines)
        console.print(f"  [dim]uro: {len(all_urls)} → {len(deduped_lines)} unique URLs[/dim]")

        gf_sqli = run_cmd(["gf", "sqli"], stdin_data=deduped, capture=True, label="gf:sqli")
        sqli_lines = [l for l in (gf_sqli.stdout or "").splitlines() if l.strip()]

        gf_xss = run_cmd(["gf", "xss"], stdin_data=deduped, capture=True, label="gf:xss")
        xss_lines = [l for l in (gf_xss.stdout or "").splitlines() if l.strip()]

        def filter_unique_structures(url_list):
            seen = set()
            clean = []
            for u in url_list:
                try:
                    p = urlparse(u)
                    keys = tuple(sorted(parse_qs(p.query).keys()))
                    struct = (p.netloc, p.path, keys)
                    if struct not in seen:
                        seen.add(struct)
                        clean.append(u)
                except Exception:
                    continue
            return clean

        unique_sqli = filter_unique_structures(sqli_lines)
        unique_xss  = filter_unique_structures(xss_lines)

        self.layout.sqli_urls.write_text("\n".join(unique_sqli), encoding="utf-8")
        self.stats["sqli_urls"] = len(unique_sqli)
        self.layout.xss_urls.write_text("\n".join(unique_xss), encoding="utf-8")
        self.stats["xss_urls"] = len(unique_xss)

        console.print(f"[success][ ✔ ] gf: {len(unique_sqli)} SQLi candidates, {len(unique_xss)} XSS candidates.[/success]")

    def step_nuclei(self) -> None:
        console.print(Panel("[+] Vulnerability scanning with Nuclei (from HTTPX)", style="step", expand=False))

        alive_hosts = read_lines(self.layout.alive)
        if not alive_hosts:
            console.print("[warn][ ! ] No alive hosts for Nuclei. Skipping.[/warn]")
            self.stats["nuclei_findings"] = 0
            return

        limit = self.args.nuclei_limit

        if len(alive_hosts) > limit:
            console.print(
                f"[warn][ ! ] {len(alive_hosts)} alive hosts found — "
                f"limiting Nuclei to first {limit}. "
                f"Use --nuclei-limit to adjust.[/warn]"
            )
            nuclei_input = self.layout.recon / "nuclei_input.txt"
            nuclei_input.write_text("\n".join(alive_hosts[:limit]), encoding="utf-8")
            scan_file  = nuclei_input
            host_count = limit
        else:
            scan_file  = self.layout.alive
            host_count = len(alive_hosts)

        concurrency = min(30, max(10, host_count))
        rate_limit  = min(300, max(self.args.rate_limit, concurrency * 5))

        console.print(
            f"[info] [→] Scanning {host_count} hosts | "
            f"-c {concurrency} | -rl {rate_limit} req/s[/info]"
        )

        result = run_cmd([
            "nuclei",
            "-l",        str(scan_file),
            "-severity", "critical,high,medium",
            "-c",        str(concurrency),
            "-rl",       str(rate_limit),
            "-timeout",  "10",
            "-retries",  "1",
            "-silent",
            "-o",        str(self.layout.nuclei_out),
        ], label="nuclei")

        if result.returncode not in (0, 1):
            stderr_preview = (result.stderr or "")[:300].strip()
            console.print(
                f"[error][ ✘ ] Nuclei exited with code {result.returncode}.[/error]\n"
                f"[dim]   stderr: {stderr_preview or 'none'}[/dim]"
            )

        count = len(read_lines(self.layout.nuclei_out))
        self.stats["nuclei_findings"] = count
        console.print(f"[success][ ✔ ] Nuclei complete. {count} finding(s).[/success]")

    def step_sqlmap(self) -> None:
        if self.args.skip_exploit:
            self.stats["sqlmap_findings"] = "Skipped"
            return

        console.print(Panel("[+] SQLi Exploitation with sqlmap", style="step", expand=False))
        sqli_urls = read_lines(self.layout.sqli_urls)
        if not sqli_urls:
            console.print("[warn][ ! ] No SQLi candidates. Skipping sqlmap.[/warn]")
            self.stats["sqlmap_findings"] = 0
            return

        output_dir = self.layout.sqlmap_out
        cmd = [
            "sqlmap", "-m", str(self.layout.sqli_urls), "--batch", "--random-agent",
            "--level=1", "--risk=1", "--threads=10", "--smart", "--technique=BEUST",
            "--timeout=5", "--retries=1", "--output-dir", str(output_dir),
        ]
        run_cmd(cmd, label="sqlmap")
        vuln_dirs = [d for d in output_dir.iterdir() if d.is_dir()] if output_dir.exists() else []
        self.stats["sqlmap_findings"] = len(vuln_dirs)
        console.print(f"[success][ ✔ ] sqlmap: {len(vuln_dirs)} target(s) processed.[/success]")

    def step_xsstrike(self) -> None:
        if self.args.skip_exploit:
            self.stats["xss_findings"] = "Skipped"
            return

        console.print(Panel("[+] XSS Exploitation with XSStrike", style="step", expand=False))
        xss_urls = read_lines(self.layout.xss_urls)
        if not xss_urls:
            console.print("[warn][ ! ] No XSS candidates. Skipping XSStrike.[/warn]")
            self.stats["xss_findings"] = 0
            return

        results: list[str] = []
        # 🛠️ تصحيح منطق الـ fallback للـ binary الخاص بـ XSStrike لضمان التوافق المطلق مع جميع التوزيعات
        xss_bin = shutil.which("xsstrike") or shutil.which("XSStrike") or "xsstrike"

        for url in xss_urls[:self.args.xss_limit]:
            cmd = [xss_bin, "-u", url, "--skip", "-t", "10", "--file-log-level", "CRITICAL"]
            res = run_cmd(cmd, capture=True, label="xsstrike")
            
            out_str = (res.stdout or "") + "\n" + (res.stderr or "")
            if "XSS Found" in out_str or "Payload:" in out_str or "[+]" in out_str:
                results.append(f"[VULNERABLE] {url}\n{out_str}\n{'─'*60}\n")

        self.layout.xsstrike_out.write_text("\n".join(results), encoding="utf-8")
        self.stats["xss_findings"] = len(results)
        console.print(f"[success][ ✔ ] XSStrike: {len(results)} confirmed XSS finding(s).[/success]")

    def run(self) -> None:
        start = time.time()
        
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TaskProgressColumn(), TimeElapsedColumn(),
            console=console,
        ) as progress:
            self._current_progress = progress
            self._current_task = progress.add_task("[cyan]Pipeline running …", total=8)

            self.step_subfinder()
            self._advance_stage("Subdomain Enumeration")

            self.step_httpx()
            self._advance_stage("Alive Filtering")

            try:
                self.step_ffuf()
            except KeyboardInterrupt:
                console.print("\n[warn][ ! ] FFUF stage aborted by user. Jumping to Crawler...[/warn]")
                self.stats["ffuf_paths"] = "Aborted"
            self._advance_stage("Directory Brute-Force")

            self.step_crawl()
            self._advance_stage("Crawling Endpoints")

            self.step_filter_params()
            self._advance_stage("Parameter Filtering")

            self.step_nuclei()
            self._advance_stage("Nuclei Deep Scan")

            self.step_sqlmap()
            self._advance_stage("SQLi Exploitation")

            self.step_xsstrike()
            self._advance_stage("XSS Exploitation")
            
        elapsed = time.time() - start
        self.stats["elapsed"] = f"{elapsed:.1f}s"


# ─────────────────────────────────────────────────────────────────────────────
# 5.  Reporting
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(target: str, layout: OutputLayout, stats: dict, args: argparse.Namespace) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _section(title: str, path: Path, max_lines: int = 150) -> str:
        lines = read_lines(path)
        if not lines:
            return f"## {title}\n\n_No results._\n\n"
        snippet = "\n".join(lines[:max_lines])
        extra   = f"\n…and {len(lines) - max_lines} more." if len(lines) > max_lines else ""
        return f"## {title}\n\n```\n{snippet}{extra}\n```\n\n"

    md  = f"# 🦅 ALKASER-GG Bug Bounty Report\n\n"
    md += f"**Target:** `{target}`  \n"
    md += f"**Date:** {now}  \n"
    md += f"**Total time:** {stats.get('elapsed', '—')}  \n\n"
    md += "---\n\n"
    
    # 🛠️ إدراج الأرجومنتس النشطة والـ Flags المفعلة داخل التقرير كـ Best Practice للتوثيق
    md += "## 🔧 Scan Context & Flags\n\n"
    md += f"• **Fuzz Threshold:** `{args.fuzz_threshold}` | **Force Fuzz:** `{args.force_fuzz}`  \n"
    md += f"• **Nuclei Limit:** `{args.nuclei_limit}` | **Rate Limit Baseline:** `{args.rate_limit}` req/s  \n\n"
    md += "---\n\n"

    md += "## 📊 Summary\n\n"
    md += "| Stage | Count |\n|---|---|\n"
    md += f"| Subdomains discovered | {stats.get('subdomains', '—')} |\n"
    md += f"| Alive hosts           | {stats.get('alive', '—')} |\n"
    md += f"| ffuf paths found      | {stats.get('ffuf_paths', '—')} |\n"
    md += f"| Crawled endpoints     | {stats.get('crawled_urls', '—')} |\n"
    md += f"| Unique URLs (uro)     | {stats.get('deduped_urls', '—')} |\n"
    md += f"| SQLi candidates       | {stats.get('sqli_urls', '—')} |\n"
    md += f"| XSS candidates        | {stats.get('xss_urls', '—')} |\n"
    md += f"| Nuclei findings       | {stats.get('nuclei_findings', '—')} |\n"
    md += f"| sqlmap findings       | {stats.get('sqlmap_findings', '—')} |\n"
    md += f"| XSStrike findings     | {stats.get('xss_findings', '—')} |\n\n"
    md += "---\n\n"

    md += _section("Subdomains", layout.subdomains)
    md += _section("Alive Hosts", layout.alive)
    md += _section("Crawled URLs (sample)", layout.all_urls)
    md += _section("SQLi Candidate URLs", layout.sqli_urls)
    md += _section("XSS Candidate URLs", layout.xss_urls)
    md += _section("Nuclei Findings", layout.nuclei_out) 
    md += _section("XSStrike Findings", layout.xsstrike_out)
    md += "---\n\n"
    md += "_Generated by [ALKASER-GG](https://github.com/your-handle/alkaser)_\n"

    layout.report.write_text(md, encoding="utf-8")
    return md


def print_final_summary(layout: OutputLayout, stats: dict) -> None:
    table = Table("Metric", "Value", box=box.ROUNDED, title="[bold]Pipeline Summary[/bold]", border_style="cyan", show_lines=True)
    for k, v in stats.items():
        table.add_row(k.replace("_", " ").title(), str(v))
    console.print(table)
    console.print(f"\n[success][ ✔ ] Report saved → [bold]{layout.report}[/bold][/success]")


# ─────────────────────────────────────────────────────────────────────────────
# 6.  Notifications
# ─────────────────────────────────────────────────────────────────────────────

def _send_discord(webhook_url: str, message: str) -> None:
    try:
        resp = requests.post(webhook_url, json={"content": message[:2000]}, timeout=10)
        resp.raise_for_status()
        console.print("[success][ ✔ ] Discord notification sent.[/success]")
    except Exception as exc:
        console.print(f"[warn][ ! ] Discord notification failed: {exc}[/warn]")


def _send_telegram(bot_token: str, chat_id: str, message: str) -> None:
    try:
        url  = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        resp = requests.post(url, json={"chat_id": chat_id, "text": message[:4096], "parse_mode": "Markdown"}, timeout=10)
        resp.raise_for_status()
        console.print("[success][ ✔ ] Telegram notification sent.[/success]")
    except Exception as exc:
        console.print(f"[warn][ ! ] Telegram notification failed: {exc}[/warn]")


def send_notifications(target: str, stats: dict, args: argparse.Namespace) -> None:
    summary = f"🦅 *ALKASER Scan Complete* — `{target}`\n\n" + "\n".join(f"• {k.replace('_',' ').title()}: `{v}`" for k, v in stats.items())
    if args.discord:
        console.print("[info][ → ] Sending Discord notification …[/info]")
        _send_discord(args.discord, summary)
    if args.telegram_token and args.telegram_chat:
        console.print("[info][ → ] Sending Telegram notification …[/info]")
        _send_telegram(args.telegram_token, args.telegram_chat, summary)


# ─────────────────────────────────────────────────────────────────────────────
# 7.  Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _default_wordlist() -> Optional[str]:
    candidates = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        str(Path.home() / "tools" / "wordlists" / "common.txt"),
    ]
    for p in candidates:
        if Path(p).exists():
            return p
            
    console.print("[warn][ ! ] Wordlist not found in OS. FFUF stage will be skipped.[/warn]")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 8.  CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alkaser",
        description="ALKASER-GG — Bug Bounty Recon & Exploitation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples
        --------
          python main.py -d example.com
          python main.py -d example.com -w /usr/share/wordlists/common.txt
          python main.py -d example.com --discord https://discord.com/api/webhooks/...
          python main.py -d example.com --skip-missing --skip-exploit
        """),
    )
 
    parser.add_argument("-d", "--domain",    required=True,  help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist",  default=None,   help="Wordlist for ffuf (auto-detected if omitted)")
    parser.add_argument("-o", "--output",    default="results", help="Base output directory (default: results)")
 
    notify = parser.add_argument_group("notifications")
    notify.add_argument("--discord",         default=None,   help="Discord webhook URL")
    notify.add_argument("--telegram-token",  default=None,   help="Telegram bot token",   dest="telegram_token")
    notify.add_argument("--telegram-chat",   default=None,   help="Telegram chat ID",     dest="telegram_chat")
    notify.add_argument("--no-notify",       action="store_true", help="Disable notifications upon completion")
 
    ctrl = parser.add_argument_group("control flags")
    ctrl.add_argument("--skip-missing",  action="store_true", help="Continue even if some tools are missing")
    ctrl.add_argument("--skip-exploit",  action="store_true", help="Skip sqlmap and XSStrike stages")
    ctrl.add_argument("--skip-fuzz",     action="store_true", help="Skip FFUF Directory Brute-force stage")
    ctrl.add_argument("--xss-limit",     type=int, default=20, help="Max XSS URLs to pass to XSStrike (default: 20)")
    
    # 1. إضافة الـ CLI Arguments الجديدة للتحكم بالـ Threshold والـ Limits بالكامل
    ctrl.add_argument("--fuzz-threshold", type=int, default=20, help="Auto-skip ffuf if alive hosts exceed this number (default: 20)")
    ctrl.add_argument("--force-fuzz",     action="store_true", help="Force ffuf even if alive hosts exceed --fuzz-threshold")
    ctrl.add_argument("--nuclei-limit",   type=int, default=75, help="Max hosts to pass to Nuclei (default: 75)")
 
    probe = parser.add_argument_group("probing options")
    probe.add_argument("--threads",    type=int, default=30,       help="Number of threads for httpx (default: 30)")
    probe.add_argument("--rate-limit", type=int, default=50,       help="Maximum requests per second (default: 50)")
    probe.add_argument("--timeout",    type=int, default=3,        help="Timeout in seconds for httpx (default: 3)")
    probe.add_argument("--ports",      type=str, default="80,443", help="Ports to scan (default: 80,443)")
 
    return parser
 
 
# ─────────────────────────────────────────────────────────────────────────────
# 9.  Entry point
# ─────────────────────────────────────────────────────────────────────────────
 
def main() -> None:
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()
 
    target = args.domain.lower().strip()
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    if not target:
        console.print("[error][ ✘ ] Invalid target domain specified.[/error]")
        sys.exit(1)
 
    ok = check_dependencies(skip_missing=args.skip_missing)
    if not ok:
        sys.exit(1)
 
    layout = OutputLayout(target=target, base=args.output)
    layout.create()
 
    pipeline = Pipeline(target=target, layout=layout, args=args)
    pipeline.run()
 
    console.print(Panel("[+] Generating Markdown report …", style="step", expand=False))
    generate_report(target, layout, pipeline.stats, args)
    print_final_summary(layout, pipeline.stats)
 
    if not args.no_notify:
        send_notifications(target, pipeline.stats, args)
 
    console.print("\n[bold green]  🦅  ALKASER finished successfully (GG).[/bold green]\n")
 
if __name__ == "__main__":
    main()
