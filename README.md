# havenshield-threat-detectors
HavenShield Threat Detectors - Learn to identify phishing, malware, and social engineering attacks through interactive gameplay. Available on web, iOS, and Android.
pip install psutil rich
#!/usr/bin/env python3
"""
HavenShield Threat Detector
Basic local system monitoring & heuristic threat detection tool.
For educational / defensive / home-lab use only.
"""

import time
import socket
import psutil
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

console = Console()

# ── Branding ──────────────────────────────────────────────────────────────
BANNER = r"""
╦ ╦╔═╗╦  ╦╔═╗╔╗╔╔═╗╦ ╦╦╔═╗╦  ╔╦╗
╠═╣╠═╣╚╗╔╝║╣ ║║║╚═╗╠═╣║║╣ ║   ║║
╩ ╩╩ ╩ ╚╝ ╚═╝╝╚╝╚═╝╩ ╩╩╚═╝╩═╝ ╩╝
        Threat Detector v0.1
"""

# Very basic heuristic list (expand this for your own lab)
SUSPICIOUS_NAMES = {
    "mimikatz", "procdump", "psexec", "cobalt", "beacon",
    "meterpreter", "powershell_ise", "nc.exe", "ncat",
    "empire", "covenant", "sliver", "havoc"
}

def get_banner():
    return Panel(
        Text(BANNER, style="bold green"),
        title="[bold gold1]HavenShield Cybersecurity[/]",
        border_style="green",
        subtitle="Defensive Monitoring • Ethical Use Only"
    )

def get_system_snapshot():
    """Return current high-level system stats."""
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    boot = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M")
    return {
        "cpu": cpu,
        "mem_percent": mem.percent,
        "mem_used_gb": round(mem.used / (1024**3), 2),
        "mem_total_gb": round(mem.total / (1024**3), 2),
        "boot": boot,
        "hostname": socket.gethostname()
    }

def get_suspicious_processes():
    """Scan running processes for basic heuristics."""
    findings = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "create_time"]):
        try:
            info = proc.info
            name = (info["name"] or "").lower()
            cpu = info["cpu_percent"] or 0.0
            mem = info["memory_percent"] or 0.0

            # Heuristic 1: known suspicious names
            for bad in SUSPICIOUS_NAMES:
                if bad in name:
                    findings.append({
                        "pid": info["pid"],
                        "name": info["name"],
                        "user": info["username"],
                        "cpu": cpu,
                        "mem": mem,
                        "reason": f"Name match: '{bad}'"
                    })
                    break

            # Heuristic 2: high resource usage (tunable)
            if cpu > 70 or mem > 40:
                findings.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "user": info["username"],
                    "cpu": cpu,
                    "mem": mem,
                    "reason": "High resource usage"
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings

def get_network_connections(limit=15):
    """Return established / listening connections."""
    conns = []
    for c in psutil.net_connections(kind="inet"):
        if c.status in ("ESTABLISHED", "LISTEN") and c.raddr:
            try:
                proc = psutil.Process(c.pid) if c.pid else None
                name = proc.name() if proc else "—"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "—"
            conns.append({
                "pid": c.pid or "—",
                "process": name,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—",
                "status": c.status
            })
    return conns[:limit]

def render_dashboard(findings, conns, stats):
    """Build the live dashboard layout."""
    # System panel
    sys_table = Table(show_header=False, box=None, padding=(0, 2))
    sys_table.add_row("Hostname", stats["hostname"])
    sys_table.add_row("Boot time", stats["boot"])
    sys_table.add_row("CPU", f"{stats['cpu']}%")
    sys_table.add_row("Memory", f"{stats['mem_percent']}%  ({stats['mem_used_gb']} / {stats['mem_total_gb']} GB)")

    # Findings table
    find_table = Table(title="[bold red]Potential Findings[/]", expand=True)
    find_table.add_column("PID", style="cyan", width=8)
    find_table.add_column("Process", style="white")
    find_table.add_column("User", style="green")
    find_table.add_column("CPU%", justify="right")
    find_table.add_column("MEM%", justify="right")
    find_table.add_column("Reason", style="yellow")

    if findings:
        for f in findings:
            find_table.add_row(
                str(f["pid"]),
                f["name"] or "—",
                f["user"] or "—",
                f"{f['cpu']:.1f}",
                f"{f['mem']:.1f}",
                f["reason"]
            )
    else:
        find_table.add_row("—", "No high-priority findings", "—", "—", "—", "—")

    # Network table
    net_table = Table(title="[bold blue]Active Network Connections[/]", expand=True)
    net_table.add_column("PID", style="cyan", width=8)
    net_table.add_column("Process")
    net_table.add_column("Local")
    net_table.add_column("Remote")
    net_table.add_column("Status")

    for c in conns:
        net_table.add_row(
            str(c["pid"]),
            c["process"],
            c["laddr"],
            c["raddr"],
            c["status"]
        )

    layout = Table.grid(expand=True)
    layout.add_row(get_banner())
    layout.add_row(Panel(sys_table, title="[bold]System Snapshot[/]", border_style="bright_blue"))
    layout.add_row(find_table)
    layout.add_row(net_table)
    layout.add_row(
        Panel(
            f"[dim]Last refresh: {datetime.now().strftime('%H:%M:%S')}  |  Press Ctrl+C to exit[/]",
            border_style="dim"
        )
    )
    return layout

def run_once():
    """Single scan mode."""
    console.clear()
    console.print(get_banner())
    console.print("\n[bold]Running single scan...[/]\n")

    stats = get_system_snapshot()
    findings = get_suspicious_processes()
    conns = get_network_connections()

    console.print(render_dashboard(findings, conns, stats))

def run_live(interval=3):
    """Continuous live monitoring mode."""
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            stats = get_system_snapshot()
            findings = get_suspicious_processes()
            conns = get_network_connections()
            live.update(render_dashboard(findings, conns, stats))
            time.sleep(interval)

def main():
    console.clear()
    console.print(get_banner())
    console.print("\n[bold cyan]Mode selection[/]")
    console.print("  1. Single scan")
    console.print("  2. Live monitoring (recommended)")
    console.print("  3. Exit\n")

    choice = console.input("[bold]Select option [1/2/3]: [/]").strip()

    if choice == "1":
        run_once()
    elif choice == "2":
        console.print("\n[green]Starting live monitor... (Ctrl+C to stop)[/]\n")
        try:
            run_live(interval=2.5)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Monitor stopped. Stay safe.[/]")
    else:
        console.print("[dim]Exiting. HavenShield out.[/]")

if __name__ == "__main__":
    main()
python haven_shield_threat_detector.py
pip install psutil rich yara-python
# Debian/Ubuntu
sudo apt install libyara-dev

# Fedora
sudo dnf install yara-devel
haven_shield_threat_detector/
├── haven_shield_threat_detector.py
└── rules/
    ├── mimikatz.yar
    ├── cobalt_strike.yar
    ├── powershell_suspicious.yar
    └── generic_malware.yar
rule Mimikatz_Strings
{
    meta:
        description = "Detects common Mimikatz strings"
        author = "HavenShield"
        severity = "high"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "mimikatz" ascii wide nocase
        $s3 = "privilege::debug" ascii wide nocase
        $s4 = "crypto::capi" ascii wide nocase
        $s5 = "lsadump::sam" ascii wide nocase
    condition:
        2 of them
}
rule CobaltStrike_Beacon
{
    meta:
        description = "Common Cobalt Strike beacon indicators"
        author = "HavenShield"
        severity = "critical"
    strings:
        $s1 = "beacon.dll" ascii wide nocase
        $s2 = "%s as %s\\%s: %d" ascii
        $s3 = "beacon.x64.dll" ascii wide
        $s4 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B F9 }
    condition:
        any of them
}rule Suspicious_PowerShell
{
    meta:
        description = "Detects common malicious PowerShell patterns"
        author = "HavenShield"
        severity = "medium"
    strings:
        $s1 = "IEX" ascii wide nocase
        $s2 = "Invoke-Expression" ascii wide nocase
        $s3 = "-EncodedCommand" ascii wide nocase
        $s4 = "FromBase64String" ascii wide nocase
        $s5 = "DownloadString" ascii wide nocase
        $s6 = "Net.WebClient" ascii wide nocase
        $s7 = "bypass" ascii wide nocase
    condition:
        3 of them
}rule Generic_Suspicious
{
    meta:
        description = "Generic high-entropy / suspicious indicators"
        author = "HavenShield"
        severity = "low"
    strings:
        $s1 = "This program cannot be run in DOS mode" ascii
        $s2 = { 4D 5A }  // MZ header
        $s3 = "cmd.exe /c" ascii wide nocase
        $s4 = "powershell -w hidden" ascii wide nocase
    condition:
        any of them
}#!/usr/bin/env python3
"""
HavenShield Threat Detector v0.2
Local monitoring + YARA rule scanning (files + process memory)
"""

import os
import time
import socket
import psutil
import yara
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt

console = Console()

BANNER = r"""
╦ ╦╔═╗╦  ╦╔═╗╔╗╔╔═╗╦ ╦╦╔═╗╦  ╔╦╗
╠═╣╠═╣╚╗╔╝║╣ ║║║╚═╗╠═╣║║╣ ║   ║║
╩ ╩╩ ╩ ╚╝ ╚═╝╝╚╝╚═╝╩ ╩╩╚═╝╩═╝ ╩╝
   Threat Detector v0.2 + YARA
"""

SUSPICIOUS_NAMES = {
    "mimikatz", "procdump", "psexec", "cobalt", "beacon",
    "meterpreter", "nc.exe", "ncat", "empire", "covenant",
    "sliver", "havoc", "rubeus", "sharpview"
}

RULES_DIR = Path("rules")


def get_banner():
    return Panel(
        Text(BANNER, style="bold green"),
        title="[bold gold1]HavenShield Cybersecurity[/]",
        border_style="green",
        subtitle="Defensive Monitoring • YARA Enabled"
    )


def load_yara_rules():
    """Load all .yar / .yara files from rules/ directory."""
    if not RULES_DIR.exists():
        console.print("[yellow]No rules/ directory found. Creating sample structure...[/]")
        RULES_DIR.mkdir(exist_ok=True)
        return None

    rule_files = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
    if not rule_files:
        console.print("[yellow]No YARA rule files found in rules/[/]")
        return None

    try:
        # Compile all rules into one ruleset
        filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
        rules = yara.compile(filepaths=filepaths)
        console.print(f"[green]Loaded {len(rule_files)} YARA rule file(s)[/]")
        return rules
    except yara.SyntaxError as e:
        console.print(f"[red]YARA syntax error: {e}[/]")
        return None
    except Exception as e:
        console.print(f"[red]Failed to load YARA rules: {e}[/]")
        return None


def scan_file_with_yara(rules, filepath):
    """Scan a single file and return matches."""
    try:
        matches = rules.match(filepath)
        results = []
        for m in matches:
            results.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "meta": dict(m.meta),
                "strings": [(s[1], s[0], s[2][:80]) for s in m.strings]  # identifier, offset, data
            })
        return results
    except Exception as e:
        return [{"error": str(e)}]


def scan_directory_yara(rules, path, recursive=True):
    """Scan a directory for YARA matches."""
    path = Path(path)
    if not path.exists():
        console.print(f"[red]Path does not exist: {path}[/]")
        return []

    findings = []
    files = path.rglob("*") if recursive else path.glob("*")

    for f in files:
        if f.is_file() and f.stat().st_size < 50 * 1024 * 1024:  # skip >50MB
            matches = scan_file_with_yara(rules, str(f))
            if matches and not any("error" in m for m in matches):
                findings.append({
                    "path": str(f),
                    "matches": matches
                })
    return findings


def scan_process_memory_yara(rules, pid):
    """Attempt to scan process memory with YARA (platform dependent)."""
    try:
        matches = rules.match(pid=pid)
        results = []
        for m in matches:
            results.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "meta": dict(m.meta)
            })
        return results
    except Exception:
        # Memory scanning is not always supported or requires elevated privileges
        return []


def get_suspicious_processes():
    findings = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            name = (info["name"] or "").lower()
            cpu = info["cpu_percent"] or 0.0
            mem = info["memory_percent"] or 0.0

            for bad in SUSPICIOUS_NAMES:
                if bad in name:
                    findings.append({
                        "pid": info["pid"],
                        "name": info["name"],
                        "user": info["username"],
                        "cpu": cpu,
                        "mem": mem,
                        "reason": f"Name match: '{bad}'"
                    })
                    break

            if cpu > 70 or mem > 40:
                findings.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "user": info["username"],
                    "cpu": cpu,
                    "mem": mem,
                    "reason": "High resource usage"
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def get_network_connections(limit=12):
    conns = []
    for c in psutil.net_connections(kind="inet"):
        if c.status in ("ESTABLISHED", "LISTEN") and c.raddr:
            try:
                proc = psutil.Process(c.pid) if c.pid else None
                name = proc.name() if proc else "—"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "—"
            conns.append({
                "pid": c.pid or "—",
                "process": name,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—",
                "status": c.status
            })
    return conns[:limit]


def get_system_snapshot():
    cpu = psutil.cpu_percent(interval=0.4)
    mem = psutil.virtual_memory()
    return {
        "cpu": cpu,
        "mem_percent": mem.percent,
        "mem_used_gb": round(mem.used / (1024**3), 2),
        "mem_total_gb": round(mem.total / (1024**3), 2),
        "hostname": socket.gethostname(),
        "boot": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M")
    }


def render_dashboard(findings, conns, stats, yara_hits=None):
    sys_table = Table(show_header=False, box=None, padding=(0, 2))
    sys_table.add_row("Hostname", stats["hostname"])
    sys_table.add_row("Boot", stats["boot"])
    sys_table.add_row("CPU", f"{stats['cpu']}%")
    sys_table.add_row("Memory", f"{stats['mem_percent']}% ({stats['mem_used_gb']}/{stats['mem_total_gb']} GB)")

    find_table = Table(title="[bold red]Heuristic Findings[/]", expand=True)
    find_table.add_column("PID", style="cyan", width=8)
    find_table.add_column("Process")
    find_table.add_column("User", style="green")
    find_table.add_column("CPU%", justify="right")
    find_table.add_column("MEM%", justify="right")
    find_table.add_column("Reason", style="yellow")

    if findings:
        for f in findings[:10]:
            find_table.add_row(
                str(f["pid"]), f["name"] or "—", f["user"] or "—",
                f"{f['cpu']:.1f}", f"{f['mem']:.1f}", f["reason"]
            )
    else:
        find_table.add_row("—", "Clean", "—", "—", "—", "—")

    net_table = Table(title="[bold blue]Network Connections[/]", expand=True)
    net_table.add_column("PID", style="cyan", width=8)
    net_table.add_column("Process")
    net_table.add_column("Local")
    net_table.add_column("Remote")
    net_table.add_column("Status")
    for c in conns:
        net_table.add_row(str(c["pid"]), c["process"], c["laddr"], c["raddr"], c["status"])

    layout = Table.grid(expand=True)
    layout.add_row(get_banner())
    layout.add_row(Panel(sys_table, title="[bold]System[/]", border_style="bright_blue"))
    layout.add_row(find_table)
    layout.add_row(net_table)

    if yara_hits:
        yara_table = Table(title="[bold magenta]YARA Matches[/]", expand=True)
        yara_table.add_column("Target")
        yara_table.add_column("Rule", style="red")
        yara_table.add_column("Severity / Tags")
        for hit in yara_hits[:8]:
            for m in hit.get("matches", []):
                sev = m.get("meta", {}).get("severity", "n/a")
                tags = ", ".join(m.get("tags", [])) or "—"
                yara_table.add_row(hit.get("path", hit.get("pid", "?")), m["rule"], f"{sev} | {tags}")
        layout.add_row(yara_table)

    layout.add_row(Panel(f"[dim]{datetime.now().strftime('%H:%M:%S')}  |  Ctrl+C to stop[/]", border_style="dim"))
    return layout


def yara_file_scan_mode(rules):
    path = Prompt.ask("\n[bold]Path to scan[/]", default=".")
    recursive = Prompt.ask("Recursive? (y/n)", default="y").lower().startswith("y")

    console.print(f"\n[cyan]Scanning {path} ...[/]")
    hits = scan_directory_yara(rules, path, recursive=recursive)

    if not hits:
        console.print("[green]No YARA matches found.[/]")
        return

    console.print(f"\n[bold red]Found matches in {len(hits)} file(s):[/]\n")
    for hit in hits:
        console.print(f"[bold]{hit['path']}[/]")
        for m in hit["matches"]:
            console.print(f"  → Rule: [red]{m['rule']}[/]")
            if m.get("meta"):
                console.print(f"    Meta: {m['meta']}")
            if m.get("strings"):
                for s in m["strings"][:3]:
                    console.print(f"    String: {s}")
        console.print()


def yara_process_scan_mode(rules):
    console.print("\n[cyan]Scanning running processes with YARA (may require elevated privileges)...[/]")
    hits = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            matches = scan_process_memory_yara(rules, proc.info["pid"])
            if matches:
                hits.append({
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "matches": matches
                })
        except Exception:
            continue

    if not hits:
        console.print("[green]No process memory matches found (or insufficient privileges).[/]")
        return

    for hit in hits:
        console.print(f"[bold]PID {hit['pid']} ({hit['name']})[/]")
        for m in hit["matches"]:
            console.print(f"  → [red]{m['rule']}[/]  tags={m.get('tags')}")


def run_live(rules=None, interval=2.5):
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            stats = get_system_snapshot()
            findings = get_suspicious_processes()
            conns = get_network_connections()
            live.update(render_dashboard(findings, conns, stats))
            time.sleep(interval)


def main():
    console.clear()
    console.print(get_banner())

    rules = load_yara_rules()

    while True:
        console.print("\n[bold cyan]HavenShield Threat Detector[/]")
        console.print("  1. Live system monitor")
        console.print("  2. YARA file / directory scan")
        console.print("  3. YARA process memory scan")
        console.print("  4. Exit\n")

        choice = Prompt.ask("Select", choices=["1", "2", "3", "4"], default="1")

        if choice == "1":
            console.print("\n[green]Starting live monitor (Ctrl+C to return to menu)...[/]\n")
            try:
                run_live(rules)
            except KeyboardInterrupt:
                console.print("\n[yellow]Returned to menu.[/]")
        elif choice == "2":
            if rules:
                yara_file_scan_mode(rules)
            else:
                console.print("[red]No YARA rules loaded.[/]")
        elif choice == "3":
            if rules:
                yara_process_scan_mode(rules)
            else:
                console.print("[red]No YARA rules loaded.[/]")
        else:
            console.print("[dim]Stay safe. HavenShield out.[/]")
            break


if __name__ == "__main__":
    main()