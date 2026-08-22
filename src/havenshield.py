"""HavenShield core implementation.

Refactored from the top-level script with improvements:
- Proper cpu sampling for processes
- Deduplicate findings per PID with aggregated reasons
- Include LISTEN connections
- Argparse CLI
- Light logging and type hints
"""
from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional

import psutil
import socket
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

console = Console()

# Branding
BANNER = r"""
╦ ╦╔═╗╦  ╦╔═╗╔╗╔╔═╗╦ ╦╦╔═╗╦  ╔╦╗
╠═╣╠═╣╚╗╔╝║╣ ║║║╚═╗╠═╣║║╣ ║   ║║
╩ ╩╩ ╩ ╚╝ ╚═╝╝╚╝╚═╝╩ ╩╩╚═╝╩═╝ ╩╝
        Threat Detector v0.2
"""

SUSPICIOUS_NAMES = {
    "mimikatz",
    "procdump",
    "psexec",
    "cobalt",
    "beacon",
    "meterpreter",
    "powershell_ise",
    "nc.exe",
    "ncat",
    "empire",
    "covenant",
    "sliver",
    "havoc",
}

logger = logging.getLogger("havenshield")


def setup_logging(logfile: str = "havenshield.log") -> None:
    handler = logging.FileHandler(logfile)
    handler.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
    )
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def get_banner() -> Panel:
    return Panel(
        Text(BANNER, style="bold green"),
        title="[bold gold1]HavenShield Cybersecurity[/]",
        border_style="green",
        subtitle="Defensive Monitoring • Ethical Use Only",
    )


def get_system_snapshot() -> Dict[str, object]:
    """Return current high-level system stats."""
    # brief cpu sample for the system
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    boot = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M")
    return {
        "cpu": cpu,
        "mem_percent": mem.percent,
        "mem_used_gb": round(mem.used / (1024 ** 3), 2),
        "mem_total_gb": round(mem.total / (1024 ** 3), 2),
        "boot": boot,
        "hostname": socket.gethostname(),
    }


def _init_proc_cpu() -> None:
    """Warm up per-process cpu counters so subsequent cpu_percent calls are useful.

    This function calls cpu_percent(None) for currently running processes and
    sleeps briefly. It's a lightweight way to avoid seeing zeros on first read.
    """
    procs = list(psutil.process_iter())
    for p in procs:
        try:
            p.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # short sleep to allow counters to accumulate
    time.sleep(0.05)


def get_suspicious_processes(high_cpu: float = 70.0, high_mem: float = 40.0) -> List[Dict[str, object]]:
    """Scan running processes for basic heuristics and deduplicate findings.

    Returns a list of findings where each PID appears once and reasons are aggregated.
    """
    findings_map: Dict[int, Dict[str, object]] = {}

    _init_proc_cpu()

    for proc in psutil.process_iter(["pid", "name", "username", "create_time"]):
        try:
            info = proc.info
            pid = int(info.get("pid") or 0)
            name = (info.get("name") or "").lower()
            user = info.get("username")
            cpu = float(proc.cpu_percent(None) or 0.0)
            mem = float(proc.memory_percent() or 0.0)

            reasons: List[str] = []

            # Heuristic 1: known suspicious names
            for bad in SUSPICIOUS_NAMES:
                if bad in name:
                    reasons.append(f"Name match: '{bad}'")
                    break

            # Heuristic 2: high resource usage
            if cpu > high_cpu or mem > high_mem:
                reasons.append("High resource usage")

            if reasons:
                if pid in findings_map:
                    # append new reasons
                    existing = findings_map[pid]
                    existing_reasons = existing["reason"].split("; ")
                    for r in reasons:
                        if r not in existing_reasons:
                            existing_reasons.append(r)
                    existing["reason"] = "; ".join(existing_reasons)
                else:
                    findings_map[pid] = {
                        "pid": pid,
                        "name": info.get("name") or "—",
                        "user": user or "—",
                        "cpu": cpu,
                        "mem": mem,
                        "reason": "; ".join(reasons),
                    }

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # sort by cpu desc
    findings = sorted(findings_map.values(), key=lambda x: x["cpu"], reverse=True)
    return findings


def _format_addr(a: Optional[psutil._common.addr]) -> str:  # type: ignore[name-defined]
    if not a:
        return "—"
    try:
        ip = getattr(a, "ip", None) or str(a)
        port = getattr(a, "port", None)
        return f"{ip}:{port}" if port is not None else str(ip)
    except Exception:
        return str(a)


def get_network_connections(limit: int = 15) -> List[Dict[str, object]]:
    """Return established and listening connections formatted for display."""
    conns = []
    for c in psutil.net_connections(kind="inet"):
        # include ESTABLISHED and LISTEN statuses
        if c.status in ("ESTABLISHED", "LISTEN"):
            try:
                proc = psutil.Process(c.pid) if c.pid else None
                name = proc.name() if proc else "—"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "—"

            laddr = _format_addr(c.laddr)
            raddr = _format_addr(c.raddr)

            conns.append(
                {
                    "pid": c.pid or "—",
                    "process": name,
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": c.status,
                }
            )

    return conns[:limit]


def render_dashboard(findings: List[Dict[str, object]], conns: List[Dict[str, object]], stats: Dict[str, object]) -> Table:
    """Build the live dashboard layout."""
    # System panel
    sys_table = Table(show_header=False, box=None, padding=(0, 2))
    sys_table.add_row("Hostname", str(stats["hostname"]))
    sys_table.add_row("Boot time", str(stats["boot"]))
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
                f["reason"],
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
        net_table.add_row(str(c["pid"]), c["process"], c["laddr"], c["raddr"], c["status"])

    layout = Table.grid(expand=True)
    layout.add_row(get_banner())
    layout.add_row(Panel(sys_table, title="[bold]System Snapshot[/]", border_style="bright_blue"))
    layout.add_row(find_table)
    layout.add_row(net_table)
    layout.add_row(
        Panel(
            f"[dim]Last refresh: {datetime.now().strftime('%H:%M:%S')}  |  Press Ctrl+C to exit[/]",
            border_style="dim",
        )
    )
    return layout


def run_once() -> None:
    console.clear()
    console.print(get_banner())
    console.print("\n[bold]Running single scan...[/]\n")

    stats = get_system_snapshot()
    findings = get_suspicious_processes()
    conns = get_network_connections()

    console.print(render_dashboard(findings, conns, stats))


def run_live(interval: float = 3.0) -> None:
    with Live(console=console, refresh_per_second=1) as live:
        try:
            while True:
                stats = get_system_snapshot()
                findings = get_suspicious_processes()
                conns = get_network_connections()
                live.update(render_dashboard(findings, conns, stats))
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Live monitor stopped by user")
            console.print("\n[bold yellow]Monitor stopped. Stay safe.[/]")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="havenshield", description="HavenShield Threat Detector")
    p.add_argument("--mode", choices=("once", "live"), default="live", help="Operation mode")
    p.add_argument("--interval", type=float, default=2.5, help="Refresh interval for live mode")
    p.add_argument("--limit", type=int, default=15, help="Max network connections to show")
    p.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    return p


def main(argv: Optional[List[str]] = None) -> None:
    setup_logging()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        console.clear()
        console.print(get_banner())

    if args.mode == "once":
        run_once()
    else:
        console.print("\n[green]Starting live monitor... (Ctrl+C to stop)[/]\n")
        run_live(interval=args.interval)


if __name__ == "__main__":
    main()
