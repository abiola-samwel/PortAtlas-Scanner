#!/usr/bin/env python3
import argparse
import json
import sys
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from backend.app.scanner import run_port_scan

console = Console()

# ==========================
# Banner
# ==========================
def print_banner():
    console.print(
        r"""
   ____            _        _        _        
  |  _ \ ___  _ __| |_ __ _| |_ __ _| |_ ___  
  | |_) / _ \| '__| __/ _` | __/ _` | __/ __| 
  |  __/ (_) | |  | || (_| | || (_| | |_\__ \ 
  |_|   \___/|_|   \__\__,_|\__\__,_|\__|___/ 
             [bold cyan]PortAtlas Scanner v1.0[/bold cyan]
        """,
        style="bold magenta",
    )
    console.print(
        "[yellow] ⚠ Legal Disclaimer:[/yellow]\n"
        "   Use PortAtlas only on systems you are authorized to scan.\n"
        "   Unauthorized access to networks or systems is illegal.\n",
        style="bold red",
    )
    console.print(
        "[green] 👉 Usage:[/green]\n"
        "   python test_scan.py <target> <ports> [--type syn|udp|tcp_connect]\n"
        "   [--banner] [--all] [--no-json] [--ignore-errors]\n",
        style="cyan",
    )
    console.print(
        f" Started on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        " Mode: Local Mode (API key not required)\n",
        style="bold yellow",
    )


# ==========================
# Run Scan
# ==========================
def run_scan(target, ports, scan_type, banner_grab, all_ports, no_json, ignore_errors):
    try:
        result = run_port_scan(target, ports, scan_type, banner_grab, all_ports)
    except Exception as e:
        if ignore_errors:
            console.print(f"[red]⚠ Error during scan: {e}[/red]")
            return None
        else:
            raise

    # CLI Table
    table = Table(title=f"[cyan]{scan_type.upper()} Scan Results for {target}[/cyan]")
    table.add_column("Port", justify="right", style="bold white")
    table.add_column("Status", justify="center", style="bold yellow")
    table.add_column("Service / Banner", justify="left", style="green")

    for entry in result["results"]:
        port = str(entry["port"])
        status = entry["status"]
        service = entry.get("service", "unknown")

        # Truncate long banners
        if service and len(service) > 60:
            service = service[:57] + "..."

        # Colorize statuses
        if status.startswith("open"):
            status_colored = f"[green]{status}[/green]"
        elif status.startswith("closed"):
            status_colored = f"[red]{status}[/red]"
        elif status.startswith("filtered"):
            status_colored = f"[yellow]{status}[/yellow]"
        else:
            status_colored = f"[magenta]{status}[/magenta]"

        table.add_row(port, status_colored, service)

    console.print(
        f"[bold cyan][{scan_type}][/bold cyan] Scanned {result['total_scanned']} ports → "
        f"[green]{result['open_count']} open[/green], "
        f"[red]{result['closed_count']} closed[/red], "
        f"[yellow]{result['filtered_count']} filtered[/yellow]\n"
    )
    console.print(table)

    if not no_json:
        console.print(json.dumps(result, indent=2))


# ==========================
# Main
# ==========================
def main():
    parser = argparse.ArgumentParser(description="PortAtlas CLI Scanner")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("ports", help="Comma-separated ports or range (e.g., 22,80,443 or 1-1000)")
    parser.add_argument("--type", default="tcp_connect", choices=["tcp_connect", "syn", "fin", "null", "udp"])
    parser.add_argument("--banner", action="store_true", help="Enable banner grabbing / service detection")
    parser.add_argument("--all", action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--no-json", action="store_true", help="Disable JSON output")
    parser.add_argument("--ignore-errors", action="store_true", help="Ignore errors during scanning")

    args = parser.parse_args()

    print_banner()

    # Parse ports
    port_list = []
    if args.all:
        port_list = list(range(1, 65536))
    elif "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        port_list = list(range(start, end + 1))
    else:
        port_list = [int(p) for p in args.ports.split(",")]

    run_scan(
        args.target,
        port_list,
        args.type,
        args.banner,
        args.all,
        args.no_json,
        args.ignore_errors,
    )


if __name__ == "__main__":
    main()
