"""Rich logger, console output formatters, and terminal UI utilities."""

from __future__ import annotations

import logging
import socket
from pathlib import Path
from typing import Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from core.models import Finding, FindingType, HostResult, ScanResult, SeverityLevel

# Custom Rich theme
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "highlight": "bold magenta",
    "muted": "dim white",
})

console = Console(theme=custom_theme)


def _read_banner_file() -> str:
    """Read the banner from the 'banner' file in the current directory or package."""
    candidate_paths = [
        Path.cwd() / "banner",
        Path.cwd() / "detecti-cli" / "banner",
        Path.cwd() / "threattrack" / "banner",
        Path(__file__).resolve().parent / "banner",
        Path(__file__).resolve().parent.parent / "banner",
        Path(__file__).resolve().parent.parent.parent / "banner",
    ]
    for p in candidate_paths:
        if p.is_file():
            try:
                content = p.read_text(encoding="utf-8").rstrip()
                if content:
                    return content
            except Exception:
                pass
    return "DetecTI-CLI v2.0 - Cyber Lead Intelligence Engine\nExternal Attack Surface Management & Threat Intelligence CLI\nPowered by DetecTI Security"


def print_banner() -> None:
    """Print the DetecTI-CLI ASCII logo banner directly from the 'banner' file."""
    banner_content = _read_banner_file()
    console.print(f"[bold cyan]{banner_content}[/bold cyan]\n", highlight=False)


def print_section_header(title: str) -> None:
    """Print a clean section divider."""
    console.print(f"\n[bold cyan]━━━ [white]{title}[/white] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")


def print_info(message: str) -> None:
    """Print standard informational message."""
    console.print(f" [info][*][/info] {message}")


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f" [success][+][/success] {message}")


def print_warning(message: str) -> None:
    """Print warning message."""
    console.print(f" [warning][!][/warning] {message}")


def print_error(message: str) -> None:
    """Print error message."""
    console.print(f" [error][-][/error] {message}")


def render_host_dossier(host: HostResult) -> None:
    """Render a dedicated, structured dossier for a specific host."""
    loc_parts = [p for p in [host.country_name, host.city, host.region_code] if p]
    loc_str = " • ".join(loc_parts) if loc_parts else "N/A"
    org_str = host.org or host.isp or "N/A"
    asn_str = f" ({host.asn})" if host.asn else ""

    # Title with Host IP
    console.print(f"\n[bold green]┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold green] [bold white on blue] IP: {host.ip} [/bold white on blue] [bold green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓[/bold green]")
    console.print(f"  [cyan]Organization:[/cyan] {org_str}{asn_str}")
    console.print(f"  [cyan]Location:[/cyan]     {loc_str}")
    console.print(f"  [cyan]OS:[/cyan]           {host.os or 'N/A'}")
    if host.hostnames:
        console.print(f"  [cyan]Hostnames:[/cyan]    {', '.join(host.hostnames)}")
    if host.domains:
        console.print(f"  [cyan]Domains:[/cyan]      {', '.join(host.domains)}")

    # 1. Ports Table for this Host
    if host.ports:
        port_table = Table(
            show_header=True,
            header_style="bold magenta",
            show_lines=False,
            title="[bold green]Open Ports & Running Services[/bold green]",
            title_justify="left",
        )
        port_table.add_column("Port / Proto", style="bold cyan", width=14)
        port_table.add_column("Service / Product", style="white")
        port_table.add_column("Version", style="dim white", width=12)
        port_table.add_column("Endpoint URL", style="cyan")
        port_table.add_column("Source", style="green", width=18)

        for p in sorted(host.ports, key=lambda x: x.port):
            prod = p.product or p.service or "unknown"
            port_label = f"{p.port}/{p.transport.upper()}"
            src_str = p.source if p.sources else (host.source or "-")
            port_table.add_row(
                port_label,
                prod,
                p.version or "-",
                p.url or "-",
                src_str,
            )
        console.print(port_table)
    else:
        console.print("  [dim]No open ports identified for this host.[/dim]")

    # 2. Vulnerabilities Table for this Host
    if host.vulnerabilities:
        vuln_table = Table(
            show_header=True,
            header_style="bold red",
            show_lines=True,
            title=f"[bold red]Identified Vulnerabilities ({len(host.vulnerabilities)} CVEs on {host.ip})[/bold red]",
            title_justify="left",
        )
        vuln_table.add_column("CVE ID", style="bold white", width=16)
        vuln_table.add_column("CWE Name", style="magenta", min_width=22)
        vuln_table.add_column("CVSS Score", style="bold", width=14)
        vuln_table.add_column("EPSS Risk", style="yellow", width=14)
        vuln_table.add_column("CISA KEV", style="bold", width=12)
        vuln_table.add_column("Public Exploits & PoCs", style="white")

        for v in host.vulnerabilities:
            sev_str = v.cvss_severity.value if hasattr(v.cvss_severity, "value") else str(v.cvss_severity)
            sev_style = "critical" if sev_str == "CRITICAL" else "high" if sev_str == "HIGH" else "medium" if sev_str == "MEDIUM" else "low"
            cvss_cell = f"[{sev_style}]{v.cvss_score or 'N/A'} ({sev_str})[/{sev_style}]"

            epss_cell = f"{v.epss.epss_score * 100:.1f}%" if v.epss else "N/A"
            kev_cell = "[bold white on red] YES [/bold white on red]" if v.in_cisa_kev else "[dim]No[/dim]"

            exploits_info = []
            for exp in v.exploits:
                exploits_info.append(f"[bold red]{exp.source}:[/bold red] {exp.url}")

            exploit_cell = "\n".join(exploits_info) if exploits_info else "[dim]None found[/dim]"
            if v.cwe_name:
                cwe_items = [c.strip() for c in v.cwe_name.split(",") if c.strip()]
                cwe_cell = "\n".join(f"• {c}" for c in cwe_items) if len(cwe_items) > 1 else (cwe_items[0] if cwe_items else "N/A")
            elif v.cwe_id:
                cwe_cell = v.cwe_id
            else:
                cwe_cell = "[dim]N/A[/dim]"

            vuln_table.add_row(
                v.cve_id,
                cwe_cell,
                cvss_cell,
                epss_cell,
                kev_cell,
                exploit_cell,
            )
        console.print(vuln_table)
    else:
        console.print("  [dim]No CVEs identified on this host.[/dim]")

    console.print("[bold green]┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛[/bold green]")


def render_scan_output(result: ScanResult) -> None:
    """Render comprehensive scan output organized per host and domain."""
    # 1. Domain Surface Recon (Subdomains and Reverse WHOIS)
    subdomains = [f for f in result.findings if f.type == FindingType.SUBDOMAIN and not f.host_ip]
    assoc_domains = [f for f in result.findings if f.type == FindingType.ASSOCIATED_DOMAIN and not f.host_ip]

    if subdomains or assoc_domains:
        print_section_header("Domain Surface & Correlation")
        if subdomains:
            table = Table(title=f"Subdomains Discovered ({len(subdomains)})", show_header=True, header_style="bold cyan")
            table.add_column("Subdomain", style="bold white")
            table.add_column("Source", style="dim")
            for sf in subdomains:
                table.add_row(sf.value, sf.source)
            console.print(table)

        if assoc_domains:
            table = Table(title=f"Associated Domains / Reverse WHOIS ({len(assoc_domains)})", show_header=True, header_style="bold blue")
            table.add_column("Correlated Domain", style="bold white")
            table.add_column("Source", style="dim")
            for adf in assoc_domains:
                table.add_row(adf.value, adf.source)
            console.print(table)

    # 2. Host Dossiers
    if result.hosts:
        print_section_header(f"Host Intelligence ({len(result.hosts)} Hosts Scanned)")
        for host in result.hosts:
            render_host_dossier(host)
    elif result.target_type == "cve":
        # Standalone CVE scan
        print_section_header("Vulnerability Intelligence")
        vuln_findings = [f for f in result.findings if f.type == FindingType.VULNERABILITY and f.vulnerability]
        if vuln_findings:
            table = Table(title=f"CVE Threat Intelligence for {result.target}", show_header=True, header_style="bold magenta", show_lines=True)
            table.add_column("CVE ID", style="bold white", width=16)
            table.add_column("CWE Name", style="magenta", min_width=22)
            table.add_column("CVSS Score", style="bold", width=14)
            table.add_column("EPSS Score", style="yellow", width=14)
            table.add_column("CISA KEV", style="bold", width=12)
            table.add_column("Exploits & PoCs", style="white")

            for vf in vuln_findings:
                v = vf.vulnerability
                sev_str = v.cvss_severity.value if hasattr(v.cvss_severity, "value") else str(v.cvss_severity)
                sev_style = "critical" if sev_str == "CRITICAL" else "high" if sev_str == "HIGH" else "medium" if sev_str == "MEDIUM" else "low"
                cvss_cell = f"[{sev_style}]{v.cvss_score or 'N/A'} ({sev_str})[/{sev_style}]"
                epss_cell = f"{v.epss.epss_score * 100:.2f}%" if v.epss else "N/A"
                kev_cell = "[bold white on red] YES [/bold white on red]" if v.in_cisa_kev else "[dim]No[/dim]"

                exploits_info = [f"[bold red]{e.source}:[/bold red] {e.url}" for e in v.exploits]
                exploit_cell = "\n".join(exploits_info) if exploits_info else "[dim]None[/dim]"
                if v.cwe_name:
                    cwe_items = [c.strip() for c in v.cwe_name.split(",") if c.strip()]
                    cwe_cell = "\n".join(f"• {c}" for c in cwe_items) if len(cwe_items) > 1 else (cwe_items[0] if cwe_items else "N/A")
                elif v.cwe_id:
                    cwe_cell = v.cwe_id
                else:
                    cwe_cell = "[dim]N/A[/dim]"

                table.add_row(v.cve_id, cwe_cell, cvss_cell, epss_cell, kev_cell, exploit_cell)
            console.print(table)
    elif not subdomains and not assoc_domains:
        print_warning("No findings were discovered for the specified target and filters.")


def get_real_ip() -> str:
    """Get the primary local network IPv4 address of this machine (not 0.0.0.0)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # Connect to public DNS IP to determine local routing interface IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def render_summary_panel(summary: Any, elapsed: float) -> Panel:
    """Generate a clean executive summary panel."""
    lines = [
        f"[bold white]Total Findings:[/bold white] {summary.total_findings}",
        f"[bold green]Total Hosts Mapped:[/bold green] {summary.total_hosts_count}",
        f"[cyan]Subdomains Discovered:[/cyan] {summary.subdomains_count}",
        f"[blue]Associated Domains (Reverse WHOIS):[/blue] {summary.associated_domains_count}",
        f"[green]Open Ports / Services:[/green] {summary.open_ports_count}",
        f"[yellow]Vulnerabilities (CVEs):[/yellow] {summary.vulnerabilities_count} "
        f"([bold red]{summary.critical_vulns_count} Critical[/bold red], "
        f"[red]{summary.high_vulns_count} High[/red], "
        f"[yellow]{summary.medium_vulns_count} Medium[/yellow], "
        f"[blue]{summary.low_vulns_count} Low[/blue])",
        f"[bold white on red] CISA Known Exploited (KEV): [/bold white on red] {summary.cisa_kev_count}",
        f"[bold red]Exploits & PoCs Found:[/bold red] {summary.exploits_count}",
        f"[dim]Scan duration: {elapsed:.2f} seconds[/dim]",
    ]
    return Panel(
        "\n".join(lines),
        title="[bold green]Executive Scan Summary[/bold green]",
        border_style="green",
        expand=False,
    )


def render_executive_summary(result: ScanResult) -> None:
    """Render high-impact executive summary focusing on key metrics, perimeter stats, and actionable dashboard access."""
    is_cve = (result.target_type == "cve") or result.target.strip().upper().startswith("CVE-")

    # 1. Executive Summary Panel
    console.print("")
    console.print(render_summary_panel(result.summary, result.elapsed_seconds))

    # 2. Critical & High-Impact Vulnerabilities Table (Only for standalone CVE lookups)
    if is_cve:
        all_vulns: List[tuple[str, Any]] = []
        for host in result.hosts:
            for v in host.vulnerabilities:
                all_vulns.append((host.ip, v))

        for f in result.findings:
            if f.type == FindingType.VULNERABILITY and f.vulnerability and not f.host_ip:
                all_vulns.append((result.target, f.vulnerability))

        seen_keys = set()
        unique_vulns = []
        for h_ip, v in all_vulns:
            k = (h_ip, v.cve_id)
            if k not in seen_keys:
                seen_keys.add(k)
                unique_vulns.append((h_ip, v))

        if unique_vulns:
            print_section_header(f"CVE Threat Intelligence ({len(unique_vulns)} Vulnerability Details)")
            table = Table(show_header=True, header_style="bold red", show_lines=True)
            table.add_column("CVE ID", style="bold white", width=16)
            table.add_column("Affected Target", style="bold cyan", width=18)
            table.add_column("Severity / CVSS", style="bold", width=16)
            table.add_column("EPSS Risk", style="yellow", width=12)
            table.add_column("CISA KEV", style="bold", width=12)
            table.add_column("Public PoCs & Weaponization", style="white")

            for h_ip, v in unique_vulns:
                sev_str = v.cvss_severity.value if hasattr(v.cvss_severity, "value") else str(v.cvss_severity)
                sev_style = "critical" if "CRIT" in sev_str.upper() else "high" if "HIGH" in sev_str.upper() else "medium"
                cvss_cell = f"[{sev_style}]{v.cvss_score or 'N/A'} ({sev_str})[/{sev_style}]"
                epss_cell = f"{v.epss.epss_score * 100:.1f}%" if v.epss else "N/A"
                kev_cell = "[bold white on red] YES [/bold white on red]" if v.in_cisa_kev else "[dim]No[/dim]"

                exploits_info = [f"[bold red]{exp.source}:[/bold red] {exp.url}" for exp in v.exploits]
                exploit_cell = "\n".join(exploits_info) if exploits_info else "[dim]None[/dim]"

                table.add_row(v.cve_id, h_ip, cvss_cell, epss_cell, kev_cell, exploit_cell)

            console.print(table)

    # 3. Discovered Perimeter Highlights (For direct target scans)
    if not is_cve:
        subdomains = [f for f in result.findings if f.type == FindingType.SUBDOMAIN and not f.host_ip]
        assoc_domains = [f for f in result.findings if f.type == FindingType.ASSOCIATED_DOMAIN and not f.host_ip]
        if subdomains or assoc_domains:
            summary_parts = []
            if subdomains:
                summary_parts.append(f"[bold cyan]{len(subdomains)} Subdomains[/bold cyan] (via crt.sh / DNS)")
            if assoc_domains:
                summary_parts.append(f"[bold blue]{len(assoc_domains)} Associated Domains[/bold blue] (via Reverse WHOIS)")
            console.print(f"\n 🌐 [bold]Perimeter Intelligence:[/bold] {' • '.join(summary_parts)}")

        # 4. DetecTIHound Web Dashboard Quick Access Callout (Only for asset/perimeter scans)
        real_ip = get_real_ip()
        port = 8000
        console.print("")
        dashboard_box = [
            "[bold cyan]DetecTIHound — Interactive Attack Surface Graph[/bold cyan]",
            "Explore full relational topology, technical banners, and active scans:",
            f"  👉 [bold white]Local Access:[/bold white]   [bold underline cyan]http://localhost:{port}[/bold underline cyan]",
            f"  👉 [bold white]Network Access:[/bold white] [bold underline cyan]http://{real_ip}:{port}[/bold underline cyan]",
        ]
        console.print(Panel("\n".join(dashboard_box), border_style="cyan", expand=False))

