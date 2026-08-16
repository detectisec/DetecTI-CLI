"""Executive Markdown Reporter for DetecTI Scans."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Set
from core.models import FindingType, ScanResult, SeverityLevel


class MarkdownReporter:
    """Generates an executive, structured Markdown security intelligence report."""

    @classmethod
    def generate(cls, result: ScanResult) -> str:
        """Render complete Markdown document from ScanResult."""
        lines: List[str] = []

        # 1. Header
        lines.append(f"# DetecTI Cyber Lead Intelligence Report: `{result.target}`")
        lines.append("")
        lines.append(f"> **Scan ID:** `{result.scan_id}`  ")
        lines.append(f"> **Target Type:** `{result.target_type}`  ")
        lines.append(f"> **Execution Date:** {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        lines.append(f"> **Duration:** {result.elapsed_seconds:.2f} seconds  ")
        lines.append(f"> **Modules Active:** `{', '.join(result.modules_run)}`  ")
        lines.append("")

        # 2. Executive Summary Metrics
        summary = result.summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append("| Metric | Count | Details |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| **Total Findings** | `{summary.total_findings}` | Total assets, ports, and intelligence records |")
        lines.append(f"| **Total Hosts Mapped** | `{summary.total_hosts_count}` | Individual IP addresses analyzed |")
        lines.append(f"| **Subdomains Discovered** | `{summary.subdomains_count}` | Certificate Transparency & DNS enumeration |")
        lines.append(f"| **Associated Domains** | `{summary.associated_domains_count}` | Reverse WHOIS & Organization correlation |")
        lines.append(f"| **Open Ports & Services** | `{summary.open_ports_count}` | Exposed internet-facing services |")
        lines.append(f"| **Identified Vulnerabilities (CVEs)** | `{summary.vulnerabilities_count}` | Public CVE references |")
        lines.append(f"| 🚨 **CISA Known Exploited (KEV)** | `{summary.cisa_kev_count}` | **Confirmed actively exploited in the wild** |")
        lines.append(f"| 💥 **Public Exploits & PoCs** | `{summary.exploits_count}` | ExploitDB entries and GitHub PoCs |")
        lines.append("")

        # 3. Critical Threat Intelligence Alerts
        cisa_kev_vulns = []
        for h in result.hosts:
            for v in h.vulnerabilities:
                if v.in_cisa_kev:
                    cisa_kev_vulns.append((h.ip, v))
        for f in result.findings:
            if f.vulnerability and f.vulnerability.in_cisa_kev and not any(v.cve_id == f.vulnerability.cve_id for _, v in cisa_kev_vulns):
                cisa_kev_vulns.append((f.host_ip or result.target, f.vulnerability))

        if cisa_kev_vulns:
            lines.append("## 2. ⚠️ Critical Risk Highlights (CISA KEV)")
            lines.append("The following vulnerabilities are cataloged by CISA as actively exploited in cyberattacks:")
            lines.append("")
            for host_ip, v in cisa_kev_vulns:
                kev = v.cisa_kev
                lines.append(f"- **[{v.cve_id}](https://nvd.nist.gov/vuln/detail/{v.cve_id})** on `{host_ip}` - *{kev.vulnerability_name if kev else 'Exploited Vulnerability'}*")
                if kev and kev.date_added:
                    lines.append(f"  - Added to KEV: `{kev.date_added}` | Due Date: `{kev.due_date or 'N/A'}`")
                if kev and kev.required_action:
                    lines.append(f"  - Action: {kev.required_action}")
                if kev and kev.known_ransomware_campaign_use:
                    lines.append(f"  - Ransomware Usage: `{kev.known_ransomware_campaign_use}`")
            lines.append("")

        # 4. Domain & DNS Surface
        subdomains = [f for f in result.findings if f.type == FindingType.SUBDOMAIN and not f.host_ip]
        assoc_domains = [f for f in result.findings if f.type == FindingType.ASSOCIATED_DOMAIN and not f.host_ip]

        if subdomains or assoc_domains:
            lines.append("## 3. Domain Surface & Correlation")
            lines.append("")
            if subdomains:
                lines.append(f"### Subdomains ({len(subdomains)} identified)")
                lines.append("")
                lines.append("| Subdomain | Discovery Source |")
                lines.append("| :--- | :--- |")
                for sf in subdomains:
                    lines.append(f"| `{sf.value}` | {sf.source} |")
                lines.append("")

            if assoc_domains:
                lines.append(f"### Associated Domains / Reverse WHOIS ({len(assoc_domains)} identified)")
                lines.append("")
                lines.append("| Correlated Domain | Discovery Source |")
                lines.append("| :--- | :--- |")
                for adf in assoc_domains:
                    lines.append(f"| `{adf.value}` | {adf.source} |")
                lines.append("")

        # 5. Per-Host Dossiers & Infrastructure
        if result.hosts:
            lines.append("## 4. Host Intelligence & Vulnerability Dossiers")
            lines.append("")

            for host in result.hosts:
                loc_parts = [p for p in [host.country_name, host.city, host.region_code] if p]
                loc_str = ", ".join(loc_parts) if loc_parts else "N/A"
                org_str = f"{host.org or host.isp or 'N/A'}"
                if host.asn:
                    org_str += f" ({host.asn})"

                lines.append(f"### 🖥️ Host: `{host.ip}`")
                lines.append(f"- **Organization / ISP:** {org_str}")
                lines.append(f"- **Location:** {loc_str}")
                lines.append(f"- **Operating System:** {host.os or 'N/A'}")
                if host.hostnames:
                    lines.append(f"- **Hostnames:** `{', '.join(host.hostnames)}`")
                if host.domains:
                    lines.append(f"- **Domains:** `{', '.join(host.domains)}`")
                lines.append("")

                # Open Ports on this Host
                if host.ports:
                    lines.append("#### Exposed Ports & Services")
                    lines.append("")
                    lines.append("| Port / Proto | Service / Product | Version | Endpoint Link | Source |")
                    lines.append("| :---: | :--- | :---: | :--- | :--- |")
                    for p in sorted(host.ports, key=lambda x: x.port):
                        prod = p.product or p.service or "Unknown"
                        ver = p.version or "-"
                        link = f"[{p.url}]({p.url})" if p.url else "-"
                        src_str = p.source if p.sources else (host.source or "-")
                        lines.append(f"| `{p.port}/{p.transport.upper()}` | {prod} | {ver} | {link} | {src_str} |")
                    lines.append("")

                # Vulnerabilities specifically affecting this host
                if host.vulnerabilities:
                    lines.append(f"#### Vulnerabilities on `{host.ip}` ({len(host.vulnerabilities)} CVEs)")
                    lines.append("")
                    lines.append("| CVE ID | CWE Name | CVSS Score | Severity | EPSS Risk | CISA KEV | Exploits / PoCs |")
                    lines.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: |")

                    for v in host.vulnerabilities:
                        cvss_str = f"**{v.cvss_score}** (v{v.cvss_version})" if v.cvss_score else "N/A"
                        sev_val = v.cvss_severity.value if hasattr(v.cvss_severity, "value") else str(v.cvss_severity)
                        sev_badge = f"`{sev_val}`"
                        epss_str = f"{v.epss.epss_score * 100:.2f}% (p{v.epss.epss_percentile * 100:.0f})" if v.epss else "N/A"
                        kev_str = "🚨 **YES**" if v.in_cisa_kev else "No"
                        exp_count = f"**{len(v.exploits)} PoCs**" if v.exploits else "0"
                        cwe_str = v.cwe_name or v.cwe_id or "N/A"

                        lines.append(f"| [{v.cve_id}](https://nvd.nist.gov/vuln/detail/{v.cve_id}) | {cwe_str} | {cvss_str} | {sev_badge} | {epss_str} | {kev_str} | {exp_count} |")
                    lines.append("")

                    # Exploits for this host
                    host_exploits = []
                    for v in host.vulnerabilities:
                        for exp in v.exploits:
                            host_exploits.append((v.cve_id, exp))

                    if host_exploits:
                        lines.append(f"##### Exploits & PoCs for `{host.ip}`")
                        lines.append("")
                        lines.append("| CVE ID | Exploit / PoC Title | Source | URL Link |")
                        lines.append("| :--- | :--- | :--- | :--- |")
                        for cve, exp in host_exploits:
                            lines.append(f"| `{cve}` | {exp.title} | `{exp.source}` | [{exp.url}]({exp.url}) |")
                        lines.append("")
                else:
                    lines.append("*No CVEs identified on this host.*")
                    lines.append("")

                lines.append("---")
                lines.append("")

        elif result.target_type == "cve":
            # Standalone CVE scan
            vuln_findings = [f for f in result.findings if f.type == FindingType.VULNERABILITY and f.vulnerability]
            if vuln_findings:
                lines.append("## 4. Vulnerability & Threat Intelligence")
                lines.append("")
                lines.append("| CVE ID | CWE Name | CVSS Score | Severity | EPSS Risk | CISA KEV | Exploits / PoCs |")
                lines.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: |")
                for vf in vuln_findings:
                    v = vf.vulnerability
                    cvss_str = f"**{v.cvss_score}** (v{v.cvss_version})" if v.cvss_score else "N/A"
                    sev_val = v.cvss_severity.value if hasattr(v.cvss_severity, "value") else str(v.cvss_severity)
                    sev_badge = f"`{sev_val}`"
                    epss_str = f"{v.epss.epss_score * 100:.2f}%" if v.epss else "N/A"
                    kev_str = "🚨 **YES**" if v.in_cisa_kev else "No"
                    exp_count = f"**{len(v.exploits)} PoCs**" if v.exploits else "0"
                    cwe_str = v.cwe_name or v.cwe_id or "N/A"
                    lines.append(f"| [{v.cve_id}](https://nvd.nist.gov/vuln/detail/{v.cve_id}) | {cwe_str} | {cvss_str} | {sev_badge} | {epss_str} | {kev_str} | {exp_count} |")
                lines.append("")

        lines.append("---")
        lines.append("*Generated automatically by DetecTI-CLI v2.0 — Modern EASM & Threat Intelligence Engine.*")

        return "\n".join(lines)

    @classmethod
    def save(cls, result: ScanResult, output_path: Path | str) -> Path:
        """Save formatted Markdown report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(result)
        path.write_text(content, encoding="utf-8")
        return path
