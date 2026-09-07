"""CSV Reporter for tabular export."""

import csv
import io
from pathlib import Path
from core.models import ScanResult

class CSVReporter:
    """Exports ScanResult to CSV."""

    @staticmethod
    def generate(result: ScanResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "Target", "Type", "IP", "Hostnames", "Organization", "ASN", 
            "Port", "Protocol", "Service", "Product", "Version", 
            "CVE", "Severity", "CVSS", "EPSS", "CISA KEV", 
            "Vulnerability Name", "Sources"
        ])
        
        target = result.target

        # Process each host
        for host in result.hosts:
            ip = host.ip
            hostnames = ", ".join(host.hostnames) if host.hostnames else ""
            org = host.org or ""
            asn = host.asn or ""
            
            # Emit host baseline if no ports and no vulns
            if not host.ports and not host.vulnerabilities:
                writer.writerow([
                    target, "Host", ip, hostnames, org, asn,
                    "", "", "", "", "",
                    "", "", "", "", "",
                    "", host.source
                ])
                continue

            # Emit ports
            for port in host.ports:
                writer.writerow([
                    target, "Port", ip, hostnames, org, asn,
                    port.port, port.transport, port.service or "", port.product or "", port.version or "",
                    "", "", "", "", "",
                    "", port.source
                ])

            # Emit vulnerabilities
            for vuln in host.vulnerabilities:
                cisa_kev = "Yes" if vuln.in_cisa_kev else "No"
                vuln_name = vuln.cwe_name or vuln.description or ""
                # VulnerabilityData doesn't have 'source', we can use the host's source or just leave empty
                writer.writerow([
                    target, "Vulnerability", ip, hostnames, org, asn,
                    "", "", "", "", "",
                    vuln.cve_id, vuln.cvss_severity.value if vuln.cvss_severity else "", 
                    vuln.cvss_score or "", vuln.epss_score or "", cisa_kev,
                    vuln_name, "NVD/ThreatTrack"
                ])

        return output.getvalue()

    @classmethod
    def save(cls, result: ScanResult, output_path: Path | str) -> Path:
        """Save formatted CSV report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(result)
        path.write_text(content, encoding="utf-8")
        return path
