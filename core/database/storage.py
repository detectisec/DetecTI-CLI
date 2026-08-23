"""SQLite storage manager for DetecTI-CLI EASM data persistence."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from core.models import (
    CISAKEVData,
    EPSSData,
    ExploitData,
    Finding,
    FindingType,
    HostResult,
    PortData,
    ScanResult,
    SeverityLevel,
    VulnerabilityData,
)
from .schema import SCHEMA_SQL


class DatabaseManager:
    """Manages SQLite database operations for EASM scan results."""

    def __init__(self, db_path: Path):
        """Initialize database manager with path to SQLite file."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self) -> None:
        """Initialize database schema if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    def _get_or_create_domain(self, conn: sqlite3.Connection, domain_name: str) -> str:
        """Get existing domain ID or create new domain record."""
        cursor = conn.execute("SELECT id FROM domains WHERE name = ?", (domain_name,))
        row = cursor.fetchone()
        if row:
            return row[0]
        
        domain_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO domains (id, name) VALUES (?, ?)",
            (domain_id, domain_name)
        )
        return domain_id

    def _get_or_create_ip(self, conn: sqlite3.Connection, host: HostResult) -> str:
        """Get existing IP ID or create new IP record."""
        cursor = conn.execute("SELECT id FROM ip_addresses WHERE ip = ?", (host.ip,))
        row = cursor.fetchone()
        if row:
            # Update existing record with new metadata
            conn.execute("""
                UPDATE ip_addresses 
                SET asn = COALESCE(?, asn), 
                    org = COALESCE(?, org),
                    country = COALESCE(?, country),
                    city = COALESCE(?, city),
                    region_code = COALESCE(?, region_code)
                WHERE ip = ?
            """, (host.asn, host.org, host.country_name, host.city, host.region_code, host.ip))
            return row[0]
        
        ip_id = str(uuid.uuid4())
        conn.execute("""
            INSERT INTO ip_addresses (id, ip, asn, org, country, city, region_code)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip_id, host.ip, host.asn, host.org, host.country_name, host.city, host.region_code))
        return ip_id

    def _store_subdomains(self, conn: sqlite3.Connection, findings: List[Finding]) -> Dict[str, str]:
        """Store subdomain findings in database and return subdomain_name -> subdomain_id mapping."""
        subdomain_findings = [f for f in findings if f.type == FindingType.SUBDOMAIN]
        subdomain_map = {}
        
        for finding in subdomain_findings:
            # Extract domain from subdomain using tldextract (handles .com.br, .co.uk, .gov.br, etc.)
            subdomain = finding.value
            if '.' in subdomain:
                try:
                    import tldextract
                    ext = tldextract.extract(subdomain)
                    domain = ext.registered_domain if ext.registered_domain else '.'.join(subdomain.split('.')[-2:])
                except Exception:
                    parts = subdomain.split('.')
                    domain = '.'.join(parts[-2:]) if len(parts) >= 2 else subdomain
                
                domain_id = self._get_or_create_domain(conn, domain)
                
                # Check if subdomain already exists
                cursor = conn.execute(
                    "SELECT id FROM subdomains WHERE domain_id = ? AND name = ?",
                    (domain_id, subdomain)
                )
                row = cursor.fetchone()
                if row:
                    subdomain_map[subdomain] = row[0]
                else:
                    subdomain_id = str(uuid.uuid4())
                    conn.execute("""
                        INSERT INTO subdomains (id, domain_id, name)
                        VALUES (?, ?, ?)
                    """, (subdomain_id, domain_id, subdomain))
                    subdomain_map[subdomain] = subdomain_id
        
        return subdomain_map

    def _store_services(self, conn: sqlite3.Connection, ip_id: str, host: HostResult) -> Dict[str, str]:
        """Store services for a host and return service_id mapping."""
        service_ids = {}
        
        for port in host.ports:
            service_id = str(uuid.uuid4())
            sources_json = json.dumps(port.sources) if port.sources else None
            
            conn.execute("""
                INSERT INTO services (id, ip_id, port, protocol, service_name, product, version, banner, url, ssl, sources)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                service_id, ip_id, port.port, port.transport, port.service,
                port.product, port.version, port.banner, port.url, port.ssl, sources_json
            ))
            
            service_ids[f"{port.port}/{port.transport}"] = service_id
        
        return service_ids

    def _store_vulnerabilities(self, conn: sqlite3.Connection, ip_id: str, host: HostResult, service_ids: Dict[str, str]) -> None:
        """Store vulnerabilities for a host, linking to services when possible."""
        for vuln in host.vulnerabilities:
            vuln_id = str(uuid.uuid4())
            
            # Serialize CISA KEV data if present
            cisa_kev_json = None
            if vuln.cisa_kev:
                cisa_kev_json = json.dumps(vuln.cisa_kev.model_dump())
            
            # Get EPSS data
            epss_score = vuln.epss.epss_score if vuln.epss else None
            epss_percentile = vuln.epss.epss_percentile if vuln.epss else None
            
            # Try to associate vulnerability with a specific service
            # This creates the HOST -> Service -> Vulnerability relationship
            service_id = None
            
            # Look for service associations based on vulnerability metadata
            # This could be enhanced with more sophisticated matching logic
            if hasattr(vuln, 'metadata') and vuln.metadata:
                # Check if vulnerability metadata contains port information
                vuln_port = vuln.metadata.get('port')
                if vuln_port:
                    # Find matching service by port
                    for port_key, sid in service_ids.items():
                        if str(vuln_port) in port_key:
                            service_id = sid
                            break
            
            # If no specific service match, try to associate with common vulnerable services
            if not service_id and service_ids:
                # For web vulnerabilities, associate with HTTP/HTTPS services
                if any(keyword in (vuln.description or "").lower() for keyword in ["web", "http", "ssl", "tls", "apache", "nginx", "iis"]):
                    # Find HTTP/HTTPS service
                    for port_key, sid in service_ids.items():
                        if any(port in port_key for port in ["80/", "443/", "8080/", "8443/"]):
                            service_id = sid
                            break
                
                # For SSH vulnerabilities, associate with SSH service
                elif any(keyword in (vuln.description or "").lower() for keyword in ["ssh", "openssh"]):
                    for port_key, sid in service_ids.items():
                        if "22/" in port_key:
                            service_id = sid
                            break
                
                # For other cases, associate with the first available service if only one exists
                elif len(service_ids) == 1:
                    service_id = list(service_ids.values())[0]
            
            conn.execute("""
                INSERT INTO vulnerabilities (
                    id, ip_id, service_id, cve_id, severity, cvss_score, cvss_version, description,
                    cwe_id, cwe_name, epss_score, epss_percentile, is_cisa_kev, cisa_kev_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln_id, ip_id, service_id, vuln.cve_id, vuln.cvss_severity.value,
                vuln.cvss_score, vuln.cvss_version, vuln.description,
                vuln.cwe_id, vuln.cwe_name, epss_score, epss_percentile,
                vuln.in_cisa_kev, cisa_kev_json
            ))
            
            # Store exploits
            for exploit in vuln.exploits:
                exploit_id = str(uuid.uuid4())
                conn.execute("""
                    INSERT INTO exploits (id, vulnerability_id, title, source, url, verified, author, date, exploit_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    exploit_id, vuln_id, exploit.title, exploit.source, exploit.url,
                    exploit.verified, exploit.author, exploit.date, exploit.exploit_type
                ))

    def store_scan_result(self, result: ScanResult) -> None:
        """Store complete scan result in database."""
        with sqlite3.connect(self.db_path) as conn:
            # Store scan metadata
            modules_json = json.dumps(result.modules_run)
            conn.execute("""
                INSERT OR REPLACE INTO scan_results (
                    id, target, target_type, started_at, completed_at, elapsed_seconds,
                    modules_run, total_findings, total_hosts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id, result.target, result.target_type,
                result.started_at.isoformat(), 
                result.completed_at.isoformat() if result.completed_at else None,
                result.elapsed_seconds, modules_json, len(result.findings), len(result.hosts)
            ))
            
            # Store subdomain findings and get mapping
            subdomain_map = self._store_subdomains(conn, result.findings)
            
            # Store host data and create subdomain-IP mappings
            ip_map = {}  # hostname -> ip_id mapping
            for host in result.hosts:
                ip_id = self._get_or_create_ip(conn, host)
                ip_map[host.ip] = ip_id
                
                # Map hostnames to this IP
                for hostname in host.hostnames:
                    if hostname in subdomain_map:
                        # Create subdomain-IP mapping
                        conn.execute("""
                            INSERT OR IGNORE INTO subdomain_ips (subdomain_id, ip_id)
                            VALUES (?, ?)
                        """, (subdomain_map[hostname], ip_id))
                
                service_ids = self._store_services(conn, ip_id, host)
                self._store_vulnerabilities(conn, ip_id, host, service_ids)
            
            conn.commit()

    def get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics for the database."""
        with sqlite3.connect(self.db_path) as conn:
            stats = {}
            
            try:
                # Get target from scan results
                cursor = conn.execute("SELECT target FROM scan_results ORDER BY created_at DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    stats['target'] = row[0]
            except Exception:
                stats['target'] = "Unknown"
            
            try:
                # Count domains and subdomains
                cursor = conn.execute("SELECT COUNT(*) FROM domains")
                stats['total_domains'] = cursor.fetchone()[0]
            except Exception:
                stats['total_domains'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM subdomains")
                stats['total_subdomains'] = cursor.fetchone()[0]
            except Exception:
                stats['total_subdomains'] = 0
            
            try:
                # Count IPs and services
                cursor = conn.execute("SELECT COUNT(*) FROM ip_addresses")
                stats['total_ips'] = cursor.fetchone()[0]
            except Exception:
                stats['total_ips'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM services")
                stats['open_services'] = cursor.fetchone()[0]
            except Exception:
                stats['open_services'] = 0
            
            try:
                # Count unique vulnerabilities by CVE ID
                cursor = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities")
                stats['total_vulnerabilities'] = cursor.fetchone()[0]
            except Exception:
                stats['total_vulnerabilities'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities WHERE is_cisa_kev = 1")
                stats['cisa_kev_count'] = cursor.fetchone()[0]
            except Exception:
                stats['cisa_kev_count'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities WHERE epss_score > 0.5")
                stats['high_epss_count'] = cursor.fetchone()[0]
            except Exception:
                stats['high_epss_count'] = 0
            
            return stats

    def reconstruct_scan_result(self) -> Optional[ScanResult]:
        """Reconstruct a complete ScanResult model from the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Fetch scan metadata
            scan_row = conn.execute("SELECT * FROM scan_results ORDER BY created_at DESC LIMIT 1").fetchone()
            if not scan_row:
                # Check if there are ip_addresses or domains to construct a basic scan
                first_ip = conn.execute("SELECT ip FROM ip_addresses LIMIT 1").fetchone()
                first_domain = conn.execute("SELECT name FROM domains LIMIT 1").fetchone()
                target = first_domain['name'] if first_domain else (first_ip['ip'] if first_ip else "unknown")
                target_type = "domain" if first_domain else "ip"
                scan_id = str(uuid.uuid4())
                started_at = datetime.now(timezone.utc)
                completed_at = started_at
                elapsed_seconds = 0.0
                modules_run = []
            else:
                target = scan_row['target']
                target_type = scan_row['target_type']
                scan_id = scan_row['id']
                try:
                    started_at = datetime.fromisoformat(scan_row['started_at'])
                except Exception:
                    started_at = datetime.now(timezone.utc)
                try:
                    completed_at = datetime.fromisoformat(scan_row['completed_at']) if scan_row['completed_at'] else None
                except Exception:
                    completed_at = None
                elapsed_seconds = scan_row['elapsed_seconds'] or 0.0
                try:
                    modules_run = json.loads(scan_row['modules_run']) if scan_row['modules_run'] else []
                except Exception:
                    modules_run = []

            # Fetch Hosts
            hosts = []
            ip_rows = conn.execute("SELECT * FROM ip_addresses").fetchall()
            for ip_row in ip_rows:
                ip_id = ip_row['id']
                ip_addr = ip_row['ip']

                # Hostnames
                hostnames = [r[0] for r in conn.execute("""
                    SELECT s.name FROM subdomains s
                    JOIN subdomain_ips si ON s.id = si.subdomain_id
                    WHERE si.ip_id = ?
                """, (ip_id,)).fetchall()]

                # Domains
                domains = [r[0] for r in conn.execute("""
                    SELECT DISTINCT d.name FROM domains d
                    JOIN subdomains s ON d.id = s.domain_id
                    JOIN subdomain_ips si ON s.id = si.subdomain_id
                    WHERE si.ip_id = ?
                """, (ip_id,)).fetchall()]

                # Services
                ports = []
                service_rows = conn.execute("SELECT * FROM services WHERE ip_id = ?", (ip_id,)).fetchall()
                for s_row in service_rows:
                    sources = []
                    if s_row['sources']:
                        try:
                            sources = json.loads(s_row['sources'])
                        except Exception:
                            sources = [s_row['sources']]
                    
                    ports.append(PortData(
                        port=s_row['port'],
                        transport=s_row['protocol'] or 'tcp',
                        service=s_row['service_name'],
                        product=s_row['product'],
                        version=s_row['version'],
                        banner=s_row['banner'],
                        url=s_row['url'],
                        ssl=bool(s_row['ssl']),
                        sources=sources
                    ))

                # Vulnerabilities
                vulns = []
                vuln_rows = conn.execute("SELECT * FROM vulnerabilities WHERE ip_id = ?", (ip_id,)).fetchall()
                for v_row in vuln_rows:
                    exploits = []
                    exp_rows = conn.execute("SELECT * FROM exploits WHERE vulnerability_id = ?", (v_row['id'],)).fetchall()
                    for e_row in exp_rows:
                        exploits.append(ExploitData(
                            title=e_row['title'],
                            source=e_row['source'],
                            url=e_row['url'],
                            verified=bool(e_row['verified']),
                            author=e_row['author'],
                            date=e_row['date'],
                            exploit_type=e_row['exploit_type']
                        ))

                    cisa_kev = None
                    if v_row['cisa_kev_data']:
                        try:
                            cisa_kev = CISAKEVData(**json.loads(v_row['cisa_kev_data']))
                        except Exception:
                            cisa_kev = CISAKEVData(in_cisa_kev=True)
                    elif v_row['is_cisa_kev']:
                        cisa_kev = CISAKEVData(in_cisa_kev=True)

                    epss = None
                    if v_row['epss_score'] is not None:
                        epss = EPSSData(
                            epss_score=v_row['epss_score'],
                            epss_percentile=v_row['epss_percentile'] or 0.0
                        )

                    sev_str = v_row['severity'] or "UNKNOWN"
                    sev = SeverityLevel(sev_str) if sev_str in SeverityLevel._value2member_map_ else SeverityLevel.UNKNOWN

                    vulns.append(VulnerabilityData(
                        cve_id=v_row['cve_id'],
                        cvss_score=v_row['cvss_score'],
                        cvss_version=v_row['cvss_version'],
                        cvss_severity=sev,
                        description=v_row['description'],
                        cwe_id=v_row['cwe_id'],
                        cwe_name=v_row['cwe_name'],
                        epss=epss,
                        cisa_kev=cisa_kev,
                        exploits=exploits
                    ))

                hosts.append(HostResult(
                    ip=ip_addr,
                    hostnames=hostnames,
                    domains=domains,
                    org=ip_row['org'],
                    asn=ip_row['asn'],
                    country_name=ip_row['country'],
                    city=ip_row['city'],
                    region_code=ip_row['region_code'],
                    ports=ports,
                    vulnerabilities=vulns
                ))

            # Findings
            findings = []
            for s_row in conn.execute("SELECT name FROM subdomains").fetchall():
                findings.append(Finding(
                    type=FindingType.SUBDOMAIN,
                    target=target,
                    value=s_row['name'],
                    source="recon"
                ))

            result = ScanResult(
                scan_id=scan_id,
                target=target,
                target_type=target_type,
                started_at=started_at,
                completed_at=completed_at,
                elapsed_seconds=elapsed_seconds,
                modules_run=modules_run,
                hosts=hosts,
                findings=findings
            )
            result.calculate_summary()
            return result

    @staticmethod
    def get_db_path_for_target(target: str, data_dir: Optional[Path] = None) -> Path:
        """Generate standardized database path for a target."""
        if data_dir is None:
            data_dir = Path.cwd() / "data" / "dbs"
        
        # Sanitize target name for filename
        safe_target = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)
        safe_target = safe_target[:50]  # Limit length
        
        return data_dir / f"{safe_target}.sqlite"

