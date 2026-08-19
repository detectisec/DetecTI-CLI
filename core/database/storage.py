"""SQLite storage manager for DetecTI-CLI EASM data persistence."""

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set

from core.models import (
    Finding,
    FindingType,
    HostResult,
    ScanResult,
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
            # Extract domain from subdomain
            subdomain = finding.value
            if '.' in subdomain:
                parts = subdomain.split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[-2:])  # Get root domain
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
                # Count vulnerabilities
                cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities")
                stats['total_vulnerabilities'] = cursor.fetchone()[0]
            except Exception:
                stats['total_vulnerabilities'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE is_cisa_kev = 1")
                stats['cisa_kev_count'] = cursor.fetchone()[0]
            except Exception:
                stats['cisa_kev_count'] = 0
            
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE epss_score > 0.5")
                stats['high_epss_count'] = cursor.fetchone()[0]
            except Exception:
                stats['high_epss_count'] = 0
            
            return stats

    @staticmethod
    def get_db_path_for_target(target: str, data_dir: Optional[Path] = None) -> Path:
        """Generate standardized database path for a target."""
        if data_dir is None:
            data_dir = Path.cwd() / "data" / "dbs"
        
        # Sanitize target name for filename
        safe_target = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)
        safe_target = safe_target[:50]  # Limit length
        
        return data_dir / f"{safe_target}.sqlite"
