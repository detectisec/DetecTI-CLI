"""Graph data builder for Cytoscape.js visualization."""

import sqlite3
from typing import Dict, List
from core.database.storage import DatabaseManager


class GraphBuilder:
    """Builds Cytoscape.js graph data from SQLite database."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def build_graph(self) -> Dict:
        """Build complete graph with nodes and edges for Cytoscape.js.
        
        Hierarchy: IP -> Domain/Subdomain -> Services -> Vulnerabilities
        """
        nodes = []
        edges = []
        
        with sqlite3.connect(self.db.db_path) as conn:
            # Build IP nodes first (root level)
            ip_nodes, ip_edges = self._build_ip_nodes(conn)
            nodes.extend(ip_nodes)
            edges.extend(ip_edges)
            
            # Build domain/subdomain nodes connected to IPs
            domain_nodes, domain_edges = self._build_domain_nodes(conn)
            nodes.extend(domain_nodes)
            edges.extend(domain_edges)
            
            # Build service nodes connected to IPs
            service_nodes, service_edges = self._build_service_nodes(conn)
            nodes.extend(service_nodes)
            edges.extend(service_edges)
            
            # Build vulnerability nodes connected to services
            vuln_nodes, vuln_edges = self._build_vulnerability_nodes(conn)
            nodes.extend(vuln_nodes)
            edges.extend(vuln_edges)
        
        return {
            "elements": {
                "nodes": nodes,
                "edges": edges
            }
        }
    
    def _build_domain_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build domain and subdomain nodes connected to IPs."""
        nodes = []
        edges = []
        
        # Get all subdomains with their IP connections
        cursor = conn.execute("""
            SELECT DISTINCT s.id, s.name, s.domain_id, d.name as domain_name,
                   si.ip_id, ip.ip
            FROM subdomains s
            JOIN domains d ON s.domain_id = d.id
            LEFT JOIN subdomain_ips si ON s.id = si.subdomain_id
            LEFT JOIN ip_addresses ip ON si.ip_id = ip.id
            ORDER BY s.name
        """)
        
        processed_subdomains = set()
        processed_domains = set()
        
        for row in cursor.fetchall():
            sub_id, sub_name, domain_id, domain_name, ip_id, ip_address = row
            
            # Add domain node if not already added
            if domain_id not in processed_domains:
                nodes.append({
                    "data": {
                        "id": f"dom_{domain_id}",
                        "label": domain_name,
                        "type": "domain",
                        "name": domain_name
                    }
                })
                processed_domains.add(domain_id)
            
            # Add subdomain node if not already added
            if sub_id not in processed_subdomains:
                nodes.append({
                    "data": {
                        "id": f"sub_{sub_id}",
                        "label": sub_name,
                        "type": "subdomain",
                        "name": sub_name
                    }
                })
                processed_subdomains.add(sub_id)
                
                # Connect subdomain to domain
                edges.append({
                    "data": {
                        "id": f"e_dom_sub_{domain_id}_{sub_id}",
                        "source": f"dom_{domain_id}",
                        "target": f"sub_{sub_id}",
                        "label": "HAS_SUBDOMAIN"
                    }
                })
            
            # Connect subdomain to IP if there's a resolution
            if ip_id and ip_address:
                edges.append({
                    "data": {
                        "id": f"e_ip_sub_{ip_id}_{sub_id}",
                        "source": f"ip_{ip_id}",
                        "target": f"sub_{sub_id}",
                        "label": "RESOLVES_TO"
                    }
                })
        
        return nodes, edges
    
    def _build_ip_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build IP address nodes."""
        nodes = []
        edges = []
        
        cursor = conn.execute("""
            SELECT id, ip, org, country, asn 
            FROM ip_addresses
        """)
        
        for ip_id, ip, org, country, asn in cursor.fetchall():
            label = ip
            if org:
                label += f"\n{org}"
            if country:
                label += f"\n{country}"
            
            nodes.append({
                "data": {
                    "id": f"ip_{ip_id}",
                    "label": label,
                    "type": "ip",
                    "ip": ip,
                    "org": org or "Unknown",
                    "country": country or "Unknown",
                    "asn": asn or "Unknown"
                }
            })
            
            # Note: Subdomain-IP connections are now handled in _build_domain_nodes
            # to maintain proper hierarchy: IP -> Subdomain
        
        return nodes, edges
    
    def _build_service_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build service/port nodes."""
        nodes = []
        edges = []
        
        cursor = conn.execute("""
            SELECT id, ip_id, port, protocol, service_name, product, version, ssl
            FROM services
        """)
        
        for service_id, ip_id, port, protocol, service_name, product, version, ssl in cursor.fetchall():
            # Build service label
            label = f"{port}/{protocol.upper()}"
            if service_name:
                label += f"\n{service_name}"
            if product:
                label += f"\n{product}"
                if version:
                    label += f" {version}"
            
            service_type = "https" if ssl else "http" if port in [80, 8080, 8000] else "service"
            
            nodes.append({
                "data": {
                    "id": f"srv_{service_id}",
                    "label": label,
                    "type": service_type,
                    "port": port,
                    "protocol": protocol,
                    "service": service_name or "unknown",
                    "product": product or "",
                    "version": version or "",
                    "ssl": bool(ssl)
                }
            })
            
            # Edge from IP to service
            edges.append({
                "data": {
                    "id": f"e_ip_srv_{ip_id}_{service_id}",
                    "source": f"ip_{ip_id}",
                    "target": f"srv_{service_id}",
                    "label": "EXPOSES"
                }
            })
        
        return nodes, edges
    
    def _build_vulnerability_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build vulnerability nodes with risk indicators and PoC information."""
        nodes = []
        edges = []
        
        try:
            cursor = conn.execute("""
                SELECT v.id, v.ip_id, v.service_id, v.cve_id, v.severity, v.cvss_score, 
                       v.epss_score, v.is_cisa_kev, v.description,
                       COUNT(e.id) as exploit_count
                FROM vulnerabilities v
                LEFT JOIN exploits e ON v.id = e.vulnerability_id
                GROUP BY v.id, v.ip_id, v.service_id, v.cve_id, v.severity, v.cvss_score, 
                         v.epss_score, v.is_cisa_kev, v.description
            """)
            
            for row in cursor.fetchall():
                vuln_id, ip_id, service_id, cve_id, severity, cvss_score, epss_score, is_cisa_kev, description, exploit_count = row
                
                # Build vulnerability label
                label = cve_id or "Unknown CVE"
                if cvss_score:
                    label += f"\nCVSS: {cvss_score}"
                if epss_score:
                    label += f"\nEPSS: {epss_score * 100:.1f}%"
                if exploit_count > 0:
                    label += f"\n{exploit_count} PoCs"
                
                # Determine risk level for styling
                risk_level = "low"
                if is_cisa_kev:
                    risk_level = "critical"
                elif epss_score and epss_score > 0.5:
                    risk_level = "high"
                elif severity in ["CRITICAL", "HIGH"]:
                    risk_level = "high" if severity == "HIGH" else "critical"
                elif severity == "MEDIUM":
                    risk_level = "medium"
                
                # Get exploit details for this vulnerability
                exploit_cursor = conn.execute("""
                    SELECT title, source, url, verified, author, date, exploit_type
                    FROM exploits WHERE vulnerability_id = ?
                """, (vuln_id,))
                
                exploits = []
                for exploit_row in exploit_cursor.fetchall():
                    exploits.append({
                        "title": exploit_row[0],
                        "source": exploit_row[1],
                        "url": exploit_row[2],
                        "verified": bool(exploit_row[3]),
                        "author": exploit_row[4],
                        "date": exploit_row[5],
                        "exploit_type": exploit_row[6]
                    })
                
                nodes.append({
                    "data": {
                        "id": f"vuln_{vuln_id}",
                        "label": label,
                        "type": "vulnerability",
                        "cve_id": cve_id or "Unknown",
                        "severity": severity or "UNKNOWN",
                        "cvss_score": cvss_score or 0,
                        "epss_score": epss_score or 0,
                        "is_cisa_kev": bool(is_cisa_kev),
                        "risk_level": risk_level,
                        "description": description or "",
                        "exploit_count": exploit_count,
                        "exploits": exploits,
                        "has_pocs": exploit_count > 0
                    }
                })
                
                # ALWAYS prioritize service-level connection if service_id exists
                if service_id:
                    edges.append({
                        "data": {
                            "id": f"e_srv_vuln_{service_id}_{vuln_id}",
                            "source": f"srv_{service_id}",
                            "target": f"vuln_{vuln_id}",
                            "label": "HAS_VULN"
                        }
                    })
                # Only connect directly to IP if no service association exists
                elif ip_id:
                    edges.append({
                        "data": {
                            "id": f"e_ip_vuln_{ip_id}_{vuln_id}",
                            "source": f"ip_{ip_id}",
                            "target": f"vuln_{vuln_id}",
                            "label": "HAS_VULN"
                        }
                    })
        except Exception as e:
            print(f"Error building vulnerability nodes: {e}")
        
        return nodes, edges
