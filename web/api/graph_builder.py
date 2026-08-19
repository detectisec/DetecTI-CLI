"""Graph data builder for Cytoscape.js visualization."""

import sqlite3
from typing import Dict, List
from core.database.storage import DatabaseManager


class GraphBuilder:
    """Builds Cytoscape.js graph data from SQLite database."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def build_graph(self) -> Dict:
        """Build complete graph with nodes and edges for Cytoscape.js."""
        nodes = []
        edges = []
        
        with sqlite3.connect(self.db.db_path) as conn:
            # Build domain nodes
            domain_nodes, domain_edges = self._build_domain_nodes(conn)
            nodes.extend(domain_nodes)
            edges.extend(domain_edges)
            
            # Build IP nodes and their connections
            ip_nodes, ip_edges = self._build_ip_nodes(conn)
            nodes.extend(ip_nodes)
            edges.extend(ip_edges)
            
            # Build service nodes
            service_nodes, service_edges = self._build_service_nodes(conn)
            nodes.extend(service_nodes)
            edges.extend(service_edges)
            
            # Build vulnerability nodes
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
        """Build domain and subdomain nodes with relationships."""
        nodes = []
        edges = []
        
        # Root domains
        cursor = conn.execute("SELECT id, name FROM domains")
        for domain_id, domain_name in cursor.fetchall():
            nodes.append({
                "data": {
                    "id": f"dom_{domain_id}",
                    "label": domain_name,
                    "type": "domain",
                    "name": domain_name
                }
            })
            
            # Subdomains for this domain
            sub_cursor = conn.execute(
                "SELECT id, name FROM subdomains WHERE domain_id = ?",
                (domain_id,)
            )
            for sub_id, sub_name in sub_cursor.fetchall():
                nodes.append({
                    "data": {
                        "id": f"sub_{sub_id}",
                        "label": sub_name,
                        "type": "subdomain",
                        "name": sub_name
                    }
                })
                
                # Edge from domain to subdomain
                edges.append({
                    "data": {
                        "id": f"e_dom_sub_{domain_id}_{sub_id}",
                        "source": f"dom_{domain_id}",
                        "target": f"sub_{sub_id}",
                        "label": "HAS_SUBDOMAIN"
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
            
            # Connect subdomains to IPs (DNS resolution)
            dns_cursor = conn.execute("""
                SELECT si.subdomain_id 
                FROM subdomain_ips si 
                WHERE si.ip_id = ?
            """, (ip_id,))
            
            for (subdomain_id,) in dns_cursor.fetchall():
                edges.append({
                    "data": {
                        "id": f"e_sub_ip_{subdomain_id}_{ip_id}",
                        "source": f"sub_{subdomain_id}",
                        "target": f"ip_{ip_id}",
                        "label": "RESOLVES_TO"
                    }
                })
        
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
        """Build vulnerability nodes with risk indicators."""
        nodes = []
        edges = []
        
        try:
            cursor = conn.execute("""
                SELECT id, ip_id, service_id, cve_id, severity, cvss_score, 
                       epss_score, is_cisa_kev, description
                FROM vulnerabilities
            """)
            
            for row in cursor.fetchall():
                vuln_id, ip_id, service_id, cve_id, severity, cvss_score, epss_score, is_cisa_kev, description = row
                
                # Build vulnerability label
                label = cve_id or "Unknown CVE"
                if cvss_score:
                    label += f"\nCVSS: {cvss_score}"
                if epss_score:
                    label += f"\nEPSS: {epss_score * 100:.1f}%"
                
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
                        "description": description or ""
                    }
                })
                
                # Edge from service to vulnerability (if service_id exists)
                if service_id:
                    edges.append({
                        "data": {
                            "id": f"e_srv_vuln_{service_id}_{vuln_id}",
                            "source": f"srv_{service_id}",
                            "target": f"vuln_{vuln_id}",
                            "label": "HAS_VULN"
                        }
                    })
                # Otherwise connect directly to IP
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
