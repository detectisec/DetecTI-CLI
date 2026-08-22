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
        
        Hierarchy: Target / Root Query (alvo.com) -> Subdomains & IPs -> Services -> Vulnerabilities
        """
        nodes = []
        edges = []
        
        with sqlite3.connect(self.db.db_path) as conn:
            # 1. Determine target root information (from scan_results)
            target_name = None
            target_type = None
            try:
                cursor = conn.execute("SELECT target, target_type FROM scan_results ORDER BY created_at DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    target_name, target_type = row
            except Exception:
                pass

            # 2. Build domain & subdomain nodes
            domain_nodes, domain_edges, root_target_node, subdomain_to_ips = self._build_domain_nodes(conn, target_name, target_type)
            if root_target_node:
                nodes.append(root_target_node)
            nodes.extend(domain_nodes)
            edges.extend(domain_edges)
            
            # 3. Build IP nodes connected to subdomains/domains (or target root)
            ip_nodes, ip_edges = self._build_ip_nodes(conn, subdomain_to_ips, root_target_node)
            nodes.extend(ip_nodes)
            edges.extend(ip_edges)
            
            # 4. Build service nodes connected to IPs
            service_nodes, service_edges = self._build_service_nodes(conn)
            nodes.extend(service_nodes)
            edges.extend(service_edges)
            
            # 5. Build vulnerability nodes connected to services/IPs
            vuln_nodes, vuln_edges = self._build_vulnerability_nodes(conn)
            nodes.extend(vuln_nodes)
            edges.extend(vuln_edges)
        
        return {
            "elements": {
                "nodes": nodes,
                "edges": edges
            }
        }
    
    def _build_domain_nodes(self, conn: sqlite3.Connection, target_name: str | None = None, target_type: str | None = None) -> tuple[List[Dict], List[Dict], Dict | None, Dict[str, set]]:
        """Build domain and subdomain nodes with hierarchy Root Domain -> Subdomains."""
        nodes = []
        edges = []
        root_target_node = None
        
        # Get all domains
        cursor = conn.execute("SELECT id, name FROM domains ORDER BY name")
        processed_domains = set()
        domains_list = cursor.fetchall()
        
        # 1. Create a dedicated Target Root Node for the query/target that generated the entire scan (Always anchors the graph)
        if target_name:
            targets_list = []
            # If target_type is file or list, retrieve the exact targets from the input file on disk
            if target_type == "file" or "file:" in str(target_name).lower():
                from pathlib import Path
                clean_path = str(target_name).replace("file:", "").strip()
                file_obj = Path(clean_path)
                if not file_obj.is_absolute():
                    # Check current directory or relative
                    if not file_obj.exists():
                        candidate = Path.cwd() / clean_path
                        if candidate.exists():
                            file_obj = candidate
                
                if file_obj.exists() and file_obj.is_file():
                    try:
                        targets_list = [line.strip() for line in file_obj.read_text().splitlines() if line.strip() and not line.startswith("#")]
                    except Exception:
                        pass
                
                # Fallback if file was moved or not found on disk:
                if not targets_list:
                    cursor_ips = conn.execute("SELECT ip FROM ip_addresses ORDER BY ip")
                    file_ips = [r[0] for r in cursor_ips.fetchall()]
                    file_doms = [d[1] for d in domains_list]
                    targets_list = sorted(list(set(file_doms + file_ips)))

            root_target_node = {
                "data": {
                    "id": "target_root",
                    "label": target_name,
                    "type": "target",
                    "name": target_name,
                    "target_type": target_type or "query",
                    "targets_list": targets_list,
                    "is_root": True
                }
            }

        # 2. Add domain nodes (Domains discovered during the scan)
        for domain_id, domain_name in domains_list:
            is_main_domain = bool(target_name and (domain_name.lower() == target_name.lower() or target_name.lower().endswith(f".{domain_name.lower()}")))
            node_data = {
                "id": f"dom_{domain_id}",
                "label": domain_name,
                "type": "domain",
                "name": domain_name,
                "is_root": is_main_domain
            }
            nodes.append({"data": node_data})
            processed_domains.add(domain_id)

            # Connect Target Root -> Domain (Unless this domain itself is the root query node and matches exactly 1 domain)
            if root_target_node:
                # If target is a multi-target list, query, cidr, or has multiple domains/IPs, connect target_root -> domains
                edges.append({
                    "data": {
                        "id": f"e_target_dom_{domain_id}",
                        "source": "target_root",
                        "target": f"dom_{domain_id}",
                        "label": "MATCHES_DOMAIN"
                    }
                })
        
        # Get all subdomains with their domain mappings and IP connections
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
        subdomain_to_ips = {}
        subdomain_records = []
        
        for row in cursor.fetchall():
            sub_id, sub_name, domain_id, domain_name, ip_id, ip_address = row
            
            # Add subdomain node if not already added
            if sub_id not in processed_subdomains:
                nodes.append({
                    "data": {
                        "id": f"sub_{sub_id}",
                        "label": sub_name,
                        "type": "subdomain",
                        "name": sub_name,
                        "domain_id": domain_id,
                        "domain_name": domain_name
                    }
                })
                processed_subdomains.add(sub_id)
                subdomain_records.append((sub_id, sub_name, domain_id, domain_name))
            
            # Keep track of Subdomain -> IP relationships
            if ip_id and ip_address:
                if sub_id not in subdomain_to_ips:
                    subdomain_to_ips[sub_id] = set()
                subdomain_to_ips[sub_id].add(ip_id)
        
        # Subdomains that don't have IP mappings yet
        cursor = conn.execute("""
            SELECT s.id, s.name, s.domain_id, d.name as domain_name
            FROM subdomains s
            JOIN domains d ON s.domain_id = d.id
            WHERE s.id NOT IN (
                SELECT DISTINCT subdomain_id FROM subdomain_ips WHERE subdomain_id IS NOT NULL
            )
            ORDER BY s.name
        """)
        
        for sub_id, sub_name, domain_id, domain_name in cursor.fetchall():
            if sub_id not in processed_subdomains:
                nodes.append({
                    "data": {
                        "id": f"sub_{sub_id}",
                        "label": sub_name,
                        "type": "subdomain",
                        "name": sub_name,
                        "domain_id": domain_id,
                        "domain_name": domain_name
                    }
                })
                processed_subdomains.add(sub_id)
                subdomain_records.append((sub_id, sub_name, domain_id, domain_name))

        # 3. Build Multi-Level FQDN Tree Hierarchy
        # Map all known domain and subdomain names to their node IDs
        fqdn_to_node_id = {}
        for domain_id, domain_name in domains_list:
            fqdn_to_node_id[domain_name.lower()] = f"dom_{domain_id}"
        for sub_id, sub_name, domain_id, domain_name in subdomain_records:
            fqdn_to_node_id[sub_name.lower()] = f"sub_{sub_id}"

        # Connect each subdomain to its closest parent in the FQDN hierarchy
        for sub_id, sub_name, domain_id, domain_name in subdomain_records:
            sname_clean = sub_name.lower().strip()
            parts = sname_clean.split(".")
            parent_node_id = None

            # Look for closest parent by peeling off sub-labels from left to right
            # e.g., api.dev.example.com -> dev.example.com -> example.com
            for i in range(1, len(parts)):
                parent_candidate = ".".join(parts[i:])
                if parent_candidate in fqdn_to_node_id and fqdn_to_node_id[parent_candidate] != f"sub_{sub_id}":
                    parent_node_id = fqdn_to_node_id[parent_candidate]
                    break

            # Fallback to direct domain parent if no intermediate subdomain ancestor was found
            if not parent_node_id or parent_node_id == f"sub_{sub_id}":
                if domain_name.lower() in fqdn_to_node_id and fqdn_to_node_id[domain_name.lower()] != f"sub_{sub_id}":
                    parent_node_id = fqdn_to_node_id[domain_name.lower()]
                else:
                    parent_node_id = f"dom_{domain_id}"

            # Only append edge if source and target are distinct (no self-loops)
            if parent_node_id and parent_node_id != f"sub_{sub_id}":
                edges.append({
                    "data": {
                        "id": f"e_tree_{parent_node_id}_sub_{sub_id}",
                        "source": parent_node_id,
                        "target": f"sub_{sub_id}",
                        "label": "HAS_SUBDOMAIN"
                    }
                })
        
        return nodes, edges, root_target_node, subdomain_to_ips
    
    def _build_ip_nodes(self, conn: sqlite3.Connection, subdomain_to_ips: Dict[str, set], root_target_node: Dict | None = None) -> tuple[List[Dict], List[Dict]]:
        """Build IP address nodes connected to Subdomains/Domains or Root Target."""
        nodes = []
        edges = []
        
        cursor = conn.execute("""
            SELECT id, ip, org, country, asn 
            FROM ip_addresses
        """)
        
        connected_ips = set()
        
        for ip_id, ip, org, country, asn in cursor.fetchall():
            label = ip
            
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
        
        # Connect Subdomains -> IPs (RESOLVES_TO)
        for sub_id, ip_ids in subdomain_to_ips.items():
            for ip_id in ip_ids:
                edges.append({
                    "data": {
                        "id": f"e_sub_ip_{sub_id}_{ip_id}",
                        "source": f"sub_{sub_id}",
                        "target": f"ip_{ip_id}",
                        "label": "RESOLVES_TO"
                    }
                })
                connected_ips.add(ip_id)
        
        # For any orphaned IPs not linked via subdomains:
        cursor = conn.execute("SELECT id, ip, org FROM ip_addresses")
        orphaned_ips = []
        for ip_id, ip, org in cursor.fetchall():
            if ip_id not in connected_ips:
                orphaned_ips.append((ip_id, ip, org))
        
        if orphaned_ips:
            cursor_dom = conn.execute("SELECT id FROM domains LIMIT 1")
            dom_row = cursor_dom.fetchone()
            
            # When target_root is available (or no domains), connect orphaned/file-list IPs directly to target_root or Org clusters
            if root_target_node:
                # If there are no domains (e.g. scanning a file of IPs, CIDR, or direct IP query):
                # Group IPs by their Organization if available to provide clean hierarchy:
                # Target Root -> Org / Network -> IPs
                org_groups: Dict[str, List[int]] = {}
                for ip_id, ip, org in orphaned_ips:
                    clean_org = (org or "").strip()
                    if clean_org and clean_org.lower() != "unknown":
                        org_groups.setdefault(clean_org, []).append(ip_id)
                    else:
                        org_groups.setdefault("Other Networks", []).append(ip_id)
                
                # If there's more than one distinct org, create Organization intermediate nodes
                # Or if there is at least one meaningful org name:
                meaningful_orgs = [o for o in org_groups.keys() if o != "Other Networks"]
                
                if meaningful_orgs and (len(org_groups) > 1 or len(orphaned_ips) > 1):
                    for org_name, ip_id_list in org_groups.items():
                        org_node_id = f"org_{abs(hash(org_name)) % 10000000}"
                        nodes.append({
                            "data": {
                                "id": org_node_id,
                                "label": org_name,
                                "type": "network",  # Organization / Network ASN cluster node
                                "name": org_name,
                                "is_root": False
                            }
                        })
                        # Connect target_root -> Org Node
                        edges.append({
                            "data": {
                                "id": f"e_root_{org_node_id}",
                                "source": "target_root",
                                "target": org_node_id,
                                "label": "MATCHES_DOMAIN"
                            }
                        })
                        # Connect Org Node -> IPs
                        for ip_id in ip_id_list:
                            edges.append({
                                "data": {
                                    "id": f"e_org_ip_{org_node_id}_{ip_id}",
                                    "source": org_node_id,
                                    "target": f"ip_{ip_id}",
                                    "label": "CONTAINS_IP"
                                }
                            })
                else:
                    # Direct connection target_root -> IP
                    for ip_id, ip, org in orphaned_ips:
                        edges.append({
                            "data": {
                                "id": f"e_root_ip_{ip_id}",
                                "source": "target_root",
                                "target": f"ip_{ip_id}",
                                "label": "CONTAINS_IP"
                            }
                        })
        
        return nodes, edges
    
    def _build_service_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build service/port nodes."""
        nodes = []
        edges = []
        
        cursor = conn.execute("""
            SELECT id, ip_id, port, protocol, service_name, product, version, banner, ssl, url
            FROM services
        """)
        
        for service_id, ip_id, port, protocol, service_name, product, version, banner, ssl, url in cursor.fetchall():
            # Build clean service label: e.g. 80/tcp, 443/tcp, 53/udp
            proto_str = (protocol or "tcp").lower()
            label = f"{port}/{proto_str}"
            
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
                    "banner": banner or "",
                    "ssl": bool(ssl),
                    "url": url or ""
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
                       COUNT(e.id) as exploit_count,
                       ip.id as resolved_ip_id, ip.ip, ip.org, ip.country, ip.asn,
                       s.port, s.protocol, s.service_name, s.product, s.version, s.url, s.ssl
                FROM vulnerabilities v
                LEFT JOIN exploits e ON v.id = e.vulnerability_id
                LEFT JOIN services s ON v.service_id = s.id
                LEFT JOIN ip_addresses ip ON COALESCE(v.ip_id, s.ip_id) = ip.id
                GROUP BY v.id, v.ip_id, v.service_id, v.cve_id, v.severity, v.cvss_score, 
                         v.epss_score, v.is_cisa_kev, v.description,
                         ip.id, ip.ip, ip.org, ip.country, ip.asn,
                         s.port, s.protocol, s.service_name, s.product, s.version, s.url, s.ssl
            """)
            
            for row in cursor.fetchall():
                (vuln_id, ip_id, service_id, cve_id, severity, cvss_score, epss_score, 
                 is_cisa_kev, description, exploit_count, resolved_ip_id, ip_address, 
                 org, country, asn, port, protocol, service_name, product, version, url, ssl) = row
                
                # Build vulnerability label - keep it simple with just CVE ID
                label = cve_id or "Unknown CVE"
                
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
                        "has_pocs": exploit_count > 0,
                        "ip": ip_address or "",
                        "ip_id": f"ip_{resolved_ip_id}" if resolved_ip_id else (f"ip_{ip_id}" if ip_id else None),
                        "org": org or "",
                        "country": country or "",
                        "asn": asn or "",
                        "service_id": f"srv_{service_id}" if service_id else None,
                        "port": port,
                        "protocol": protocol,
                        "service": service_name or "",
                        "product": product or "",
                        "version": version or "",
                        "url": url or "",
                        "ssl": bool(ssl) if ssl is not None else False
                    }
                })
                
                # ALWAYS prioritize service-level connection if service_id exists (Services -> Vulnerabilities)
                if service_id:
                    edges.append({
                        "data": {
                            "id": f"e_srv_vuln_{service_id}_{vuln_id}",
                            "source": f"srv_{service_id}",
                            "target": f"vuln_{vuln_id}",
                            "label": "HAS_VULN"
                        }
                    })
                # Only connect directly to IP if no service association exists (IP -> Vulnerabilities)
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
