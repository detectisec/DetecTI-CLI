"""Graph data builder for Cytoscape.js visualization."""

import sqlite3
from typing import Dict, List, Optional, Set
from core.database.storage import DatabaseManager


class GraphBuilder:
    """Builds Cytoscape.js graph data from SQLite database."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def build_graph(self, active_targets: Optional[List[str]] = None) -> Dict:
        """Build complete graph with nodes and edges for Cytoscape.js.
        
        Host-Centric Architecture:
        - Target Root connects directly to Host IPs via CONTAINS_TARGET
        - Explicit FQDN targets connect to Target Root (CONTAINS_TARGET) and IP (RESOLVES_TO)
        - All enumerated domains/subdomains are embedded as rich metadata in target_root
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

            # 2. Build domain & subdomain nodes (only explicit targets spawned as graph nodes)
            domain_nodes, domain_edges, root_target_node, subdomain_to_ips, domain_to_ips = self._build_domain_nodes(
                conn, target_name, target_type, active_targets=active_targets
            )
            if root_target_node:
                nodes.append(root_target_node)
            nodes.extend(domain_nodes)
            edges.extend(domain_edges)
            
            # 3. Build IP nodes connected to target root
            spawned_fqdn_ids = {n["data"]["id"] for n in domain_nodes}
            ip_nodes, ip_edges = self._build_ip_nodes(
                conn,
                subdomain_to_ips,
                domain_to_ips,
                spawned_fqdn_ids=spawned_fqdn_ids,
                target_name=target_name,
                target_type=target_type,
                root_target_node=root_target_node
            )
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
    
    def _build_domain_nodes(
        self,
        conn: sqlite3.Connection,
        target_name: str | None = None,
        target_type: str | None = None,
        active_targets: Optional[List[str]] = None
    ) -> tuple[List[Dict], List[Dict], Dict | None, Dict[str, set], Dict[str, set]]:
        """Build domain and subdomain inventory and spawn nodes ONLY for explicit targets."""
        nodes = []
        edges = []
        root_target_node = None
        
        # Get all domains
        cursor = conn.execute("SELECT id, name FROM domains ORDER BY name")
        domains_list = cursor.fetchall()
        
        targets_list = []
        explicit_targets = set()
        if target_name:
            if target_type == "file":
                from pathlib import Path
                clean_path = str(target_name).strip()
                file_obj = Path(clean_path)
                if not file_obj.is_absolute() and not file_obj.exists():
                    candidate = Path.cwd() / clean_path
                    if candidate.exists():
                        file_obj = candidate
                
                if file_obj.exists() and file_obj.is_file():
                    try:
                        targets_list = [line.strip() for line in file_obj.read_text().splitlines() if line.strip() and not line.startswith("#")]
                    except Exception:
                        pass
                
                if not targets_list:
                    cursor_ips = conn.execute("SELECT ip FROM ip_addresses ORDER BY ip")
                    file_ips = [r[0] for r in cursor_ips.fetchall()]
                    file_doms = [d[1] for d in domains_list]
                    targets_list = sorted(list(set(file_doms + file_ips)))

            def _normalize_target_item(t: str) -> str:
                t = str(t).strip().lower()
                if t.startswith("http://"):
                    t = t[7:]
                elif t.startswith("https://"):
                    t = t[8:]
                if "/" in t:
                    t = t.split("/")[0]
                if ":" in t:
                    t = t.split(":")[0]
                return t

            explicit_targets = {_normalize_target_item(t) for t in targets_list if _normalize_target_item(t)}
            if active_targets:
                for at in active_targets:
                    norm = _normalize_target_item(at)
                    if norm:
                        explicit_targets.add(norm)

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

        # Query all subdomains and their resolved IPs
        cursor_subs = conn.execute("""
            SELECT s.id, s.name, s.domain_id, d.name as domain_name, si.ip_id, ip.ip
            FROM subdomains s
            JOIN domains d ON s.domain_id = d.id
            LEFT JOIN subdomain_ips si ON s.id = si.subdomain_id
            LEFT JOIN ip_addresses ip ON si.ip_id = ip.id
            ORDER BY s.name ASC
        """)
        
        subdomain_to_ips: Dict[str, set] = {}
        domain_to_ips: Dict[str, set] = {}
        subdomain_info_map: Dict[str, Dict] = {}
        
        for sub_id, sub_name, domain_id, domain_name, ip_id, ip_addr in cursor_subs.fetchall():
            is_apex = (sub_name.strip().lower() == domain_name.strip().lower())
            if ip_id:
                subdomain_to_ips.setdefault(sub_id, set()).add(ip_id)
                if is_apex:
                    domain_to_ips.setdefault(domain_id, set()).add(ip_id)

            if not is_apex:
                if sub_id not in subdomain_info_map:
                    subdomain_info_map[sub_id] = {
                        "id": sub_id,
                        "name": sub_name,
                        "domain_id": domain_id,
                        "domain_name": domain_name,
                        "ips": []
                    }
                if ip_addr and ip_addr not in subdomain_info_map[sub_id]["ips"]:
                    subdomain_info_map[sub_id]["ips"].append(ip_addr)

        all_domains = [{"id": d[0], "name": d[1]} for d in domains_list]
        all_subdomains = list(subdomain_info_map.values())

        # Embed complete DNS inventory inside target_root for instant Asset Inspector access
        if root_target_node:
            root_target_node["data"]["all_domains"] = all_domains
            root_target_node["data"]["all_subdomains"] = all_subdomains
            root_target_node["data"]["total_domains"] = len(all_domains)
            root_target_node["data"]["total_subdomains"] = len(all_subdomains)

        # 2. Spawn Graph Nodes ONLY for FQDNs that were explicitly marked / scanned as targets
        for domain_id, domain_name in domains_list:
            dname_lower = domain_name.lower()
            if dname_lower in explicit_targets:
                node_data = {
                    "id": f"dom_{domain_id}",
                    "label": domain_name,
                    "type": "domain",
                    "name": domain_name,
                    "is_target": True,
                    "is_root": False
                }
                nodes.append({"data": node_data, "classes": "is-target"})
                if root_target_node:
                    edges.append({"data": {"id": f"e_target_dom_{domain_id}", "source": "target_root", "target": f"dom_{domain_id}", "label": "CONTAINS_TARGET"}})

        for sub_id, sub_info in subdomain_info_map.items():
            sname_lower = sub_info["name"].lower()
            if sname_lower in explicit_targets:
                node_data = {
                    "id": f"sub_{sub_id}",
                    "label": sub_info["name"],
                    "type": "subdomain",
                    "name": sub_info["name"],
                    "domain_id": sub_info["domain_id"],
                    "domain_name": sub_info["domain_name"],
                    "is_target": True
                }
                nodes.append({"data": node_data, "classes": "is-target"})
                if root_target_node:
                    edges.append({"data": {"id": f"e_target_sub_{sub_id}", "source": "target_root", "target": f"sub_{sub_id}", "label": "CONTAINS_TARGET"}})

        return nodes, edges, root_target_node, subdomain_to_ips, domain_to_ips
    
    def _build_ip_nodes(
        self,
        conn: sqlite3.Connection,
        subdomain_to_ips: Dict[str, set],
        domain_to_ips: Dict[str, set],
        spawned_fqdn_ids: Optional[Set[str]] = None,
        target_name: Optional[str] = None,
        target_type: Optional[str] = None,
        targets_list: Optional[List[str]] = None,
        root_target_node: Optional[Dict] = None
    ) -> tuple[List[Dict], List[Dict]]:
        nodes = []
        edges = []
        cols = {r[1] for r in conn.execute("PRAGMA table_info(ip_addresses)").fetchall()}
        select_post = ", postal_code" if "postal_code" in cols else ", '' as postal_code"
        select_geo = ", latitude, longitude" if ("latitude" in cols and "longitude" in cols) else ", NULL as latitude, NULL as longitude"

        cursor = conn.execute(f"""
            SELECT id, ip, org, country, city, region_code, asn {select_post} {select_geo}
            FROM ip_addresses
        """)
        ip_rows = cursor.fetchall()

        cursor_fqdns = conn.execute("""
            SELECT DISTINCT si.ip_id, s.name
            FROM subdomain_ips si
            JOIN subdomains s ON si.subdomain_id = s.id
            ORDER BY LENGTH(s.name) ASC, s.name ASC
        """)
        ip_to_fqdns: Dict[str, List[str]] = {}
        for ip_id, fqdn in cursor_fqdns.fetchall():
            if fqdn:
                ip_to_fqdns.setdefault(str(ip_id), []).append(fqdn)
        
        targets_set = set(t.strip().lower() for t in targets_list) if targets_list else set()

        for ip_id, ip, org, country, city, region_code, asn, postal_code, latitude, longitude in ip_rows:
            fqdns = ip_to_fqdns.get(str(ip_id), [])
            is_tgt = bool(ip and ip.strip().lower() in targets_set)
            node_dict = {
                "data": {
                    "id": f"ip_{ip_id}",
                    "label": ip,
                    "type": "ip",
                    "ip": ip,
                    "org": org or "Unknown",
                    "country": country or "Unknown",
                    "city": city or "",
                    "region_code": region_code or "",
                    "postal_code": postal_code or "",
                    "latitude": latitude,
                    "longitude": longitude,
                    "asn": asn or "Unknown",
                    "fqdns": fqdns,
                    "fqdn_count": len(fqdns),
                    "is_target": is_tgt
                }
            }
            if is_tgt:
                node_dict["classes"] = "is-target"
            nodes.append(node_dict)

            # Every Host IP directly relates to target_root via CONTAINS_TARGET
            if root_target_node:
                edges.append({
                    "data": {
                        "id": f"e_root_ip_{ip_id}",
                        "source": "target_root",
                        "target": f"ip_{ip_id}",
                        "label": "CONTAINS_TARGET"
                    }
                })
        
        # Connect Explicit FQDN targets -> IPs (RESOLVES_TO) ONLY if the node exists in graph
        fqdn_set = spawned_fqdn_ids or set()
        for sub_id, ip_ids in subdomain_to_ips.items():
            sub_node_id = f"sub_{sub_id}"
            if sub_node_id in fqdn_set:
                for ip_id in ip_ids:
                    edges.append({"data": {"id": f"e_sub_ip_{sub_id}_{ip_id}", "source": sub_node_id, "target": f"ip_{ip_id}", "label": "RESOLVES_TO"}})

        for dom_id, ip_ids in domain_to_ips.items():
            dom_node_id = f"dom_{dom_id}"
            if dom_node_id in fqdn_set:
                for ip_id in ip_ids:
                    edges.append({"data": {"id": f"e_dom_ip_{dom_id}_{ip_id}", "source": dom_node_id, "target": f"ip_{ip_id}", "label": "RESOLVES_TO"}})
        
        return nodes, edges
    
    def _build_service_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build service/port nodes with active scan differentiation."""
        import json
        nodes = []
        edges = []
        
        cursor = conn.execute("""
            SELECT id, ip_id, port, protocol, service_name, product, version, banner, ssl, url, sources
            FROM services
            ORDER BY rowid ASC
        """)
        
        seen_services = {}
        
        for service_id, ip_id, port, protocol, service_name, product, version, banner, ssl, url, sources_raw in cursor.fetchall():
            proto_str = (protocol or "tcp").lower()
            key = (ip_id, port, proto_str)
            
            # Parse sources
            sources_list = []
            if sources_raw:
                try:
                    parsed = json.loads(sources_raw)
                    if isinstance(parsed, list):
                        sources_list = parsed
                    else:
                        sources_list = [str(parsed)]
                except Exception:
                    sources_list = [sources_raw]
            
            has_masscan = any("masscan" in str(s).lower() for s in sources_list)
            
            if key in seen_services:
                # Merge into existing node data
                existing_node = seen_services[key]
                cur_sources = set(existing_node["data"]["sources"])
                cur_sources.update(sources_list)
                existing_node["data"]["sources"] = sorted(list(cur_sources))
                if has_masscan:
                    existing_node["data"]["is_active_scan"] = True
                    existing_node["data"]["verified_active"] = True
                if banner and not existing_node["data"]["banner"]:
                    existing_node["data"]["banner"] = banner
                if service_name and (not existing_node["data"]["service"] or existing_node["data"]["service"] == "unknown"):
                    existing_node["data"]["service"] = service_name
                continue
            
            label = f"{port}/{proto_str}"
            service_type = "https" if ssl else "http" if port in [80, 8080, 8000] else "service"
            
            node_obj = {
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
                    "url": url or "",
                    "sources": sources_list,
                    "is_active_scan": has_masscan,
                    "verified_active": has_masscan,
                }
            }
            seen_services[key] = node_obj
            nodes.append(node_obj)
            
            # Edge from IP to service
            edges.append({
                "data": {
                    "id": f"e_ip_srv_{ip_id}_{service_id}",
                    "source": f"ip_{ip_id}",
                    "target": f"srv_{service_id}",
                    "label": "EXPOSES",
                    "is_active_scan": has_masscan,
                    "verified_active": has_masscan
                }
            })
        
        return nodes, edges
    
    def _build_vulnerability_nodes(self, conn: sqlite3.Connection) -> tuple[List[Dict], List[Dict]]:
        """Build vulnerability nodes with risk indicators and PoC information.
        
        Consolidates vulnerability nodes by CVE ID (or vuln ID) so that identical
        vulnerabilities affecting multiple services or IPs share a single node on the graph
        with incoming HAS_VULN edges from each affected service/IP.
        """
        nodes = []
        edges = []
        seen_vuln_node_ids = set()
        seen_edge_ids = set()
        
        try:
            # Ensure source column exists
            try:
                cols = [r[1] for r in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()]
                has_source_col = "source" in cols
            except Exception:
                has_source_col = False

            source_select = "v.source" if has_source_col else "'NVD' as source"

            cursor = conn.execute(f"""
                SELECT v.id, v.ip_id, v.service_id, v.cve_id, v.severity, v.cvss_score, 
                       v.epss_score, v.is_cisa_kev, v.description, {source_select},
                       COUNT(e.id) as exploit_count,
                       ip.id as resolved_ip_id, ip.ip, ip.org, ip.country, ip.asn,
                       s.port, s.protocol, s.service_name, s.product, s.version, s.url, s.ssl
                FROM vulnerabilities v
                LEFT JOIN exploits e ON v.id = e.vulnerability_id
                LEFT JOIN services s ON v.service_id = s.id
                LEFT JOIN ip_addresses ip ON COALESCE(v.ip_id, s.ip_id) = ip.id
                GROUP BY v.id, v.ip_id, v.service_id, v.cve_id, v.severity, v.cvss_score, 
                         v.epss_score, v.is_cisa_kev, v.description, {source_select},
                         ip.id, ip.ip, ip.org, ip.country, ip.asn,
                         s.port, s.protocol, s.service_name, s.product, s.version, s.url, s.ssl
            """)
            
            for row in cursor.fetchall():
                (vuln_id, ip_id, service_id, cve_id, severity, cvss_score, epss_score, 
                 is_cisa_kev, description, vuln_source, exploit_count, resolved_ip_id, ip_address, 
                 org, country, asn, port, protocol, service_name, product, version, url, ssl) = row
                
                # Build vulnerability label - keep it simple with just CVE ID
                label = cve_id or "Unknown CVE"
                # Use normalized CVE node ID if available to merge identical CVEs into one node
                clean_cve = (cve_id or "").strip()
                node_id = f"vuln_{clean_cve.replace(' ', '_').lower()}" if clean_cve and clean_cve.upper() != "UNKNOWN" else f"vuln_{vuln_id}"
                
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
                
                # Only construct the node data once per unique CVE
                if node_id not in seen_vuln_node_ids:
                    seen_vuln_node_ids.add(node_id)
                    
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
                            "id": node_id,
                            "label": label,
                            "type": "vulnerability",
                            "cve_id": cve_id or "Unknown",
                            "severity": severity or "UNKNOWN",
                            "cvss_score": cvss_score or 0,
                            "epss_score": epss_score or 0,
                            "is_cisa_kev": bool(is_cisa_kev),
                            "risk_level": risk_level,
                            "source": vuln_source or ("Nuclei" if not clean_cve.startswith("CVE-") else "NVD"),
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
                
                # Create HAS_VULN edge from Service or IP to the deduplicated Vulnerability node
                vuln_sev = (severity or "UNKNOWN").upper()
                if service_id:
                    edge_id = f"e_srv_vuln_{service_id}_{node_id}"
                    if edge_id not in seen_edge_ids:
                        seen_edge_ids.add(edge_id)
                        edges.append({
                            "data": {
                                "id": edge_id,
                                "source": f"srv_{service_id}",
                                "target": node_id,
                                "label": "HAS_VULN",
                                "vuln_severity": vuln_sev,
                            }
                        })
                elif ip_id:
                    edge_id = f"e_ip_vuln_{ip_id}_{node_id}"
                    if edge_id not in seen_edge_ids:
                        seen_edge_ids.add(edge_id)
                        edges.append({
                            "data": {
                                "id": edge_id,
                                "source": f"ip_{ip_id}",
                                "target": node_id,
                                "label": "HAS_VULN",
                                "vuln_severity": vuln_sev,
                            }
                        })
        except Exception as e:
            print(f"Error building vulnerability nodes: {e}")
        
        return nodes, edges
