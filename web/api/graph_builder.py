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
            domain_nodes, domain_edges, root_target_node, subdomain_to_ips, domain_to_ips = self._build_domain_nodes(conn, target_name, target_type)
            if root_target_node:
                nodes.append(root_target_node)
            nodes.extend(domain_nodes)
            edges.extend(domain_edges)
            
            # 3. Build IP nodes connected to subdomains/domains (or target root)
            ip_nodes, ip_edges = self._build_ip_nodes(conn, subdomain_to_ips, domain_to_ips, root_target_node)
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
        targets_list = []
        explicit_targets = set()
        if target_name:
            # If target_type is file or list, retrieve the exact targets from the input file on disk
            if target_type == "file":
                from pathlib import Path
                clean_path = str(target_name).strip()
                file_obj = Path(clean_path)
                if not file_obj.is_absolute():
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

        is_file_target = (target_type == "file" or bool(targets_list and len(targets_list) > 1))
        direct_target_subdomains = set()

        # Determine in-scope target roots
        target_scopes = set()
        if explicit_targets:
            for item in explicit_targets:
                if "." in item and not item.replace(".", "").isdigit():
                    try:
                        import tldextract
                        ext = tldextract.extract(item)
                        if ext.registered_domain:
                            target_scopes.add(ext.registered_domain.lower())
                    except Exception:
                        pass
                    target_scopes.add(item.lower())
        elif target_name:
            t_clean = target_name.strip().lower()
            if "." in t_clean and not t_clean.replace(".", "").isdigit():
                try:
                    import tldextract
                    ext = tldextract.extract(t_clean)
                    if ext.registered_domain:
                        target_scopes.add(ext.registered_domain.lower())
                except Exception:
                    pass
                target_scopes.add(t_clean)

        def _is_in_scope(h: str) -> bool:
            if not target_scopes:
                return True
            h_clean = h.strip().lower()
            return any(h_clean == s or h_clean.endswith(f".{s}") for s in target_scopes)

        # Filter out out-of-scope third party domains (like rdstation, aramado, cloudfront, etc.)
        if target_scopes:
            domains_list = [d for d in domains_list if _is_in_scope(d[1])]

        # 2. Add domain nodes (Domains discovered during the scan)
        for domain_id, domain_name in domains_list:
            dname_lower = domain_name.lower()
            is_main_domain = bool(target_name and (dname_lower == target_name.lower() or target_name.lower().endswith(f".{dname_lower}")))
            node_data = {
                "id": f"dom_{domain_id}",
                "label": domain_name,
                "type": "domain",
                "name": domain_name,
                "is_root": is_main_domain
            }
            nodes.append({"data": node_data})
            processed_domains.add(domain_id)

            # Connect Target Root -> Domain (if domain was explicitly in targets_list or general scan)
            if root_target_node:
                if is_file_target and explicit_targets:
                    if dname_lower in explicit_targets:
                        edges.append({
                            "data": {
                                "id": f"e_target_dom_{domain_id}",
                                "source": "target_root",
                                "target": f"dom_{domain_id}",
                                "label": "MATCHES_DOMAIN"
                            }
                        })
                else:
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
        domain_to_ips = {}
        subdomain_records = []
        
        for row in cursor.fetchall():
            sub_id, sub_name, domain_id, domain_name, ip_id, ip_address = row
            
            # Filter out out-of-scope subdomains
            if target_scopes and (not _is_in_scope(sub_name) or not _is_in_scope(domain_name)):
                continue

            # If sub_name is the root domain itself (e.g. vila11.com.br == vila11.com.br), do not create duplicate subdomain node
            if sub_name.strip().lower() == domain_name.strip().lower():
                if ip_id and ip_address:
                    domain_to_ips.setdefault(domain_id, set()).add(ip_id)
                continue

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

                # Check if this subdomain is an explicit target from the input file/list
                if is_file_target and explicit_targets and sub_name.lower() in explicit_targets:
                    direct_target_subdomains.add(sub_id)
                    if root_target_node:
                        edges.append({
                            "data": {
                                "id": f"e_target_sub_{sub_id}",
                                "source": "target_root",
                                "target": f"sub_{sub_id}",
                                "label": "TARGET_SUBDOMAIN"
                            }
                        })
            
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
            if target_scopes and (not _is_in_scope(sub_name) or not _is_in_scope(domain_name)):
                continue

            if sub_name.strip().lower() == domain_name.strip().lower():
                continue

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

                if is_file_target and explicit_targets and sub_name.lower() in explicit_targets:
                    direct_target_subdomains.add(sub_id)
                    if root_target_node:
                        edges.append({
                            "data": {
                                "id": f"e_target_sub_{sub_id}",
                                "source": "target_root",
                                "target": f"sub_{sub_id}",
                                "label": "TARGET_SUBDOMAIN"
                            }
                        })

        # If a file target had domains but none matched explicitly, connect them to target_root
        if is_file_target and root_target_node:
            connected_targets = {e["data"]["target"] for e in edges if e["data"]["source"] == "target_root"}
            if not connected_targets:
                for domain_id, _ in domains_list:
                    edges.append({
                        "data": {
                            "id": f"e_target_dom_{domain_id}",
                            "source": "target_root",
                            "target": f"dom_{domain_id}",
                            "label": "MATCHES_DOMAIN"
                        }
                    })

        # 3. Build Multi-Level FQDN Tree Hierarchy
        # Map all known domain and subdomain names to their node IDs
        fqdn_to_node_id = {}
        for domain_id, domain_name in domains_list:
            fqdn_to_node_id[domain_name.lower()] = f"dom_{domain_id}"
        for sub_id, sub_name, domain_id, domain_name in subdomain_records:
            fqdn_to_node_id[sub_name.lower()] = f"sub_{sub_id}"

        # Ensure every explicit domain/subdomain target from input file exists as a node directly under target_root
        if is_file_target and explicit_targets and root_target_node:
            for item in explicit_targets:
                item_clean = item.strip().lower()
                if item_clean not in fqdn_to_node_id:
                    # If it has dots and is not a plain IP
                    if "." in item_clean and not item_clean.replace(".", "").isdigit():
                        try:
                            import tldextract
                            ext = tldextract.extract(item_clean)
                            reg_dom = ext.registered_domain
                        except Exception:
                            reg_dom = item_clean
                        
                        is_sub = bool(reg_dom and item_clean != reg_dom)
                        node_type = "subdomain" if is_sub else "domain"
                        node_id = f"target_item_{abs(hash(item_clean)) % 10000000}"
                        fqdn_to_node_id[item_clean] = node_id
                        
                        nodes.append({
                            "data": {
                                "id": node_id,
                                "label": item_clean,
                                "type": node_type,
                                "name": item_clean,
                                "is_root": False
                            }
                        })
                        edges.append({
                            "data": {
                                "id": f"e_target_root_{node_id}",
                                "source": "target_root",
                                "target": node_id,
                                "label": "TARGET_SUBDOMAIN" if is_sub else "MATCHES_DOMAIN"
                            }
                        })
                        if is_sub:
                            direct_target_subdomains.add(node_id)

        # Connect each subdomain to its closest parent in the FQDN hierarchy
        for sub_id, sub_name, domain_id, domain_name in subdomain_records:
            # If this subdomain was explicitly connected directly to target_root as a top-level target, don't nest it under domain
            if sub_id in direct_target_subdomains:
                continue

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
        
        return nodes, edges, root_target_node, subdomain_to_ips, domain_to_ips
    
    def _build_ip_nodes(self, conn: sqlite3.Connection, subdomain_to_ips: Dict[str, set], domain_to_ips: Dict[str, set] | None = None, root_target_node: Dict | None = None) -> tuple[List[Dict], List[Dict]]:
        """Build IP address nodes connected to Subdomains/Domains or Root Target."""
        nodes = []
        edges = []
        
        cols = [r[1] for r in conn.execute("PRAGMA table_info(ip_addresses)").fetchall()]
        has_geo = "latitude" in cols and "longitude" in cols
        has_post = "postal_code" in cols
        
        select_geo = ", latitude, longitude" if has_geo else ", NULL as latitude, NULL as longitude"
        select_post = ", postal_code" if has_post else ", NULL as postal_code"

        cursor = conn.execute(f"""
            SELECT id, ip, org, country, city, region_code, asn {select_post} {select_geo}
            FROM ip_addresses
        """)
        
        connected_ips = set()
        
        for ip_id, ip, org, country, city, region_code, asn, postal_code, latitude, longitude in cursor.fetchall():
            label = ip
            
            nodes.append({
                "data": {
                    "id": f"ip_{ip_id}",
                    "label": label,
                    "type": "ip",
                    "ip": ip,
                    "org": org or "Unknown",
                    "country": country or "Unknown",
                    "city": city or "",
                    "region_code": region_code or "",
                    "postal_code": postal_code or "",
                    "latitude": latitude,
                    "longitude": longitude,
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

        # Connect Domains -> IPs (RESOLVES_TO for root domain resolutions)
        if domain_to_ips:
            for dom_id, ip_ids in domain_to_ips.items():
                for ip_id in ip_ids:
                    if ip_id not in connected_ips:
                        edges.append({
                            "data": {
                                "id": f"e_dom_ip_{dom_id}_{ip_id}",
                                "source": f"dom_{dom_id}",
                                "target": f"ip_{ip_id}",
                                "label": "RESOLVES_TO"
                            }
                        })
                        connected_ips.add(ip_id)
        
        # For any IPs not linked via subdomains (e.g. file targets, IP lists, direct IP targets):
        cursor = conn.execute("SELECT id, ip, org FROM ip_addresses")
        orphaned_ips = []
        for ip_id, ip, org in cursor.fetchall():
            if ip_id not in connected_ips:
                orphaned_ips.append((ip_id, ip, org))
        
        if orphaned_ips:
            cursor_dom = conn.execute("SELECT id FROM domains LIMIT 1")
            dom_row = cursor_dom.fetchone()
            
            targets_list = root_target_node["data"].get("targets_list", []) if root_target_node else []
            explicit_targets = {str(t).strip().lower() for t in targets_list if t}
            is_file_target = bool(root_target_node and (root_target_node["data"].get("target_type") == "file" or len(targets_list) > 1))
            
            # When target_root is available:
            if root_target_node:
                for ip_id, ip, org in orphaned_ips:
                    ip_clean = str(ip).strip().lower()
                    # If this IP was an explicit item in the target list, or if there are no domains in the scan:
                    if (is_file_target and ip_clean in explicit_targets) or not dom_row:
                        edges.append({
                            "data": {
                                "id": f"e_root_ip_{ip_id}",
                                "source": "target_root",
                                "target": f"ip_{ip_id}",
                                "label": "CONTAINS_IP"
                            }
                        })
                    elif dom_row:
                        dom_id = dom_row[0]
                        edges.append({
                            "data": {
                                "id": f"e_dom_ip_{dom_id}_{ip_id}",
                                "source": f"dom_{dom_id}",
                                "target": f"ip_{ip_id}",
                                "label": "RESOLVES_TO"
                            }
                        })
            elif dom_row:
                dom_id = dom_row[0]
                for ip_id, ip, org in orphaned_ips:
                    edges.append({
                        "data": {
                            "id": f"e_dom_ip_{dom_id}_{ip_id}",
                            "source": f"dom_{dom_id}",
                            "target": f"ip_{ip_id}",
                            "label": "RESOLVES_TO"
                        }
                    })
        
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
