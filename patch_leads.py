import re

def patch_graph_builder():
    path = "web/api/graph_builder.py"
    with open(path, "r") as f:
        content = f.read()

    # We need to replace the logic in _build_domain_nodes that spawns all nodes.
    # From:
    # domains_to_spawn = set(d[0] for d in domains_list)
    # subdomains_to_spawn = set(subdomain_info_map.keys())
    # To:
    # domains_to_spawn = set()
    # subdomains_to_spawn = set()
    
    # Actually, we can revert to what it was before 1dcb915dee2fc4efc3909485d497c6530c4f6346:
    replacement = """
# 2. Topologically hierarchical node spawning
        domains_to_spawn = set()
        subdomains_to_spawn = set()

        # Determine which domains are explicit targets (or parents of explicit targets) to receive CONTAINS_TARGET
        explicit_domains = set()
        for domain_id, domain_name in domains_list:
            if domain_name.lower() in explicit_targets:
                domains_to_spawn.add(domain_id)
                explicit_domains.add(domain_id)
        
        for sub_id, sub_info in subdomain_info_map.items():
            if sub_info["name"].lower() in explicit_targets:
                subdomains_to_spawn.add(sub_id)
                domains_to_spawn.add(sub_info["domain_id"])
                explicit_domains.add(sub_info["domain_id"])
            elif any(ip in explicit_targets for ip in sub_info["ips"]):
                subdomains_to_spawn.add(sub_id)
                domains_to_spawn.add(sub_info["domain_id"])
                explicit_domains.add(sub_info["domain_id"])
                
        cursor_all_ips = conn.execute("SELECT id, ip FROM ip_addresses")
        ip_id_to_str = {str(r[0]): r[1].lower() for r in cursor_all_ips.fetchall()}
        for domain_id, ip_ids in domain_to_ips.items():
            if domain_id not in domains_to_spawn:
                if any(ip_id_to_str.get(str(ip_id)) in explicit_targets for ip_id in ip_ids):
                    domains_to_spawn.add(domain_id)
                    explicit_domains.add(domain_id)

        for domain_id, domain_name in domains_list:
            if domain_id in domains_to_spawn:
                dname_lower = domain_name.lower()
                domain_subs = [s for s in all_subdomains if s.get("domain_id") == domain_id or s.get("domain_name", "").lower() == dname_lower]
                node_data = {
                    "id": f"dom_{domain_id}",
                    "label": domain_name,
                    "type": "domain",
                    "name": domain_name,
                    "related_subdomains": domain_subs,
                    "subdomain_count": len(domain_subs),
                    "is_target": (dname_lower in explicit_targets),
                    "is_root": False
                }
                nodes.append({"data": node_data, "classes": "is-target" if node_data["is_target"] else ""})
                
                if root_target_node:
                    if domain_id in explicit_domains:
                        edges.append({"data": {"id": f"e_target_dom_{domain_id}", "source": "target_root", "target": f"dom_{domain_id}", "label": "CONTAINS_TARGET"}})
                    else:
                        edges.append({"data": {"id": f"e_target_dom_{domain_id}", "source": "target_root", "target": f"dom_{domain_id}", "label": "MATCHES_DOMAIN"}})

        for sub_id, sub_info in subdomain_info_map.items():
            if sub_id in subdomains_to_spawn:
                sname_lower = sub_info["name"].lower()
                node_data = {
                    "id": f"sub_{sub_id}",
                    "label": sub_info["name"],
                    "type": "subdomain",
                    "name": sub_info["name"],
                    "domain_id": sub_info["domain_id"],
                    "domain_name": sub_info["domain_name"],
                    "is_target": (sname_lower in explicit_targets)
                }
                nodes.append({"data": node_data, "classes": "is-target" if node_data["is_target"] else ""})
                
                parent_dom_id = sub_info["domain_id"]
                edges.append({"data": {"id": f"e_dom_sub_{sub_id}", "source": f"dom_{parent_dom_id}", "target": f"sub_{sub_id}", "label": "HAS_SUBDOMAIN"}})

        # --- EXPLORE LEADS DATA BUILDER ---
        # Build the explore_leads array and attach it to root_target_node
        if root_target_node:
            explore_leads = []
            ip_stats = {}
            cursor_ips = conn.execute(\"\"\"
                SELECT ip.id, ip.ip,
                       COUNT(DISTINCT s.id) as service_count,
                       COUNT(DISTINCT CASE WHEN s.sources LIKE '%masscan%' OR s.sources LIKE '%active%' THEN s.id END) as verified_service_count,
                       COUNT(DISTINCT v.id) as vuln_count,
                       MAX(CASE WHEN v.is_cisa_kev = 1 THEN 1 ELSE 0 END) as has_kev,
                       COUNT(DISTINCT CASE WHEN v.is_cisa_kev = 1 THEN v.id END) as kev_count,
                       COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.id END) as critical_count,
                       COUNT(DISTINCT CASE WHEN v.severity = 'HIGH' THEN v.id END) as high_count,
                       MAX(v.epss_score) as max_epss,
                       COUNT(DISTINCT CASE WHEN v.epss_score >= 0.20 THEN v.id END) as high_epss_count,
                       COUNT(DISTINCT e.id) as poc_count
                FROM ip_addresses ip
                LEFT JOIN services s ON ip.id = s.ip_id
                LEFT JOIN vulnerabilities v ON ip.id = v.ip_id OR s.id = v.service_id
                LEFT JOIN exploits e ON v.id = e.vulnerability_id
                GROUP BY ip.id, ip.ip
            \"\"\")
            for row in cursor_ips.fetchall():
                ip_id, ip, s_cnt, vs_cnt, v_cnt, has_kev, k_cnt, c_cnt, h_cnt, max_epss, h_epss_cnt, poc_cnt = row
                max_epss = max_epss or 0.0
                stats = {
                    "service_count": s_cnt,
                    "verified_service_count": vs_cnt,
                    "vuln_count": v_cnt,
                    "has_kev": bool(has_kev),
                    "kev_count": k_cnt,
                    "critical_count": c_cnt,
                    "high_count": h_cnt,
                    "max_epss": max_epss,
                    "high_epss_count": h_epss_cnt,
                    "poc_count": poc_cnt
                }
                ip_stats[ip_id] = stats
                score = (k_cnt * 1000000) + (poc_cnt * 200000) + (h_epss_cnt * 100000) + (max_epss * 50000) + (c_cnt * 50000) + (h_cnt * 20000) + (vs_cnt * 5000) + (v_cnt * 1000) + (s_cnt * 100)
                explore_leads.append({
                    "id": f"ip_{ip_id}",
                    "label": ip,
                    "display_name": ip,
                    "type": "ip",
                    "three_d_score": score,
                    **stats
                })
            
            subdomain_stats = {}
            for sub_id, sub_info in subdomain_info_map.items():
                s_stats = {"service_count": 0, "verified_service_count": 0, "vuln_count": 0, "has_kev": False, "kev_count": 0, "critical_count": 0, "high_count": 0, "max_epss": 0.0, "high_epss_count": 0, "poc_count": 0}
                ips = subdomain_to_ips.get(sub_id, set())
                for ip_id in ips:
                    if ip_id in ip_stats:
                        st = ip_stats[ip_id]
                        for k in ["service_count", "verified_service_count", "vuln_count", "kev_count", "critical_count", "high_count", "high_epss_count", "poc_count"]:
                            s_stats[k] += st[k]
                        s_stats["has_kev"] = s_stats["has_kev"] or st["has_kev"]
                        s_stats["max_epss"] = max(s_stats["max_epss"], st["max_epss"])
                subdomain_stats[sub_id] = s_stats
                score = (s_stats["kev_count"] * 1000000) + (s_stats["poc_count"] * 200000) + (s_stats["high_epss_count"] * 100000) + (s_stats["max_epss"] * 50000) + (s_stats["critical_count"] * 50000) + (s_stats["high_count"] * 20000) + (s_stats["verified_service_count"] * 5000) + (s_stats["vuln_count"] * 1000) + (s_stats["service_count"] * 100)
                explore_leads.append({
                    "id": f"sub_{sub_id}",
                    "label": sub_info["name"],
                    "display_name": sub_info["name"],
                    "type": "subdomain",
                    "three_d_score": score,
                    **s_stats
                })

            for domain_id, domain_name in domains_list:
                d_stats = {"service_count": 0, "verified_service_count": 0, "vuln_count": 0, "has_kev": False, "kev_count": 0, "critical_count": 0, "high_count": 0, "max_epss": 0.0, "high_epss_count": 0, "poc_count": 0}
                # aggregate from apex ips
                for ip_id in domain_to_ips.get(domain_id, set()):
                    if ip_id in ip_stats:
                        st = ip_stats[ip_id]
                        for k in ["service_count", "verified_service_count", "vuln_count", "kev_count", "critical_count", "high_count", "high_epss_count", "poc_count"]:
                            d_stats[k] += st[k]
                        d_stats["has_kev"] = d_stats["has_kev"] or st["has_kev"]
                        d_stats["max_epss"] = max(d_stats["max_epss"], st["max_epss"])
                
                # aggregate from subdomains
                for sub_id, sub_info in subdomain_info_map.items():
                    if sub_info["domain_id"] == domain_id:
                        st = subdomain_stats.get(sub_id, {})
                        if st:
                            for k in ["service_count", "verified_service_count", "vuln_count", "kev_count", "critical_count", "high_count", "high_epss_count", "poc_count"]:
                                d_stats[k] += st.get(k, 0)
                            d_stats["has_kev"] = d_stats["has_kev"] or st.get("has_kev", False)
                            d_stats["max_epss"] = max(d_stats["max_epss"], st.get("max_epss", 0.0))
                
                score = (d_stats["kev_count"] * 1000000) + (d_stats["poc_count"] * 200000) + (d_stats["high_epss_count"] * 100000) + (d_stats["max_epss"] * 50000) + (d_stats["critical_count"] * 50000) + (d_stats["high_count"] * 20000) + (d_stats["verified_service_count"] * 5000) + (d_stats["vuln_count"] * 1000) + (d_stats["service_count"] * 100)
                explore_leads.append({
                    "id": f"dom_{domain_id}",
                    "label": domain_name,
                    "display_name": domain_name,
                    "type": "domain",
                    "three_d_score": score,
                    **d_stats
                })
            
            root_target_node["data"]["explore_leads"] = explore_leads
"""
    
    # We will regex replace from "# 2. Topologically hierarchical node spawning" to "return nodes, edges, root_target_node, subdomain_to_ips, domain_to_ips, explicit_targets"
    pattern = r"# 2\. Topologically hierarchical node spawning.*?return nodes, edges, root_target_node, subdomain_to_ips, domain_to_ips, explicit_targets"
    new_content = re.sub(pattern, replacement + "\n\n        return nodes, edges, root_target_node, subdomain_to_ips, domain_to_ips, explicit_targets", content, flags=re.DOTALL)
    
    with open(path, "w") as f:
        f.write(new_content)

def patch_ip_nodes():
    path = "web/api/graph_builder.py"
    with open(path, "r") as f:
        content = f.read()
    
    # We also need to fix `connected_ip_ids` back to what it was before `1dcb915dee2fc4efc3909485d497c6530c4f6346`
    # In `_build_ip_nodes` we don't return `connected_ip_ids`.
    # It is done in `build_graph`:
    old_code = r'''            # Determine which IPs have actual topological connections on canvas (either via RESOLVES_TO or CONTAINS_TARGET)
            connected_ip_ids = \{n\["data"\]\["id"\] for n in ip_nodes\}

            # In Scope-driven mode (file, domain, subdomain), omit orphaned passive IPs from canvas
            # In Discovery query mode, all IPs have CONTAINS_TARGET and are kept
            visible_ip_nodes = ip_nodes'''
    
    new_code = '''            # Determine which IPs have actual topological connections on canvas (either via RESOLVES_TO or CONTAINS_TARGET)
            connected_ip_ids = {
                e["data"]["target"] for e in (domain_edges + ip_edges)
                if e["data"].get("label") in ("RESOLVES_TO", "CONTAINS_TARGET") and str(e["data"].get("target", "")).startswith("ip_")
            }

            # In Scope-driven mode (file, domain, subdomain), omit orphaned passive IPs from canvas
            # In Discovery query mode, all IPs have CONTAINS_TARGET and are kept
            visible_ip_nodes = [n for n in ip_nodes if n["data"]["id"] in connected_ip_ids]'''
            
    content = re.sub(old_code, new_code, content)
    with open(path, "w") as f:
        f.write(content)

patch_graph_builder()
patch_ip_nodes()
