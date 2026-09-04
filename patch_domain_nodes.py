import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/api/graph_builder.py"
with open(file_path, "r") as f:
    content = f.read()

# Replace the specific node spawning logic
old_logic = """# 2. Topologically hierarchical node spawning (Avoid Triangles Rule)
        # Determine which domains and subdomains MUST spawn to preserve the full lineage for explicit targets.
        domains_to_spawn = set()
        subdomains_to_spawn = set()

        for domain_id, domain_name in domains_list:
            if domain_name.lower() in explicit_targets:
                domains_to_spawn.add(domain_id)

        for sub_id, sub_info in subdomain_info_map.items():
            # If the subdomain is an explicit target, spawn it AND its parent domain
            if sub_info["name"].lower() in explicit_targets:
                subdomains_to_spawn.add(sub_id)
                domains_to_spawn.add(sub_info["domain_id"])
            # If any IP of this subdomain is an explicit target, spawn the lineage
            elif any(ip in explicit_targets for ip in sub_info["ips"]):
                subdomains_to_spawn.add(sub_id)
                domains_to_spawn.add(sub_info["domain_id"])

        # Also check apex domains for targeted IPs
        cursor_all_ips = conn.execute("SELECT id, ip FROM ip_addresses")
        ip_id_to_str = {str(r[0]): r[1].lower() for r in cursor_all_ips.fetchall()}

        for domain_id, ip_ids in domain_to_ips.items():
            if domain_id not in domains_to_spawn:
                if any(ip_id_to_str.get(str(ip_id)) in explicit_targets for ip_id in ip_ids):
                    domains_to_spawn.add(domain_id)

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
                
                # Tier 1: Domains ALWAYS connect to root
                if root_target_node:
                    edges.append({"data": {"id": f"e_target_dom_{domain_id}", "source": "target_root", "target": f"dom_{domain_id}", "label": "CONTAINS_TARGET"}})

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
                
                # Tier 2: Subdomains ALWAYS connect to their parent domain (No Root Triangles)
                parent_dom_id = sub_info["domain_id"]
                if parent_dom_id in domains_to_spawn:
                    edges.append({"data": {"id": f"e_dom_sub_{sub_id}", "source": f"dom_{parent_dom_id}", "target": f"sub_{sub_id}", "label": "HAS_SUBDOMAIN"}})"""

new_logic = """# 2. Topologically hierarchical node spawning
        # Spawn ALL domains and subdomains so they are available in the frontend Explore Leads modal.
        # Explicit targets get CONTAINS_TARGET (Tier 1 auto-render). Passive discoveries get MATCHES_DOMAIN.
        domains_to_spawn = set(d[0] for d in domains_list)
        subdomains_to_spawn = set(subdomain_info_map.keys())

        # Determine which domains are explicit targets (or parents of explicit targets) to receive CONTAINS_TARGET
        explicit_domains = set()
        for domain_id, domain_name in domains_list:
            if domain_name.lower() in explicit_targets:
                explicit_domains.add(domain_id)
        
        for sub_id, sub_info in subdomain_info_map.items():
            if sub_info["name"].lower() in explicit_targets or any(ip in explicit_targets for ip in sub_info["ips"]):
                explicit_domains.add(sub_info["domain_id"])
                
        cursor_all_ips = conn.execute("SELECT id, ip FROM ip_addresses")
        ip_id_to_str = {str(r[0]): r[1].lower() for r in cursor_all_ips.fetchall()}
        for domain_id, ip_ids in domain_to_ips.items():
            if any(ip_id_to_str.get(str(ip_id)) in explicit_targets for ip_id in ip_ids):
                explicit_domains.add(domain_id)

        for domain_id, domain_name in domains_list:
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
            edges.append({"data": {"id": f"e_dom_sub_{sub_id}", "source": f"dom_{parent_dom_id}", "target": f"sub_{sub_id}", "label": "HAS_SUBDOMAIN"}})"""

if old_logic in content:
    with open(file_path, "w") as f:
        f.write(content.replace(old_logic, new_logic))
    print("Patched successfully")
else:
    print("Could not find the exact old logic block")
