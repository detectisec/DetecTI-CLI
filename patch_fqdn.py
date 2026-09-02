import re

with open("web/api/graph_builder.py", "r") as f:
    content = f.read()

# We will replace the block from "        # 2. Spawn Graph Nodes ONLY for FQDNs that were explicitly marked / scanned as targets"
# to the end of _build_fqdn_nodes.

replacement = """
        # 2. Topologically hierarchical node spawning (Avoid Triangles Rule)
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
        for domain_id, ip_ids in domain_to_ips.items():
            if domain_id not in domains_to_spawn:
                # Need to look up the IPs to see if they are in explicit_targets
                # We can do this efficiently later or just assume if it's an apex IP, it should spawn the domain.
                pass # We will handle apex IPs in _build_ip_nodes if needed, but usually explicit_targets has IPs as strings.

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
                    edges.append({"data": {"id": f"e_dom_sub_{sub_id}", "source": f"dom_{parent_dom_id}", "target": f"sub_{sub_id}", "label": "HAS_SUBDOMAIN"}})

        return nodes, edges, root_target_node, subdomain_to_ips, domain_to_ips, explicit_targets
"""

pattern = re.compile(r'        # 2\. Spawn Graph Nodes ONLY for FQDNs.*?return nodes, edges, root_target_node, subdomain_to_ips, domain_to_ips, explicit_targets', re.DOTALL)
new_content = pattern.sub(replacement.strip(), content)

with open("web/api/graph_builder.py", "w") as f:
    f.write(new_content)
