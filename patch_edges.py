import re

with open("web/api/graph_builder.py", "r") as f:
    content = f.read()

target = """        # Connect Explicit FQDN targets -> IPs (RESOLVES_TO) ONLY if the node exists in graph
        for sub_id, ip_ids in subdomain_to_ips.items():
            sub_node_id = f"sub_{sub_id}"
            if sub_node_id in fqdn_set:
                for ip_id in ip_ids:
                    edges.append({"data": {"id": f"e_sub_ip_{sub_id}_{ip_id}", "source": sub_node_id, "target": f"ip_{ip_id}", "label": "RESOLVES_TO"}})

        for dom_id, ip_ids in domain_to_ips.items():
            dom_node_id = f"dom_{dom_id}"
            if dom_node_id in fqdn_set:
                for ip_id in ip_ids:
                    edges.append({"data": {"id": f"e_dom_ip_{dom_id}_{ip_id}", "source": dom_node_id, "target": f"ip_{ip_id}", "label": "RESOLVES_TO"}})"""

replacement = """        # Connect FQDN targets -> IPs (RESOLVES_TO) ONLY if the node exists in graph.
        # If the FQDN is an explicit target, we show ALL its resolved IPs.
        # If the FQDN was merely spawned to support an explicitly targeted IP, we ONLY connect to the targeted IPs!
        cursor_all_ips = conn.execute("SELECT id, ip FROM ip_addresses")
        ip_id_to_str = {str(r[0]): r[1].lower() for r in cursor_all_ips.fetchall()}

        # Re-verify if fqdns are explicit targets
        cursor_fqdns_check = conn.execute("SELECT id, name FROM domains UNION SELECT id, name FROM subdomains")
        fqdn_id_to_name = {f"dom_{r[0]}": r[1].lower() for r in cursor_fqdns_check.fetchall()}
        cursor_fqdns_check = conn.execute("SELECT id, name FROM subdomains")
        for r in cursor_fqdns_check.fetchall():
            fqdn_id_to_name[f"sub_{r[0]}"] = r[1].lower()

        for sub_id, ip_ids in subdomain_to_ips.items():
            sub_node_id = f"sub_{sub_id}"
            if sub_node_id in fqdn_set:
                is_fqdn_targeted = fqdn_id_to_name.get(sub_node_id) in explicit_targets
                for ip_id in ip_ids:
                    ip_str = ip_id_to_str.get(str(ip_id), "")
                    if is_fqdn_targeted or ip_str in targets_set:
                        edges.append({"data": {"id": f"e_sub_ip_{sub_id}_{ip_id}", "source": sub_node_id, "target": f"ip_{ip_id}", "label": "RESOLVES_TO"}})

        for dom_id, ip_ids in domain_to_ips.items():
            dom_node_id = f"dom_{dom_id}"
            if dom_node_id in fqdn_set:
                is_fqdn_targeted = fqdn_id_to_name.get(dom_node_id) in explicit_targets
                for ip_id in ip_ids:
                    ip_str = ip_id_to_str.get(str(ip_id), "")
                    if is_fqdn_targeted or ip_str in targets_set:
                        edges.append({"data": {"id": f"e_dom_ip_{dom_id}_{ip_id}", "source": dom_node_id, "target": f"ip_{ip_id}", "label": "RESOLVES_TO"}})"""

content = content.replace(target, replacement)
with open("web/api/graph_builder.py", "w") as f:
    f.write(content)
