with open("web/api/graph_builder.py", "r") as f:
    content = f.read()

target = """        # Also check apex domains for targeted IPs
        for domain_id, ip_ids in domain_to_ips.items():
            if domain_id not in domains_to_spawn:
                # Need to look up the IPs to see if they are in explicit_targets
                # We can do this efficiently later or just assume if it's an apex IP, it should spawn the domain.
                pass # We will handle apex IPs in _build_ip_nodes if needed, but usually explicit_targets has IPs as strings."""

replacement = """        # Also check apex domains for targeted IPs
        cursor_all_ips = conn.execute("SELECT id, ip FROM ip_addresses")
        ip_id_to_str = {str(r[0]): r[1].lower() for r in cursor_all_ips.fetchall()}

        for domain_id, ip_ids in domain_to_ips.items():
            if domain_id not in domains_to_spawn:
                if any(ip_id_to_str.get(str(ip_id)) in explicit_targets for ip_id in ip_ids):
                    domains_to_spawn.add(domain_id)"""

content = content.replace(target, replacement)
with open("web/api/graph_builder.py", "w") as f:
    f.write(content)
