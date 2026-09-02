import re

with open("web/api/graph_builder.py", "r") as f:
    content = f.read()

replacement = """
        # Also check apex domains for targeted IPs
        for domain_id, ip_ids in domain_to_ips.items():
            if domain_id not in domains_to_spawn:
                # To check this efficiently without full IP lookup, we can query or match explicit_targets
                # Wait, domain_to_ips maps domain_id -> set of IP IDs. 
                # explicit_targets contains strings like "192.168.1.1".
                # We already know which subdomains to spawn because sub_info contains the literal "ips" list.
                # For domains, we don't have the literal IPs list in this loop easily.
                pass # Let's fetch IP strings for domain_to_ips
        
        # Build IP ID to IP String mapping to resolve domain_to_ips
        cursor_all_ips = conn.execute("SELECT id, ip FROM ip_addresses")
        ip_id_to_str = {str(r[0]): r[1].lower() for r in cursor_all_ips.fetchall()}

        for domain_id, ip_ids in domain_to_ips.items():
            if domain_id not in domains_to_spawn:
                if any(ip_id_to_str.get(str(ip_id)) in explicit_targets for ip_id in ip_ids):
                    domains_to_spawn.add(domain_id)
"""

pattern = re.compile(r'        # Also check apex domains for targeted IPs.*?# We will handle apex IPs in _build_ip_nodes if needed, but usually explicit_targets has IPs as strings\.\n                pass', re.DOTALL)
new_content = pattern.sub(replacement.strip(), content)

with open("web/api/graph_builder.py", "w") as f:
    f.write(new_content)
