import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/api/graph_builder.py"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"            has_visible_fqdn_parent = str\(ip_id\) in ips_resolved_by_visible_fqdns\n            should_connect_root_to_ip = \(is_explicit_ip_tgt or is_query_discovery\) and not has_visible_fqdn_parent"

new_logic = """            has_visible_fqdn_parent = str(ip_id) in ips_resolved_by_visible_fqdns
            # Always connect to target_root if the IP has no FQDN parent, so it doesn't float!
            should_connect_root_to_ip = not has_visible_fqdn_parent"""

if re.search(pattern, content):
    new_content = re.sub(pattern, new_logic, content)
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Fixed IP root connection logic!")
else:
    print("Regex failed to find root connection logic")
