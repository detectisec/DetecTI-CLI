import re

path = "web/api/graph_builder.py"
with open(path, "r") as f:
    content = f.read()

# 1. domain_name in explicit_targets -> domain_name.lower() in explicit_targets or str(domain_id) in explicit_targets
old1 = r'''            if domain_name\.lower\(\) in explicit_targets:'''
new1 = '''            if domain_name.lower() in explicit_targets or str(domain_id) in explicit_targets:'''
content = re.sub(old1, new1, content)

# 2. sub_info["name"] in explicit_targets -> sub_info["name"].lower() in explicit_targets or str(sub_id) in explicit_targets
old2 = r'''            if sub_info\["name"\]\.lower\(\) in explicit_targets:'''
new2 = '''            if sub_info["name"].lower() in explicit_targets or str(sub_id) in explicit_targets:'''
content = re.sub(old2, new2, content)

# 3. ip in explicit_targets -> ip in explicit_targets or str(ip_id) in explicit_targets
# Wait, for ip_ids in domain_to_ips:
# if any(ip_id_to_str.get(str(ip_id)) in explicit_targets for ip_id in ip_ids):
# change to: if any(ip_id_to_str.get(str(ip_id)) in explicit_targets or str(ip_id) in explicit_targets for ip_id in ip_ids):
old3 = r'''if any\(ip_id_to_str\.get\(str\(ip_id\)\) in explicit_targets for ip_id in ip_ids\):'''
new3 = '''if any(ip_id_to_str.get(str(ip_id)) in explicit_targets or str(ip_id) in explicit_targets for ip_id in ip_ids):'''
content = re.sub(old3, new3, content)

old3b = r'''elif any\(ip in explicit_targets for ip in sub_info\["ips"\]\):'''
new3b = '''elif any(ip in explicit_targets or str(ip_id) in explicit_targets for ip_id, ip in zip(sub_info.get("ip_ids", []), sub_info["ips"])):'''
# Wait, sub_info doesn't have ip_ids. I will just leave this one as is, since IPs can be matched by name. But wait, if they pass UUID of IP, it will fail here.
# Let's fix _build_ip_nodes instead:
old4 = r'''            visible_ip_nodes = \[n for n in ip_nodes if is_discovery or n\["data"\]\["ip"\]\.lower\(\) in targets_set\]'''
new4 = '''            visible_ip_nodes = [n for n in ip_nodes if is_discovery or n["data"]["ip"].lower() in targets_set or str(n["data"]["id"]).replace("ip_", "") in targets_set]'''
content = re.sub(old4, new4, content)

old5 = r'''            is_explicit_ip_tgt = bool\(ip and ip\.strip\(\)\.lower\(\) in targets_set\)'''
new5 = '''            is_explicit_ip_tgt = bool((ip and ip.strip().lower() in targets_set) or str(ip_id) in targets_set)'''
content = re.sub(old5, new5, content)

with open(path, "w") as f:
    f.write(content)
