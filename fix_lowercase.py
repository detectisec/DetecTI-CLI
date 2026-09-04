import re

path = "web/api/graph_builder.py"
with open(path, "r") as f:
    content = f.read()

content = content.replace("str(domain_id) in explicit_targets", "str(domain_id).lower() in explicit_targets")
content = content.replace("str(sub_id) in explicit_targets", "str(sub_id).lower() in explicit_targets")
content = content.replace("str(ip_id) in explicit_targets", "str(ip_id).lower() in explicit_targets")
content = content.replace('str(n["data"]["id"]).replace("ip_", "") in explicit_targets', 'str(n["data"]["id"]).replace("ip_", "").lower() in explicit_targets')

with open(path, "w") as f:
    f.write(content)
