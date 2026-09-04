file_path = "/home/ls4ss/dev/DetecTI-CLI/web/api/graph_builder.py"
with open(file_path, "r") as f:
    lines = f.readlines()

new_lines = []
skip = False
for line in lines:
    if "connected_ip_ids =" in line:
        new_lines.append('            connected_ip_ids = {n["data"]["id"] for n in ip_nodes}\n')
        skip = True
    elif skip and "}" in line and "startswith" in line:
        continue
    elif skip and "}" in line:
        skip = False
    elif not skip:
        new_lines.append(line)

with open(file_path, "w") as f:
    f.writelines(new_lines)
print("Fixed successfully")
