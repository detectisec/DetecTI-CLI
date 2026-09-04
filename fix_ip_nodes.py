import re

path = "web/api/graph_builder.py"
with open(path, "r") as f:
    content = f.read()

# Fix the overwritten explicit_targets in _build_ip_nodes
old_code = r'''        explicit_targets = set\(t\.strip\(\)\.lower\(\) for t in targets_list\) if targets_list else set\(\)
        if explicit_targets:
            explicit_targets\.update\(explicit_targets\)'''

new_code = '''        targets_set = set(t.strip().lower() for t in targets_list) if targets_list else set()
        if explicit_targets:
            targets_set.update(explicit_targets)'''
content = re.sub(old_code, new_code, content)

# Also fix the line 467:
old_is_explicit = r'''            is_explicit_ip_tgt = bool\(ip and ip\.strip\(\)\.lower\(\) in explicit_targets\)'''
new_is_explicit = '''            is_explicit_ip_tgt = bool(ip and ip.strip().lower() in targets_set)'''
content = re.sub(old_is_explicit, new_is_explicit, content)

with open(path, "w") as f:
    f.write(content)
