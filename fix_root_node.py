import re

path = "web/api/graph_builder.py"
with open(path, "r") as f:
    content = f.read()

old_code = r'''            root_target_node = \{
                "data": \{
                    "id": "target_root",
                    "label": target_name,
                    "type": "target",
                    "name": target_name,
                    "target_type": target_type or "query",
                    "targets_list": targets_list,
                    "is_root": True
                \}
            \}'''

new_code = '''        root_target_node = {
            "data": {
                "id": "target_root",
                "label": target_name or "Target Root",
                "type": "target",
                "name": target_name or "Target Root",
                "target_type": target_type or "query",
                "targets_list": targets_list,
                "is_root": True
            }
        }'''

content = re.sub(old_code, new_code, content)
with open(path, "w") as f:
    f.write(content)
