import re

path = "web/api/graph_builder.py"
with open(path, "r") as f:
    content = f.read()

old_block = r'''            def _normalize_target_item\(t: str\) -> str:
                t = str\(t\)\.strip\(\)\.lower\(\)
                if t\.startswith\("http://"\):
                    t = t\[7:\]
                elif t\.startswith\("https://"\):
                    t = t\[8:\]
                if "/" in t:
                    t = t\.split\("/"\)\[0\]
                if ":" in t:
                    if t\.startswith\("\["\) and "\]" in t:
                        # Handle IPv6 with port: \[2001:db8::1\]:80 -> 2001:db8::1
                        t = t\.split\("\]"\)\[0\]\[1:\]
                    elif t\.count\(":"\) == 1:
                        # Handle IPv4 or Domain with port: 192\.168\.1\.1:80 -> 192\.168\.1\.1
                        t = t\.split\(":"\)\[0\]
                    # If count > 1 and no brackets, it's a raw IPv6 \(e\.g\. 2001:db8::1\), leave as is\.
                return t

            explicit_targets = \{_normalize_target_item\(t\) for t in targets_list if _normalize_target_item\(t\)\}
            if active_targets:
                for at in active_targets:
                    norm = _normalize_target_item\(at\)
                    if norm:
                        explicit_targets\.add\(norm\)'''

new_block = '''        def _normalize_target_item(t: str) -> str:
            t = str(t).strip().lower()
            if t.startswith("http://"):
                t = t[7:]
            elif t.startswith("https://"):
                t = t[8:]
            if "/" in t:
                t = t.split("/")[0]
            if ":" in t:
                if t.startswith("[") and "]" in t:
                    t = t.split("]")[0][1:]
                elif t.count(":") == 1:
                    t = t.split(":")[0]
            return t

        explicit_targets = {_normalize_target_item(t) for t in targets_list if _normalize_target_item(t)}
        if active_targets:
            for at in active_targets:
                norm = _normalize_target_item(at)
                if norm:
                    explicit_targets.add(norm)'''

content = re.sub(old_block, new_block, content)
with open(path, "w") as f:
    f.write(content)
