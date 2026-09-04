import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"""                // CRITICAL FIX: IPs must be placed relative to their specific parent's X coordinate!
                targetX = positions\[pid\]\.x \+ 220;
                
                const srvCount = srvsByIp\.get\(node\.id\(\)\) \? srvsByIp\.get\(node\.id\(\)\)\.length : 0;
                const sRows = Math\.min\(Math\.max\(1, srvCount\), 3\);
                const reqHeight = Math\.max\(200, sRows \* 180\);
                
                baseY = positions\[pid\]\.y \+ \(parentOffsets\[pid\] \* reqHeight\);
                parentOffsets\[pid\]\+\+;"""

new_logic = """                const offset = parentOffsets[pid];
                const col = Math.floor(offset / 10);
                const row = offset % 10;
                
                // CRITICAL FIX: Wrap every 10 items into a new pseudo-tier block to prevent massive linear stretching
                targetX = positions[pid].x + 220 + (col * 220);
                
                const srvCount = srvsByIp.get(node.id()) ? srvsByIp.get(node.id()).length : 0;
                const sRows = Math.min(Math.max(1, srvCount), 3);
                const reqHeight = Math.max(200, sRows * 180);
                
                // Center the block relative to parent based on the max items in this column
                // Wait, previously we just added from parent.y. To keep it simple and consistent:
                baseY = positions[pid].y + (row * reqHeight);
                parentOffsets[pid]++;"""

if re.search(pattern, content):
    new_content = re.sub(pattern, new_logic, content)
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Patched wrapping logic successfully")
else:
    print("Could not find the block")
