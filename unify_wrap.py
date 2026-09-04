file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

import re

# Tier 4 Services
content = re.sub(r'const col = Math\.floor\(offset / 3\);', r'const col = Math.floor(offset / 10);', content)
content = re.sub(r'const row = offset % 3;', r'const row = offset % 10;', content)
# We should also adjust the Y centering so it matches the 10-item block.
# (row - 4.5) * 160 instead of (row * 160) - 160
content = re.sub(r'const y = positions\[pid\]\.y \+ \(row \* 160\) - 160;', r'const y = positions[pid].y + (row * 160) - 720;', content)

# Tier 5 Vulns
content = re.sub(r'const col = Math\.floor\(offset / 2\);', r'const col = Math.floor(offset / 10);', content)
content = re.sub(r'const row = offset % 2;', r'const row = offset % 10;', content)
# (row - 4.5) * 140
content = re.sub(r'const y = positions\[pid\]\.y \+ \(row \* 140\) - 70;', r'const y = positions[pid].y + (row * 140) - 630;', content)

with open(file_path, "w") as f:
    f.write(content)
print("Unified wrapping to 10 for all tiers!")
