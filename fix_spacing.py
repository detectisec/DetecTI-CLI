import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

# Tier 1 Domains: spacing 400 -> 12000
content = re.sub(r'const y = \(row - \(t1Rows - 1\) / 2\) \* 400;', r'const y = (row - (t1Rows - 1) / 2) * 12000;', content)

# Tier 2 Subdomains: spacing 200 -> 3000
content = re.sub(r'const y = positions\[pid\]\.y \+ getGridCenterOffset\(total, 10, row, 200\);', r'const y = positions[pid].y + getGridCenterOffset(total, 10, row, 3000);', content)
content = re.sub(r'const y = getGridCenterOffset\(t2TotalOrphans, 10, row, 200\);', r'const y = getGridCenterOffset(t2TotalOrphans, 10, row, 3000);', content)

# Tier 3 IPs: spacing 200 -> 800
content = re.sub(r'const y = positions\[pid\]\.y \+ getGridCenterOffset\(total, 10, row, 200\);', r'const y = positions[pid].y + getGridCenterOffset(total, 10, row, 800);', content)
content = re.sub(r'const y = getGridCenterOffset\(t3TotalOrphans, 10, row, 200\);', r'const y = getGridCenterOffset(t3TotalOrphans, 10, row, 800);', content)

# Tier 4 Services: spacing 160 -> 250
content = re.sub(r'const y = positions\[pid\]\.y \+ getGridCenterOffset\(total, 10, row, 160\);', r'const y = positions[pid].y + getGridCenterOffset(total, 10, row, 250);', content)

# Tier 5 Vulns: spacing 140 -> 140 is fine
# Let's verify Tier 5 was untouched by keeping it 140.

# Also, horizontal depth (X) spacing should be increased slightly to avoid long label overlapping
# Tier 2 depth: 220 -> 400
# Tier 3 depth: 220 -> 400
# Tier 4 depth: 100 -> 300
# Tier 5 depth: 80 -> 250

content = re.sub(r'const x = currentTierDepth \+ \(col \* 220\);', r'const x = currentTierDepth + (col * 400);', content)
content = re.sub(r'const x = currentTierDepth \+ \(col \* 100\);', r'const x = currentTierDepth + (col * 300);', content)
content = re.sub(r'const x = currentTierDepth \+ \(col \* 80\);', r'const x = currentTierDepth + (col * 250);', content)

with open(file_path, "w") as f:
    f.write(content)
print("Spaced perfectly")
