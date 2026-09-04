import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

content = re.sub(r'currentTierDepth = maxT1Depth \+ 240;', r'currentTierDepth = maxT1Depth + 400;', content)
content = re.sub(r'currentTierDepth = maxT2Depth \+ 260;', r'currentTierDepth = maxT2Depth + 400;', content)
content = re.sub(r'currentTierDepth = maxT3Depth \+ 260;', r'currentTierDepth = maxT3Depth + 400;', content)
content = re.sub(r'currentTierDepth = maxT4Depth \+ 200;', r'currentTierDepth = maxT4Depth + 300;', content)

with open(file_path, "w") as f:
    f.write(content)
print("Base gaps increased")
