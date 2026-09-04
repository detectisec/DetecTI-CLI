import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"        const heightCache = \{\};\n        const getRequiredHeight = \(node\) => \{"
new_logic = """        const heightCache = {};
        const visitedHeights = new Set();
        const getRequiredHeight = (node) => {
            if (heightCache[node.id()]) return heightCache[node.id()];
            if (visitedHeights.has(node.id())) return 180; // break cycle
            visitedHeights.add(node.id());
"""
content = re.sub(pattern, new_logic, content)

pattern2 = r"        // Top-down placement\n        const placeChildren = \(parentId, children, baseX, tierX\) => \{"
new_logic2 = """        // Top-down placement
        const visitedPlace = new Set();
        const placeChildren = (parentId, children, baseX, tierX) => {
            if (!children || children.length === 0) return;
            if (visitedPlace.has(parentId)) return; // break cycle
            visitedPlace.add(parentId);
"""
content = re.sub(pattern2, new_logic2, content)

with open(file_path, "w") as f:
    f.write(content)
print("Recursion protected!")
