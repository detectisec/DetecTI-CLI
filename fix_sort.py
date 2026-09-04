import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"        const placeChildren = \(parentId, children, baseX, tierX\) => \{\n            if \(\!children \|\| children\.length === 0\) return;\n            if \(visitedPlace\.has\(parentId\)\) return; // break cycle\n            visitedPlace\.add\(parentId\);"

new_logic = """        const placeChildren = (parentId, children, baseX, tierX) => {
            if (!children || children.length === 0) return;
            if (visitedPlace.has(parentId)) return; // break cycle
            visitedPlace.add(parentId);
            
            // SORT CHILDREN: nodes without children first, so they stay in the first columns (smaller X depth).
            // This prevents empty subdomains from being pushed deeper than resolved IPs in grid wrapping.
            children.sort((a, b) => {
                const countA = childrenMap[a.id()] ? childrenMap[a.id()].length : 0;
                const countB = childrenMap[b.id()] ? childrenMap[b.id()].length : 0;
                return countA - countB;
            });
"""

if re.search(pattern, content):
    new_content = re.sub(pattern, new_logic, content)
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Added sorting to placeChildren")
else:
    print("Regex failed to find placeChildren")
