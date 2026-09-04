import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"                if \(\!positions\[c\.id\(\)\]\) \{ positions\[c\.id\(\)\] = \{ x, y \}; placeChildren\(c\.id\(\), childrenMap\[c\.id\(\)\], x, nextTierX\); \}\n                \n                // Recursively place this child's children\n                let nextTierX = x \+ 400; // rough guess based on tier, we can refine\n                if \(tierX >= X_SPACINGS\.t4\) nextTierX = x \+ 300;\n                placeChildren\(c\.id\(\), childrenMap\[c\.id\(\)\], x, nextTierX\);"

new_logic = """                if (!positions[c.id()]) {
                    positions[c.id()] = { x, y };
                    // Recursively place this child's children
                    let nextTierX = x + 400; // rough guess based on tier, we can refine
                    if (tierX >= X_SPACINGS.t4) nextTierX = x + 300;
                    placeChildren(c.id(), childrenMap[c.id()], x, nextTierX);
                }"""

if re.search(pattern, content):
    new_content = re.sub(pattern, new_logic, content)
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Fixed placeChildren syntax!")
else:
    print("Regex failed to find block")
