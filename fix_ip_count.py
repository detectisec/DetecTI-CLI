import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"            outgoers\.forEach\(child => \{\n                if \(child\.data\('type'\) === 'ip'\) \{\n                    ipNodes\.push\(child\);\n                \}"

new_logic = """            outgoers.forEach(child => {
                if (child.data('type') === 'ip') {
                    if (!visited.has(child.id())) {
                        ipNodes.push(child);
                        visited.add(child.id());
                    }
                }"""

if re.search(pattern, content):
    new_content = re.sub(pattern, new_logic, content)
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Fixed IP counting bug!")
else:
    print("Regex failed to find IP counting block")
