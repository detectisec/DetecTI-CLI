import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_code = r'''            \} else \{
                // Physics-based layouts \(cose, cose-bilkent, etc\.\)
                const layout = target\.layout\(\{
                    \.\.\.layoutOptions,
                    name: layoutOptions\.name \|\| layoutName,
                    fit: true,
                    padding: 40,
                    animate: true,
                    animationDuration: 650,
                    animationEasing: 'ease-in-out'
                \}\);'''

new_code = '''            } else {
                // Physics-based layouts (cose, cose-bilkent, etc.)
                // Force randomize: false so it uses current positions and just smoothly applies gravity/repulsion
                const layout = target.layout({
                    ...layoutOptions,
                    name: layoutOptions.name || layoutName,
                    fit: true,
                    padding: 40,
                    randomize: false,
                    animate: true,
                    animationDuration: 1000,
                    animationEasing: 'ease-out-cubic'
                });'''

content = re.sub(old_code, new_code, content)
with open(path, "w") as f:
    f.write(content)
