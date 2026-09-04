import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_code = r'''        // Core \(Canvas\) Right-Click Handler
        this\.cy\.on\('cxttap', 'core', \(event\) => \{
            const originalEvent = event\.originalEvent;
            if \(originalEvent\) \{
                originalEvent\.preventDefault\(\);
                originalEvent\.stopPropagation\(\);
            \}'''

new_code = '''        // Core (Canvas) Right-Click Handler
        this.cy.on('cxttap', (event) => {
            if (event.target !== this.cy) return;
            const originalEvent = event.originalEvent;
            if (originalEvent) {
                originalEvent.preventDefault();
                originalEvent.stopPropagation();
            }'''

content = re.sub(old_code, new_code, content)
with open(path, "w") as f:
    f.write(content)
