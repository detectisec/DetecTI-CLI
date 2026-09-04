import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_code_bulk_set = r'''            this\.updateTargetBadgeCount\(\);
            this\.renderTargetsList\(\);
            if \(typeof this\.showToast === 'function'\) \{'''

new_code_bulk_set = '''            this.updateTargetBadgeCount();
            this.renderTargetsList();
            if (this.selectedNode) {
                this.showNodeInspector(this.selectedNode);
            }
            if (typeof this.showToast === 'function') {'''
content = re.sub(old_code_bulk_set, new_code_bulk_set, content)

with open(path, "w") as f:
    f.write(content)
