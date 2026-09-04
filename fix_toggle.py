import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_code = """        window.toggleLeadVisibility = async (nodeId, isChecked) => {
            if (isChecked) {
                this.selectedLeads.add(nodeId);
                await window.api.setTarget(nodeId.replace(/^(ip_|dom_|sub_)/, ''));
                await this.loadGraph(true);
            } else {
                this.selectedLeads.delete(nodeId);
                await window.api.removeTarget(nodeId.replace(/^(ip_|dom_|sub_)/, ''));
                await this.loadGraph(true);
            }"""

new_code = """        window.toggleLeadVisibility = async (nodeId, isChecked) => {
            const cleanId = nodeId.replace(/^(ip_|dom_|sub_)/, '');
            if (isChecked) {
                this.selectedLeads.add(nodeId);
                await this.setTarget(cleanId);
            } else {
                this.selectedLeads.delete(nodeId);
                await this.removeTarget(cleanId);
            }"""

if old_code in content:
    content = content.replace(old_code, new_code)
    with open(path, "w") as f:
        f.write(content)
    print("Replaced!")
else:
    print("Not found! Let's find what is there:")
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if "window.toggleLeadVisibility = " in line:
            print("\n".join(lines[i:i+15]))
