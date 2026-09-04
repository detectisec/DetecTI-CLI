import re
with open('web/static/js/graph.js', 'r') as f:
    content = f.read()

old_toggle = r'''        window\.toggleLeadVisibility = async \(nodeId, isChecked\) => \{
            if \(isChecked\) \{
                this\.selectedLeads\.add\(nodeId\);
                await window\.api\.setTarget\(nodeId\.replace\(/^\(ip_\|dom_\|sub_\)/, ''\)\);
                await this\.loadGraph\(true\);
            \} else \{
                this\.selectedLeads\.delete\(nodeId\);
                await window\.api\.removeTarget\(nodeId\.replace\(/^\(ip_\|dom_\|sub_\)/, ''\)\);
                await this\.loadGraph\(true\);
            \}'''
print("Match found:", bool(re.search(old_toggle, content)))
