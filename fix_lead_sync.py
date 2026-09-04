import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

# Fix populateLeadSelector auto-selection
old_select = r'''            if \(!preserveSelection\) \{
                this\.selectedLeads\.clear\(\);
                
                // Auto-select ONLY Tier 1 targets if their total is <= 50 to prevent blank graphs
                const tier1Leads = this\.leads\.filter\(l => l\.is_tier1\);
                if \(tier1Leads\.length > 0 && tier1Leads\.length <= 50\) \{
                    tier1Leads\.forEach\(lead => this\.selectedLeads\.add\(lead\.id\)\);
                \}
            \}'''

new_select = '''            if (!preserveSelection) {
                this.selectedLeads.clear();
                
                // Auto-select leads that are already marked as targets in the backend
                this.leads.forEach(lead => {
                    const cleanId = lead.id.replace(/^(ip_|dom_|sub_)/, '');
                    if (this.markedTargets.has(cleanId)) {
                        this.selectedLeads.add(lead.id);
                    }
                });
                
                // If no targets were selected from backend, fallback to Tier 1
                if (this.selectedLeads.size === 0) {
                    const tier1Leads = this.leads.filter(l => l.is_tier1);
                    if (tier1Leads.length > 0 && tier1Leads.length <= 50) {
                        tier1Leads.forEach(lead => this.selectedLeads.add(lead.id));
                    }
                }
            }'''
content = re.sub(old_select, new_select, content)

# Fix toggleLeadVisibility to call this.setTarget and this.removeTarget
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

new_toggle = '''        window.toggleLeadVisibility = async (nodeId, isChecked) => {
            const cleanId = nodeId.replace(/^(ip_|dom_|sub_)/, '');
            if (isChecked) {
                this.selectedLeads.add(nodeId);
                await this.setTarget(cleanId);
            } else {
                this.selectedLeads.delete(nodeId);
                await this.removeTarget(cleanId);
            }'''
content = re.sub(old_toggle, new_toggle, content)

with open(path, "w") as f:
    f.write(content)
