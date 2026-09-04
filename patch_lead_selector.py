import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

target = """            // Reset lead selection on initial database load (leads come unchecked by default)
            // But preserve active leads when refreshing after a background scan
            if (!preserveSelection) {
                this.selectedLeads.clear();
            } else {"""

replacement = """            // Reset lead selection on initial database load (leads come unchecked by default)
            // But preserve active leads when refreshing after a background scan
            if (!preserveSelection) {
                this.selectedLeads.clear();
                
                // Auto-select leads if total is <= 50 to prevent blank graphs on small datasets
                if (this.leads.length > 0 && this.leads.length <= 50) {
                    this.leads.forEach(lead => this.selectedLeads.add(lead.id));
                }
            } else {"""

content = content.replace(target, replacement)

# Bump version in index.html
with open("web/static/index.html", "r") as f:
    index_content = f.read()
    
index_content = re.sub(r"graph\.js\?v=\d+", "graph.js?v=66", index_content)

with open("web/static/index.html", "w") as f:
    f.write(index_content)
    
with open("web/static/js/graph.js", "w") as f:
    f.write(content)
