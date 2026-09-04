import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_code = r'''    deselectAllLeads\(\) \{
        this\.selectedLeads\.clear\(\);
        document\.querySelectorAll\('\.lead-item'\)\.forEach\(item => \{
            item\.classList\.remove\('selected'\);
            const checkbox = item\.querySelector\('\.lead-checkbox-input'\);
            if \(checkbox\) checkbox\.checked = false;
        \}\);
        this\.applyLeadFilter\(\{ relayout: false \}\);
    \}'''

new_code = '''    async deselectAllLeads() {
        const ids = Array.from(this.selectedLeads);
        this.selectedLeads.clear();
        await this.removeTargetsBulk(ids);
        this.renderLeadSelector();
        this.applyLeadFilter({ relayout: true });
    }'''

content = re.sub(old_code, new_code, content)
with open(path, "w") as f:
    f.write(content)
