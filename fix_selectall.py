import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_select_all = r'''    selectAllLeads\(\) \{
        this\.leads\.forEach\(lead => \{
            this\.selectedLeads\.add\(lead\.id\);
            const leadItem = document\.querySelector\(`\[data-lead-id="\$\{lead\.id\}"\]`\);
            if \(leadItem\) \{
                leadItem\.classList\.add\('selected'\);
                const checkbox = leadItem\.querySelector\('\.lead-checkbox-input'\);
                if \(checkbox\) checkbox\.checked = true;
            \}
        \}\);
        this\.applyLeadFilter\(\{ relayout: true \}\);
    \}'''

new_select_all = '''    async selectAllLeads() {
        const ids = [];
        this.leads.forEach(lead => {
            this.selectedLeads.add(lead.id);
            ids.push(lead.id);
            const leadItem = document.querySelector(`[data-lead-id="${lead.id}"]`);
            if (leadItem) {
                leadItem.classList.add('selected');
                const checkbox = leadItem.querySelector('.lead-checkbox-input');
                if (checkbox) checkbox.checked = true;
            }
        });
        await this.setTargetsBulk(ids);
        this.applyLeadFilter({ relayout: true });
    }'''

content = re.sub(old_select_all, new_select_all, content)

old_deselect_all = r'''    deselectAllLeads\(\) \{
        this\.selectedLeads\.clear\(\);
        document\.querySelectorAll\('\.lead-item'\)\.forEach\(item => \{
            item\.classList\.remove\('selected'\);
            const checkbox = item\.querySelector\('\.lead-checkbox-input'\);
            if \(checkbox\) checkbox\.checked = false;
        \}\);
        this\.applyLeadFilter\(\{ relayout: true \}\);
    \}'''

new_deselect_all = '''    async deselectAllLeads() {
        const ids = Array.from(this.selectedLeads);
        this.selectedLeads.clear();
        document.querySelectorAll('.lead-item').forEach(item => {
            item.classList.remove('selected');
            const checkbox = item.querySelector('.lead-checkbox-input');
            if (checkbox) checkbox.checked = false;
        });
        await this.removeTargetsBulk(ids);
        this.applyLeadFilter({ relayout: true });
    }'''

content = re.sub(old_deselect_all, new_deselect_all, content)

with open(path, "w") as f:
    f.write(content)
