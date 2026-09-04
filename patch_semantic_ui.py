import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

# 1. Change "Expand All Leads" context menu to "Target All Leads"
content = content.replace("label: 'Expand All Leads'", "label: 'Target All Leads'")

# 2. Update renderLeadSelector HTML
old_html = r'''            leadItem\.innerHTML = `
                <input type="checkbox" id="chk_\$\{lead\.id\}" class="lead-checkbox-input" style="margin-top: 0\.25rem; cursor: pointer;">
                <div class="lead-info">
                    <div class="lead-header">
                        <label for="chk_\$\{lead\.id\}" class="lead-name" style="cursor: pointer;">\$\{lead\.display_name\}</label>
                        <div class="lead-type \$\{lead\.type\}">\$\{lead\.type\.toUpperCase\(\)\}</div>
                    </div>
                    <div class="lead-badges">\$\{badges\.join\(''\)\}</div>
                    <div class="lead-stats">\$\{stats\}</div>
                </div>
                <div class="lead-risk-indicator \$\{riskClass\}"></div>
            `;'''

new_html = '''            const isSelected = this.selectedLeads.has(lead.id);
            const iconName = isSelected ? 'check-circle' : 'crosshair';
            const iconColor = isSelected ? '#10b981' : '#64748b';
            
            leadItem.innerHTML = `
                <div class="lead-target-btn" style="cursor: pointer; margin-right: 10px; display: flex; align-items: center; justify-content: center; color: ${iconColor};">
                    <i data-lucide="${iconName}" style="width: 18px; height: 18px;"></i>
                </div>
                <div class="lead-info" style="flex: 1;">
                    <div class="lead-header">
                        <span class="lead-name" style="cursor: pointer; font-weight: 500;">${lead.display_name}</span>
                        <div class="lead-type ${lead.type}">${lead.type.toUpperCase()}</div>
                    </div>
                    <div class="lead-badges">${badges.join('')}</div>
                    <div class="lead-stats">${stats}</div>
                </div>
                <div class="lead-risk-indicator ${riskClass}"></div>
            `;'''

content = re.sub(old_html, new_html, content)

# 3. Update event listeners for the new icon
old_listeners = r'''            // Prevent event bubbling when clicking the checkbox directly
            const checkbox = leadItem\.querySelector\('\.lead-checkbox-input'\);
            checkbox\.addEventListener\('click', \(e\) => \{
                e\.stopPropagation\(\);
                window\.toggleLeadVisibility\(lead\.id, checkbox\.checked\);
            \}\);

            leadItem\.addEventListener\('click', \(e\) => \{
                if \(e\.target !== checkbox && e\.target\.tagName !== 'LABEL'\) \{
                    checkbox\.checked = !checkbox\.checked;
                    window\.toggleLeadVisibility\(lead\.id, checkbox\.checked\);
                \}
            \}\);

            // Set initial state
            if \(this\.selectedLeads\.has\(lead\.id\)\) \{
                checkbox\.checked = true;
                leadItem\.classList\.add\('selected'\);
            \}'''

new_listeners = '''            const toggleBtn = leadItem.querySelector('.lead-target-btn');
            
            const handleToggle = (e) => {
                e.stopPropagation();
                const currentlySelected = this.selectedLeads.has(lead.id);
                const willBeSelected = !currentlySelected;
                
                // Optimistic UI update
                if (willBeSelected) {
                    leadItem.classList.add('selected');
                    toggleBtn.style.color = '#10b981';
                    toggleBtn.innerHTML = '<i data-lucide="check-circle" style="width: 18px; height: 18px;"></i>';
                } else {
                    leadItem.classList.remove('selected');
                    toggleBtn.style.color = '#64748b';
                    toggleBtn.innerHTML = '<i data-lucide="crosshair" style="width: 18px; height: 18px;"></i>';
                }
                if (typeof lucide !== 'undefined') lucide.createIcons({ root: toggleBtn });
                
                window.toggleLeadVisibility(lead.id, willBeSelected);
            };

            toggleBtn.addEventListener('click', handleToggle);
            leadItem.addEventListener('click', (e) => {
                // Ignore clicks on buttons/links inside the item (if any are added later)
                if (e.target.closest('a') || e.target.closest('button')) return;
                handleToggle(e);
            });

            // Set initial state
            if (this.selectedLeads.has(lead.id)) {
                leadItem.classList.add('selected');
            }'''

content = re.sub(old_listeners, new_listeners, content)

# 4. In window.toggleLeadVisibility, remove UI updates since we do it optimistically
old_toggle_ui = r'''            // Update UI
            const leadItem = document\.querySelector\(`\[data-lead-id="\$\{nodeId\}"\]`\);
            if \(leadItem\) \{
                if \(isChecked\) \{
                    leadItem\.classList\.add\('selected'\);
                \} else \{
                    leadItem\.classList\.remove\('selected'\);
                \}
                const checkbox = leadItem\.querySelector\('\.lead-checkbox-input'\);
                if \(checkbox && checkbox\.checked !== isChecked\) \{
                    checkbox\.checked = isChecked;
                \}
            \}'''
            
new_toggle_ui = '''            // UI is updated optimistically before this is called'''
content = re.sub(old_toggle_ui, new_toggle_ui, content)

# 5. selectAllLeads
old_select_all = r'''    async selectAllLeads\(\) \{
        const ids = \[\];
        this\.leads\.forEach\(lead => \{
            this\.selectedLeads\.add\(lead\.id\);
            ids\.push\(lead\.id\);
            const leadItem = document\.querySelector\(`\[data-lead-id="\$\{lead\.id\}"\]`\);
            if \(leadItem\) \{
                leadItem\.classList\.add\('selected'\);
                const checkbox = leadItem\.querySelector\('\.lead-checkbox-input'\);
                if \(checkbox\) checkbox\.checked = true;
            \}
        \}\);
        await this\.setTargetsBulk\(ids\);
        this\.applyLeadFilter\(\{ relayout: true \}\);
    \}'''
new_select_all = '''    async selectAllLeads() {
        const ids = [];
        this.leads.forEach(lead => {
            if (!this.selectedLeads.has(lead.id)) {
                this.selectedLeads.add(lead.id);
                ids.push(lead.id);
            }
        });
        await this.setTargetsBulk(ids);
        this.renderLeadSelector(); // Re-render to update icons
        this.applyLeadFilter({ relayout: true });
    }'''
content = re.sub(old_select_all, new_select_all, content)

# 6. deselectAllLeads
old_deselect_all = r'''    async deselectAllLeads\(\) \{
        const ids = Array\.from\(this\.selectedLeads\);
        this\.selectedLeads\.clear\(\);
        document\.querySelectorAll\('\.lead-item'\)\.forEach\(item => \{
            item\.classList\.remove\('selected'\);
            const checkbox = item\.querySelector\('\.lead-checkbox-input'\);
            if \(checkbox\) checkbox\.checked = false;
        \}\);
        await this\.removeTargetsBulk\(ids\);
        this\.applyLeadFilter\(\{ relayout: true \}\);
    \}'''
new_deselect_all = '''    async deselectAllLeads() {
        const ids = Array.from(this.selectedLeads);
        this.selectedLeads.clear();
        await this.removeTargetsBulk(ids);
        this.renderLeadSelector(); // Re-render to update icons
        this.applyLeadFilter({ relayout: true });
    }'''
content = re.sub(old_deselect_all, new_deselect_all, content)

with open(path, "w") as f:
    f.write(content)
