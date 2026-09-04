import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_code = r'''        const targetsHtml = Array\.from\(this\.markedTargets\)\.map\(ip => \{
            const statusObj = this\.targetStatuses\[ip\] \|\| \{ status: 'idle', nuclei_status: 'idle', ports_count: 0 \};'''

new_code = '''        const targetsHtml = Array.from(this.markedTargets).map(ip => {
            const statusObj = this.targetStatuses[ip] || { status: 'idle', nuclei_status: 'idle', ports_count: 0 };
            
            let displayName = ip;
            if (this.leads && Array.isArray(this.leads)) {
                const lead = this.leads.find(l => l.id.replace(/^(ip_|dom_|sub_)/, '') === ip);
                if (lead) displayName = lead.display_name || lead.label || ip;
            } else if (this.nodeIndex) {
                const node = this.nodeIndex.get(`ip_${ip}`) || this.nodeIndex.get(`dom_${ip}`) || this.nodeIndex.get(`sub_${ip}`);
                if (node) displayName = node.display_name || node.label || node.name || node.ip || ip;
            }'''

content = re.sub(old_code, new_code, content)

# Now find where it displays `ip` and replace it with `displayName`
# <span class="target-card-ip">${ip}</span>
old_display = r'''<span class="target-card-ip">\$\{ip\}</span>'''
new_display = '''<span class="target-card-ip">${displayName}</span>'''
content = re.sub(old_display, new_display, content)

# Also fix the `removeTarget` onclick inside the html
# <button class="target-action-btn delete" onclick="window.dashboard.removeTargetsBulk(['${ip}'])" title="Remove from Target List">
# Wait, this is fine because it passes the UUID (`ip`) back to the function, which is correct!

with open(path, "w") as f:
    f.write(content)
