import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

# Fix setTarget
old_set = r'''            if \(typeof this\.showToast === 'function'\) \{
                this\.showToast\('success', `Target set: \$\{target\}`\);
            \}
            await window\.api\.setTarget\(target\);'''

new_set = '''            const targetLower = target.toLowerCase();
            const matchingLead = this.leads.find(l => {
                const lName = (l.name || l.display_name || '').toLowerCase();
                const lId = (l.id || '').toLowerCase();
                return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
            });
            const displayName = matchingLead ? (matchingLead.name || matchingLead.display_name || matchingLead.label || target) : target;

            if (typeof this.showToast === 'function') {
                this.showToast('success', `Target set: ${displayName}`);
            }
            await window.api.setTarget(target);'''

content = re.sub(old_set, new_set, content)

# Fix removeTarget
old_remove = r'''            if \(typeof this\.showToast === 'function'\) \{
                this\.showToast\('info', `Target removed: \$\{target\}`\);
            \}
            await window\.api\.removeTarget\(target\);'''

new_remove = '''            const targetLower = target.toLowerCase();
            const matchingLead = this.leads.find(l => {
                const lName = (l.name || l.display_name || '').toLowerCase();
                const lId = (l.id || '').toLowerCase();
                return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
            });
            const displayName = matchingLead ? (matchingLead.name || matchingLead.display_name || matchingLead.label || target) : target;

            if (typeof this.showToast === 'function') {
                this.showToast('info', `Target removed: ${displayName}`);
            }
            await window.api.removeTarget(target);'''

content = re.sub(old_remove, new_remove, content)

with open(path, "w") as f:
    f.write(content)
