import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_code = r'''            if \(typeof this\.showToast === 'function'\) \{
                this\.showToast\('info', `Target removed: \$\{target\}`\);
            \}
            await window\.api\.removeTarget\(target\);
            await this\.loadGraph\(true\);
        \} catch \(err\) \{'''

new_code = '''            if (typeof this.showToast === 'function') {
                this.showToast('info', `Target removed: ${target}`);
            }
            await window.api.removeTarget(target);
            await this.loadGraph(true);

            // Automatically deactivate the removed target in the Lead Selector
            const targetLower = target.toLowerCase();
            const matchingLead = this.leads.find(l => {
                const lName = (l.name || l.display_name || '').toLowerCase();
                const lId = (l.id || '').toLowerCase();
                return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
            });
            if (matchingLead) {
                this.selectedLeads.delete(matchingLead.id);
                this.applyLeadFilter({ relayout: true });
                this.renderLeadSelector();
            }
        } catch (err) {'''

content = re.sub(old_code, new_code, content)
with open(path, "w") as f:
    f.write(content)
