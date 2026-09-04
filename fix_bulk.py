import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

# Fix setTargetsBulk
old_code_bulk_set = r'''            await Promise\.all\(cleanTargets\.map\(t => window\.api\.setTarget\(t\)\)\);
            await this\.loadGraph\(true\);
        \} catch \(err\) \{'''

new_code_bulk_set = '''            await Promise.all(cleanTargets.map(t => window.api.setTarget(t)));
            await this.loadGraph(true);

            // Sync Lead Selector
            cleanTargets.forEach(target => {
                const targetLower = target.toLowerCase();
                const matchingLead = this.leads.find(l => {
                    const lName = (l.name || l.display_name || '').toLowerCase();
                    const lId = (l.id || '').toLowerCase();
                    return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
                });
                if (matchingLead) {
                    this.selectedLeads.add(matchingLead.id);
                }
            });
            this.applyLeadFilter({ relayout: true });
            this.renderLeadSelector();
        } catch (err) {'''
content = re.sub(old_code_bulk_set, new_code_bulk_set, content)

# Fix removeTargetsBulk
old_code_bulk_remove = r'''            await Promise\.all\(cleanTargets\.map\(t => window\.api\.removeTarget\(t\)\)\);
            await this\.loadGraph\(true\);
        \} catch \(err\) \{'''

new_code_bulk_remove = '''            await Promise.all(cleanTargets.map(t => window.api.removeTarget(t)));
            await this.loadGraph(true);

            // Sync Lead Selector
            cleanTargets.forEach(target => {
                const targetLower = target.toLowerCase();
                const matchingLead = this.leads.find(l => {
                    const lName = (l.name || l.display_name || '').toLowerCase();
                    const lId = (l.id || '').toLowerCase();
                    return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
                });
                if (matchingLead) {
                    this.selectedLeads.delete(matchingLead.id);
                }
            });
            this.applyLeadFilter({ relayout: true });
            this.renderLeadSelector();
        } catch (err) {'''
content = re.sub(old_code_bulk_remove, new_code_bulk_remove, content)

with open(path, "w") as f:
    f.write(content)
