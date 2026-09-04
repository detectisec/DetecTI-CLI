import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

# Fix setTarget
old_set = r'''            await window\.api\.setTarget\(target\);
            await this\.loadGraph\(true\);

            // Automatically activate the newly set target in the Lead Selector so it immediately renders
            const targetLower = target\.toLowerCase\(\);
            const matchingLead = this\.leads\.find\(l => \{
                const lName = \(l\.name \|\| l\.display_name \|\| ''\)\.toLowerCase\(\);
                const lId = \(l\.id \|\| ''\)\.toLowerCase\(\);
                return lName === targetLower \|\| lId === targetLower \|\| lId === `dom_\$\{targetLower\}` \|\| lId === `sub_\$\{targetLower\}` \|\| lId === `ip_\$\{targetLower\}`;
            \}\);
            if \(matchingLead\) \{'''

new_set = '''            await window.api.setTarget(target);
            await this.loadGraph(true);

            // Automatically activate the newly set target in the Lead Selector so it immediately renders
            if (matchingLead) {'''
content = re.sub(old_set, new_set, content)

# Fix removeTarget
old_remove = r'''            await window\.api\.removeTarget\(target\);
            await this\.loadGraph\(true\);

            // Automatically deactivate the removed target in the Lead Selector
            const targetLower = target\.toLowerCase\(\);
            const matchingLead = this\.leads\.find\(l => \{
                const lName = \(l\.name \|\| l\.display_name \|\| ''\)\.toLowerCase\(\);
                const lId = \(l\.id \|\| ''\)\.toLowerCase\(\);
                return lName === targetLower \|\| lId === targetLower \|\| lId === `dom_\$\{targetLower\}` \|\| lId === `sub_\$\{targetLower\}` \|\| lId === `ip_\$\{targetLower\}`;
            \}\);
            if \(matchingLead\) \{'''

new_remove = '''            await window.api.removeTarget(target);
            await this.loadGraph(true);

            // Automatically deactivate the removed target in the Lead Selector
            if (matchingLead) {'''
content = re.sub(old_remove, new_remove, content)

with open(path, "w") as f:
    f.write(content)
