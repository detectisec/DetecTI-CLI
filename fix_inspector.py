import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

# Fix IP Bulk target
old_ip = r'''                if \(allIps\.length > 0\) \{
                    const ipStrings = allIps\.map\(item => item\.ip\);
                    const allMarked = ipStrings\.length > 0 && ipStrings\.every\(ip => this\.isTargetMarked\(ip\)\);
                    const ipListHtml = allIps\.map\(item => \{
                        const isMarked = this\.isTargetMarked\(item\.ip\);'''

new_ip = '''                if (allIps.length > 0) {
                    const ipStrings = allIps.map(item => item.id.replace('ip_', ''));
                    const allMarked = ipStrings.length > 0 && ipStrings.every(ip => this.isTargetMarked(ip));
                    const ipListHtml = allIps.map(item => {
                        const isMarked = this.isTargetMarked(item.id.replace('ip_', ''));'''
content = re.sub(old_ip, new_ip, content)

# Fix Subdomain Bulk target
old_sub = r'''                if \(relatedSubs\.length > 0\) \{
                    const subNamesList = relatedSubs\.map\(s => s\.name \|\| s\.label\);
                    const allMarked = subNamesList\.length > 0 && subNamesList\.every\(name => this\.isTargetMarked\(name\)\);
                    const subListHtml = relatedSubs\.map\(\(sub\) => \{
                        const subName = sub\.name \|\| sub\.label;
                        const isMarked = this\.isTargetMarked\(subName\);'''

new_sub = '''                if (relatedSubs.length > 0) {
                    const subNamesList = relatedSubs.map(s => s.id ? s.id.replace(/^(dom_|sub_)/, '') : (s.name || s.label));
                    const allMarked = subNamesList.length > 0 && subNamesList.every(name => this.isTargetMarked(name));
                    const subListHtml = relatedSubs.map((sub) => {
                        const subName = sub.id ? sub.id.replace(/^(dom_|sub_)/, '') : (sub.name || sub.label);
                        const isMarked = this.isTargetMarked(subName);'''
content = re.sub(old_sub, new_sub, content)

with open(path, "w") as f:
    f.write(content)
