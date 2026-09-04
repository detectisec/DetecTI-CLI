import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

# 1. findConnectedIPs
# Look for:
#        const ips = Array.from(connectedIpIds).map(id => this.nodeIndex.get(id)).filter(Boolean);
#        return ips;
old_ips = r'''        const ips = Array\.from\(connectedIpIds\)\.map\(id => this\.nodeIndex\.get\(id\)\)\.filter\(Boolean\);
        return ips;'''
new_ips = '''        const ips = Array.from(connectedIpIds).map(id => this.nodeIndex.get(id)).filter(Boolean);
        if (targetData.passive_ips && Array.isArray(targetData.passive_ips)) {
            targetData.passive_ips.forEach(ip => {
                if (!connectedIpIds.has(ip.id)) {
                    connectedIpIds.add(ip.id);
                    ips.push(ip);
                }
            });
        }
        return ips;'''
content = re.sub(old_ips, new_ips, content)

# 2. findConnectedServices
# Look for:
#            const uniqueServices = services.filter((service, index, self) => 
#                index === self.findIndex(s => s.id === service.id)
#            );
old_srvs = r'''            // Remove duplicates
            const uniqueServices = services\.filter\(\(service, index, self\) => 
                index === self\.findIndex\(s => s\.id === service\.id\)
            \);'''
new_srvs = '''            if (selfData && selfData.passive_services && Array.isArray(selfData.passive_services)) {
                selfData.passive_services.forEach(srv => services.push(srv));
            }
            
            // Remove duplicates
            const uniqueServices = services.filter((service, index, self) => 
                index === self.findIndex(s => s.id === service.id)
            );'''
content = re.sub(old_srvs, new_srvs, content)

# 3. findConnectedVulnerabilities
# Look for:
#            // Remove duplicates by CVE ID or ID
#            const seenCveKeys = new Set();
old_vulns = r'''            // Remove duplicates by CVE ID or ID
            const seenCveKeys = new Set\(\);'''
new_vulns = '''            if (selfData && selfData.passive_vulns && Array.isArray(selfData.passive_vulns)) {
                selfData.passive_vulns.forEach(vuln => vulnerabilities.push(vuln));
            }
            
            // Remove duplicates by CVE ID or ID
            const seenCveKeys = new Set();'''
content = re.sub(old_vulns, new_vulns, content)

with open(path, "w") as f:
    f.write(content)
