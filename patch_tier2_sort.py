import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"        // Position Resolved IPs \(Tier 2\) near their parent FQDNs or in column\n        const parentOffsets = \{\};\n        tier2_resolved_ips\.forEach\(\(node, idx\) => \{"
end_pattern = r"            positions\[node\.id\(\)\] = \{ x: targetX, y: baseY \};\n        \}\);"

# Find the block
start_idx = content.find('        // Position Resolved IPs (Tier 2) near their parent FQDNs or in column')
end_idx = content.find('        // Center the IPs around their parents properly')

if start_idx != -1 and end_idx != -1:
    old_block = content[start_idx:end_idx]
    
    new_block = """        // Position Resolved IPs (Tier 2) near their parent FQDNs or in column
        const parentOffsets = {};
        
        // Guarantee topological ordering so parents are placed before children!
        const tier2_domains = tier2_resolved_ips.filter(n => n.data('type') === 'domain');
        const tier2_subdomains = tier2_resolved_ips.filter(n => n.data('type') === 'subdomain');
        const tier2_ips = tier2_resolved_ips.filter(n => n.data('type') === 'ip' || n.data('type') === 'network');
        const tier2_others = tier2_resolved_ips.filter(n => !['domain', 'subdomain', 'ip', 'network'].includes(n.data('type')));
        
        const placeTier2Node = (node, idx, totalLen) => {
            // Support multiple passive relation edges
            let parentFqdn = node.incomers('edge[label="RESOLVES_TO"], edge[label="MATCHES_DOMAIN"], edge[label="ASSOCIATED_DOMAIN"], edge[label="CONTAINS_IP"]').sources().first();
            if (parentFqdn.length === 0) parentFqdn = node.incomers('node').first();
            
            let baseY = 0;
            let targetX = tier2StartX;
            
            if (parentFqdn.length > 0 && positions[parentFqdn.id()]) {
                const pid = parentFqdn.id();
                if (!parentOffsets[pid]) parentOffsets[pid] = 0;
                
                // CRITICAL FIX: IPs must be placed relative to their specific parent's X coordinate!
                targetX = positions[pid].x + 220;
                
                const srvCount = srvsByIp.get(node.id()) ? srvsByIp.get(node.id()).length : 0;
                const sRows = Math.min(Math.max(1, srvCount), 3);
                const reqHeight = Math.max(200, sRows * 180);
                
                baseY = positions[pid].y + (parentOffsets[pid] * reqHeight);
                parentOffsets[pid]++;
            } else {
                baseY = (idx - (totalLen - 1) / 2) * 350;
            }
            positions[node.id()] = { x: targetX, y: baseY };
        };

        tier2_domains.forEach((n, i) => placeTier2Node(n, i, tier2_domains.length));
        tier2_subdomains.forEach((n, i) => placeTier2Node(n, i, tier2_subdomains.length));
        tier2_ips.forEach((n, i) => placeTier2Node(n, i, tier2_ips.length));
        tier2_others.forEach((n, i) => placeTier2Node(n, i, tier2_others.length));
"""
    new_content = content[:start_idx] + new_block + content[end_idx:]
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Patched successfully")
else:
    print("Could not find the block")
