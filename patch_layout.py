import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

# We need to offset IPs that share the same parent FQDN.
# We can track the number of IPs per parentFqdn.

target = """        // Position Resolved IPs (Tier 2) near their parent FQDNs or in column
        tier2_resolved_ips.forEach((node, idx) => {
            const parentFqdn = node.incomers('edge[label="RESOLVES_TO"]').sources().first();
            let baseY = 0;
            if (parentFqdn.length > 0 && positions[parentFqdn.id()]) {
                baseY = positions[parentFqdn.id()].y;
            } else {
                baseY = (idx - (tier2_resolved_ips.length - 1) / 2) * 150;
            }
            positions[node.id()] = { x: tier2StartX, y: baseY };
        });"""

replacement = """        // Position Resolved IPs (Tier 2) near their parent FQDNs or in column
        const parentOffsets = {};
        tier2_resolved_ips.forEach((node, idx) => {
            const parentFqdn = node.incomers('edge[label="RESOLVES_TO"]').sources().first();
            let baseY = 0;
            if (parentFqdn.length > 0 && positions[parentFqdn.id()]) {
                const pid = parentFqdn.id();
                if (!parentOffsets[pid]) parentOffsets[pid] = 0;
                // Offset each subsequent IP by 70px down, centered around the parent
                baseY = positions[pid].y + (parentOffsets[pid] * 70);
                parentOffsets[pid]++;
            } else {
                baseY = (idx - (tier2_resolved_ips.length - 1) / 2) * 150;
            }
            positions[node.id()] = { x: tier2StartX, y: baseY };
        });
        
        // Center the IPs around their parents properly
        // We need to shift them up by half the total offset height
        tier2_resolved_ips.forEach((node) => {
            const parentFqdn = node.incomers('edge[label="RESOLVES_TO"]').sources().first();
            if (parentFqdn.length > 0 && parentOffsets[parentFqdn.id()] > 1) {
                const pid = parentFqdn.id();
                const totalHeight = (parentOffsets[pid] - 1) * 70;
                positions[node.id()].y -= totalHeight / 2;
            }
        });"""

content = content.replace(target, replacement)

with open("web/static/js/graph.js", "w") as f:
    f.write(content)
