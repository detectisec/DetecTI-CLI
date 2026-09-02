import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

target = """        tier2_resolved_ips.forEach((node, idx) => {
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
        });"""

replacement = """        tier2_resolved_ips.forEach((node, idx) => {
            const parentFqdn = node.incomers('edge[label="RESOLVES_TO"]').sources().first();
            let baseY = 0;
            let targetX = tier2StartX;
            
            if (parentFqdn.length > 0 && positions[parentFqdn.id()]) {
                const pid = parentFqdn.id();
                if (!parentOffsets[pid]) parentOffsets[pid] = 0;
                
                // CRITICAL FIX: IPs must be placed relative to their specific parent's X coordinate!
                // Otherwise, parents in different grid columns sharing the same Y will cause their IPs to overlap perfectly.
                targetX = positions[pid].x + 220;
                
                // For spacing, we also need to account for Services (Tier 3) height.
                // A minimum of 70px, but more if it has multiple services.
                const srvCount = srvsByIp.get(node.id()) ? srvsByIp.get(node.id()).length : 0;
                const sRows = Math.min(Math.max(1, srvCount), 3);
                const reqHeight = Math.max(70, sRows * 60);
                
                baseY = positions[pid].y + (parentOffsets[pid] * reqHeight);
                parentOffsets[pid]++;
            } else {
                baseY = (idx - (tier2_resolved_ips.length - 1) / 2) * 150;
            }
            positions[node.id()] = { x: targetX, y: baseY };
        });"""

content = content.replace(target, replacement)

# We must also fix the centering logic to use reqHeight
target2 = """        // Center the IPs around their parents properly
        // We need to shift them up by half the total offset height
        tier2_resolved_ips.forEach((node) => {
            const parentFqdn = node.incomers('edge[label="RESOLVES_TO"]').sources().first();
            if (parentFqdn.length > 0 && parentOffsets[parentFqdn.id()] > 1) {
                const pid = parentFqdn.id();
                const totalHeight = (parentOffsets[pid] - 1) * 70;
                positions[node.id()].y -= totalHeight / 2;
            }
        });"""

replacement2 = """        // Center the IPs around their parents properly
        // We need to shift them up by half the total offset height
        tier2_resolved_ips.forEach((node) => {
            const parentFqdn = node.incomers('edge[label="RESOLVES_TO"]').sources().first();
            if (parentFqdn.length > 0 && parentOffsets[parentFqdn.id()] > 1) {
                const pid = parentFqdn.id();
                
                // We must recalculate total height based on the average reqHeight, or just use the same multiplier.
                // Actually, since we just need to shift them all uniformly, we can recalculate total height:
                const childIps = parentFqdn.outgoers('edge[label="RESOLVES_TO"]').targets();
                let totalHeight = 0;
                childIps.forEach(ip => {
                    const sCount = srvsByIp.get(ip.id()) ? srvsByIp.get(ip.id()).length : 0;
                    const sr = Math.min(Math.max(1, sCount), 3);
                    totalHeight += Math.max(70, sr * 60);
                });
                
                // Shift up by half of the total height minus the height of one item (to center the block)
                const srvCount = srvsByIp.get(node.id()) ? srvsByIp.get(node.id()).length : 0;
                const sRows = Math.min(Math.max(1, srvCount), 3);
                const currentHeight = Math.max(70, sRows * 60);
                
                positions[node.id()].y -= (totalHeight - currentHeight) / 2;
            }
        });"""

content = content.replace(target2, replacement2)

with open("web/static/js/graph.js", "w") as f:
    f.write(content)
