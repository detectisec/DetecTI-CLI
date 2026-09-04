file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

import re

# We will completely replace computeSemanticHierarchicalPositions again to make it perfect
pattern = r"computeSemanticHierarchicalPositions\(targetElements = null\) \{[\s\S]*?return topDownPositions;\n    \}"

new_func = """computeSemanticHierarchicalPositions(targetElements = null) {
        if (!this.cy) return {};
        const elements = targetElements || this.cy.elements(':visible');
        const nodes = elements.nodes ? elements.nodes() : elements.filter('node');
        if (nodes.length === 0) return {};

        const positions = {};
        
        // Semantic Tier Buckets
        const t0_root = [];
        const t1_domains = [];
        const t2_subdomains = [];
        const t3_ips = [];
        const t4_services = [];
        const t5_vulns = [];

        nodes.forEach(node => {
            const data = node.data();
            const type = data.type;
            if (type === 'target' || data.id === 'target_root' || data.is_root === true) t0_root.push(node);
            else if (type === 'domain') t1_domains.push(node);
            else if (type === 'subdomain') t2_subdomains.push(node);
            else if (type === 'ip' || type === 'network') t3_ips.push(node);
            else if (['service', 'http', 'https', 'cluster_services'].includes(type)) t4_services.push(node);
            else if (['vulnerability', 'cluster_vulns'].includes(type)) t5_vulns.push(node);
            else t3_ips.push(node);
        });

        const sortByResolvedIp = (a, b) => {
            const getIpId = (n) => {
                const target = n.outgoers('edge[label="RESOLVES_TO"]').targets().first();
                return target.length > 0 ? target.id() : n.id();
            };
            return getIpId(a).localeCompare(getIpId(b));
        };
        t1_domains.sort(sortByResolvedIp);
        t2_subdomains.sort(sortByResolvedIp);

        // Tier 0
        t0_root.forEach((node, i) => {
            positions[node.id()] = { x: 0, y: (i - (t0_root.length - 1) / 2) * 350 };
        });

        // Pre-compute child counts for perfect centering
        const childCounts = {};
        const countChild = (pid) => {
            if (!childCounts[pid]) childCounts[pid] = 0;
            childCounts[pid]++;
        };
        
        const getParentId = (node, edgeLabels) => {
            let parent = node.incomers(`edge[label="${edgeLabels.join('"], edge[label="')}"]`).sources().first();
            if (parent.length === 0) parent = node.incomers('node').first();
            return parent.length > 0 ? parent.id() : null;
        };

        t2_subdomains.forEach(n => { const pid = getParentId(n, ["HAS_SUBDOMAIN", "MATCHES_DOMAIN"]); if (pid) countChild(pid); });
        t3_ips.forEach(n => { const pid = getParentId(n, ["RESOLVES_TO", "CONTAINS_IP"]); if (pid) countChild(pid); });
        t4_services.forEach(n => {
            let parent = n.incomers('node[type="ip"]').first();
            if (parent.length === 0) parent = n.incomers('node').first();
            if (parent.length > 0) countChild(parent.id());
        });
        t5_vulns.forEach(n => {
            let parent = n.incomers('node').first();
            if (parent.length > 0) countChild(parent.id());
        });

        const childOffsets = {};
        const getOffset = (pid) => {
            if (!childOffsets[pid]) childOffsets[pid] = 0;
            return childOffsets[pid]++;
        };

        const getGridCenterOffset = (totalItems, limit, rowIdx, spacing) => {
            // A column has at most `limit` items. If this is the last column, it might have fewer.
            // Wait, actually it's visually better to center the entire grid block globally, or just center each column independently!
            // Let's center each column independently based on its actual height.
            // Wait! totalItems isn't needed if we just center based on Math.min(totalItems, limit).
            // Actually, if a block has 3 items, rowCount = 3. 
            // If it has 12 items, col 0 has 10 items (rowCount = 10), col 1 has 2 items (rowCount = 2).
            const isFullColumn = totalItems >= limit; // simplified
            // For true perfection, we center the entire block using a constant shift, so rows align horizontally!
            // If we center each column independently, a 2-item column will have its items at Y=0, while the 10-item column next to it has items at Y=-4, Y=-3, etc. This breaks the grid!
            // We MUST use the exact same max row count for the whole block!
            const blockMaxRows = Math.min(totalItems, limit);
            return (rowIdx - (blockMaxRows - 1) / 2) * spacing;
        };

        let currentTierDepth = 280;

        // Tier 1: Domains
        let maxT1Depth = currentTierDepth;
        const t1Total = t1_domains.length;
        const t1Rows = Math.min(t1Total, 10);
        t1_domains.forEach((node, idx) => {
            const col = Math.floor(idx / 10);
            const row = idx % 10;
            const x = currentTierDepth + (col * 220);
            const y = (row - (t1Rows - 1) / 2) * 400;
            positions[node.id()] = { x, y };
            maxT1Depth = Math.max(maxT1Depth, x);
        });
        
        currentTierDepth = maxT1Depth + 240;

        // Tier 2: Subdomains
        let maxT2Depth = currentTierDepth;
        const t2TotalOrphans = t2_subdomains.filter(n => !getParentId(n, ["HAS_SUBDOMAIN", "MATCHES_DOMAIN"])).length;
        let t2OrphanOffset = 0;

        t2_subdomains.forEach((node) => {
            const pid = getParentId(node, ["HAS_SUBDOMAIN", "MATCHES_DOMAIN"]);
            if (pid && positions[pid]) {
                const total = childCounts[pid];
                const offset = getOffset(pid);
                const col = Math.floor(offset / 10);
                const row = offset % 10;
                const x = currentTierDepth + (col * 220);
                const y = positions[pid].y + getGridCenterOffset(total, 10, row, 200);
                positions[node.id()] = { x, y };
                maxT2Depth = Math.max(maxT2Depth, x);
            } else {
                const col = Math.floor(t2OrphanOffset / 10);
                const row = t2OrphanOffset % 10;
                const x = currentTierDepth + (col * 220);
                const y = getGridCenterOffset(t2TotalOrphans, 10, row, 200);
                positions[node.id()] = { x, y };
                maxT2Depth = Math.max(maxT2Depth, x);
                t2OrphanOffset++;
            }
        });
        
        currentTierDepth = maxT2Depth + 260;

        // Tier 3: IPs
        let maxT3Depth = currentTierDepth;
        const t3TotalOrphans = t3_ips.filter(n => !getParentId(n, ["RESOLVES_TO", "CONTAINS_IP"])).length;
        let t3OrphanOffset = 0;

        t3_ips.forEach((node) => {
            const pid = getParentId(node, ["RESOLVES_TO", "CONTAINS_IP"]);
            if (pid && positions[pid]) {
                const total = childCounts[pid];
                const offset = getOffset(pid);
                const col = Math.floor(offset / 10);
                const row = offset % 10;
                const x = currentTierDepth + (col * 220);
                const y = positions[pid].y + getGridCenterOffset(total, 10, row, 200);
                positions[node.id()] = { x, y };
                maxT3Depth = Math.max(maxT3Depth, x);
            } else {
                const col = Math.floor(t3OrphanOffset / 10);
                const row = t3OrphanOffset % 10;
                const x = currentTierDepth + (col * 220);
                const y = getGridCenterOffset(t3TotalOrphans, 10, row, 200);
                positions[node.id()] = { x, y };
                maxT3Depth = Math.max(maxT3Depth, x);
                t3OrphanOffset++;
            }
        });

        currentTierDepth = maxT3Depth + 260;

        // Tier 4: Services
        let maxT4Depth = currentTierDepth;
        t4_services.forEach((node) => {
            let parent = node.incomers('node[type="ip"]').first();
            if (parent.length === 0) parent = node.incomers('node').first();
            
            if (parent.length > 0 && positions[parent.id()]) {
                const pid = parent.id();
                const total = childCounts[pid];
                const offset = getOffset(pid);
                const col = Math.floor(offset / 10);
                const row = offset % 10;
                const x = currentTierDepth + (col * 100);
                const y = positions[pid].y + getGridCenterOffset(total, 10, row, 160);
                positions[node.id()] = { x, y };
                maxT4Depth = Math.max(maxT4Depth, x);
            } else {
                positions[node.id()] = { x: currentTierDepth, y: 0 };
            }
        });
        
        currentTierDepth = maxT4Depth + 200;

        // Tier 5: Vulns
        t5_vulns.forEach((node) => {
            let parent = node.incomers('node').first();
            if (parent.length > 0 && positions[parent.id()]) {
                const pid = parent.id();
                const total = childCounts[pid];
                const offset = getOffset(pid);
                const col = Math.floor(offset / 10);
                const row = offset % 10;
                const x = currentTierDepth + (col * 80);
                const y = positions[pid].y + getGridCenterOffset(total, 10, row, 140);
                positions[node.id()] = { x, y };
            } else {
                positions[node.id()] = { x: currentTierDepth, y: 0 };
            }
        });

        // Top-Down Swap
        const topDownPositions = {};
        for (const [nodeId, pos] of Object.entries(positions)) {
            topDownPositions[nodeId] = { x: pos.y, y: pos.x };
        }
        
        return topDownPositions;
    }"""

if re.search(pattern, content):
    new_content = re.sub(pattern, new_func, content)
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Fixed centering dynamically perfectly!")
else:
    print("Regex failed to find function")
