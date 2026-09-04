file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    lines = f.readlines()

new_func = """    computeSemanticHierarchicalPositions(targetElements = null) {
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

        // Sort to group relatives
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

        const childOffsets = {};
        const getOffset = (pid) => {
            if (!childOffsets[pid]) childOffsets[pid] = 0;
            return childOffsets[pid]++;
        };

        let currentTierDepth = 280; // Start Tier 1 at X=280

        // Tier 1: Domains (Grid of 10 rows)
        let maxT1Depth = currentTierDepth;
        t1_domains.forEach((node, idx) => {
            const col = Math.floor(idx / 10);
            const row = idx % 10;
            const x = currentTierDepth + (col * 220);
            const y = (row - 4.5) * 400;
            positions[node.id()] = { x, y };
            maxT1Depth = Math.max(maxT1Depth, x);
        });
        
        currentTierDepth = maxT1Depth + 240;

        // Tier 2: Subdomains
        let maxT2Depth = currentTierDepth;
        t2_subdomains.forEach((node, idx) => {
            let parent = node.incomers('edge[label="HAS_SUBDOMAIN"], edge[label="MATCHES_DOMAIN"]').sources().first();
            if (parent.length === 0) parent = node.incomers('node').first();
            
            if (parent.length > 0 && positions[parent.id()]) {
                const pid = parent.id();
                const offset = getOffset(pid);
                const col = Math.floor(offset / 10);
                const row = offset % 10;
                
                // Align exactly at the current global tier depth, PLUS any grid wrapping columns
                const x = currentTierDepth + (col * 220);
                // Center vertically relative to parent
                const y = positions[pid].y + (row * 200) - 900;
                
                positions[node.id()] = { x, y };
                maxT2Depth = Math.max(maxT2Depth, x);
            } else {
                const col = Math.floor(idx / 10);
                const row = idx % 10;
                const x = currentTierDepth + (col * 220);
                const y = (row - 4.5) * 200;
                positions[node.id()] = { x, y };
                maxT2Depth = Math.max(maxT2Depth, x);
            }
        });
        
        currentTierDepth = maxT2Depth + 260;

        // Tier 3: IPs
        let maxT3Depth = currentTierDepth;
        t3_ips.forEach((node, idx) => {
            let parent = node.incomers('edge[label="RESOLVES_TO"], edge[label="CONTAINS_IP"]').sources().first();
            if (parent.length === 0) parent = node.incomers('node').first();
            
            if (parent.length > 0 && positions[parent.id()]) {
                const pid = parent.id();
                const offset = getOffset(pid);
                const col = Math.floor(offset / 10);
                const row = offset % 10;
                
                const x = currentTierDepth + (col * 220);
                const y = positions[pid].y + (row * 200) - 900;
                positions[node.id()] = { x, y };
                maxT3Depth = Math.max(maxT3Depth, x);
            } else {
                const col = Math.floor(idx / 10);
                const row = idx % 10;
                const x = currentTierDepth + (col * 220);
                const y = (row - 4.5) * 200;
                positions[node.id()] = { x, y };
                maxT3Depth = Math.max(maxT3Depth, x);
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
                const offset = getOffset(pid);
                const col = Math.floor(offset / 3);
                const row = offset % 3;
                const x = currentTierDepth + (col * 100);
                const y = positions[pid].y + (row * 160) - 160;
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
                const offset = getOffset(pid);
                const col = Math.floor(offset / 2);
                const row = offset % 2;
                const x = currentTierDepth + (col * 80);
                const y = positions[pid].y + (row * 140) - 70;
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
    }
"""

# Replace lines 41 to 283
new_lines = lines[:40] + [new_func + "\n"] + lines[283:]

with open(file_path, "w") as f:
    f.writelines(new_lines)
print("Replaced layout cleanly!")
