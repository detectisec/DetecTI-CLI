file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    lines = f.readlines()

new_func = """    computeSemanticHierarchicalPositions(targetElements = null) {
        if (!this.cy) return {};
        const elements = targetElements || this.cy.elements(':visible');
        const nodes = elements.nodes ? elements.nodes() : elements.filter('node');
        if (nodes.length === 0) return {};

        const positions = {};
        
        // Tier Buckets
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
            else t3_ips.push(node); // fallback
        });

        // Group sorting helper
        const sortByResolvedIp = (a, b) => {
            const getIpId = (n) => {
                const target = n.outgoers('edge[label="RESOLVES_TO"]').targets().first();
                return target.length > 0 ? target.id() : n.id();
            };
            return getIpId(a).localeCompare(getIpId(b));
        };
        t1_domains.sort(sortByResolvedIp);
        t2_subdomains.sort(sortByResolvedIp);

        // Tier 0: Root
        t0_root.forEach((node, i) => {
            positions[node.id()] = { x: 0, y: (i - (t0_root.length - 1) / 2) * 350 };
        });

        // Track offsets for relative positioning
        const childOffsets = {};
        const getOffset = (pid) => {
            if (!childOffsets[pid]) childOffsets[pid] = 0;
            return childOffsets[pid]++;
        };

        const X_GAP = 280;
        
        // Tier 1: Domains
        t1_domains.forEach((node, idx) => {
            const col = Math.floor(idx / 5);
            const row = idx % 5;
            const x = X_GAP + (col * 180);
            const y = (row - 2) * 600;
            positions[node.id()] = { x, y };
        });

        // Tier 2: Subdomains
        let maxDomainX = X_GAP;
        t1_domains.forEach(n => { maxDomainX = Math.max(maxDomainX, positions[n.id()].x); });
        
        t2_subdomains.forEach((node, idx) => {
            let parent = node.incomers('edge[label="HAS_SUBDOMAIN"]').sources().first();
            if (parent.length === 0) parent = node.incomers('node').first();
            
            if (parent.length > 0 && positions[parent.id()]) {
                const pid = parent.id();
                const offset = getOffset(pid);
                // Offset calculation (simulating rows for siblings)
                const row = offset % 3;
                positions[node.id()] = { 
                    x: positions[pid].x + 220, 
                    y: positions[pid].y + (row * 350) - 350 
                };
            } else {
                positions[node.id()] = { x: maxDomainX + 220, y: (idx - t2_subdomains.length/2) * 350 };
            }
        });

        // Tier 3: IPs
        let maxSubX = maxDomainX + 220;
        t2_subdomains.forEach(n => { maxSubX = Math.max(maxSubX, positions[n.id()].x); });

        t3_ips.forEach((node, idx) => {
            let parent = node.incomers('edge[label="RESOLVES_TO"], edge[label="CONTAINS_IP"]').sources().first();
            if (parent.length === 0) parent = node.incomers('node').first();
            
            if (parent.length > 0 && positions[parent.id()]) {
                const pid = parent.id();
                const offset = getOffset(pid);
                const row = offset % 3;
                // IPs go further right than their FQDN parent
                positions[node.id()] = { 
                    x: positions[pid].x + 240, 
                    y: positions[pid].y + (row * 300) - 300 
                };
            } else {
                // Completely orphaned IPs
                positions[node.id()] = { x: maxSubX + 240, y: (idx - t3_ips.length/2) * 300 };
            }
        });

        // Tier 4: Services
        t4_services.forEach((node) => {
            let parent = node.incomers('node[type="ip"]').first();
            if (parent.length === 0) parent = node.incomers('node').first();
            
            if (parent.length > 0 && positions[parent.id()]) {
                const pid = parent.id();
                const offset = getOffset(pid);
                const col = Math.floor(offset / 3);
                const row = offset % 3;
                positions[node.id()] = { 
                    x: positions[pid].x + 150 + (col * 90), 
                    y: positions[pid].y + (row * 160) - 160
                };
            } else {
                positions[node.id()] = { x: maxSubX + 400, y: 0 };
            }
        });

        // Tier 5: Vulns
        t5_vulns.forEach((node) => {
            let parent = node.incomers('node').first();
            
            if (parent.length > 0 && positions[parent.id()]) {
                const pid = parent.id();
                const offset = getOffset(pid);
                const col = Math.floor(offset / 2);
                const row = offset % 2;
                positions[node.id()] = { 
                    x: positions[pid].x + 110 + (col * 70), 
                    y: positions[pid].y + (row * 140) - 70
                };
            } else {
                positions[node.id()] = { x: maxSubX + 500, y: 0 };
            }
        });

        // Apply Top-Down Swap
        // To maintain the Top-Down physics, we swap X and Y right before returning,
        // effectively rotating our cleanly calculated horizontal hierarchy by 90 degrees.
        const topDownPositions = {};
        for (const [nodeId, pos] of Object.entries(positions)) {
            topDownPositions[nodeId] = { x: pos.y, y: pos.x };
        }
        
        return topDownPositions;
    }
"""

new_lines = lines[:40] + [new_func + "\n"] + lines[283:]

with open(file_path, "w") as f:
    f.writelines(new_lines)
print("Replaced layout block successfully")
