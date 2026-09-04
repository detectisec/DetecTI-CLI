import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"        const childOffsets = \{\};[\s\S]*?return topDownPositions;\n    \}"

new_func = """        const getParentId = (node, edgeLabels) => {
            let parent = node.incomers(`edge[label="${edgeLabels.join('"], edge[label="')}"]`).sources().first();
            if (parent.length === 0) parent = node.incomers('node').first();
            return parent.length > 0 ? parent.id() : null;
        };

        // Build parent-child relationships strictly
        const childrenMap = {}; // pid -> array of nodes
        const addChild = (pid, node) => {
            if (!childrenMap[pid]) childrenMap[pid] = [];
            childrenMap[pid].push(node);
        };

        t2_subdomains.forEach(n => { const pid = getParentId(n, ["HAS_SUBDOMAIN", "MATCHES_DOMAIN"]); if(pid) addChild(pid, n); });
        t3_ips.forEach(n => { const pid = getParentId(n, ["RESOLVES_TO", "CONTAINS_IP"]); if(pid) addChild(pid, n); });
        t4_services.forEach(n => {
            let parent = n.incomers('node[type="ip"]').first();
            if (parent.length === 0) parent = n.incomers('node').first();
            if (parent.length > 0) addChild(parent.id(), n);
        });
        t5_vulns.forEach(n => {
            let parent = n.incomers('node').first();
            if (parent.length > 0) addChild(parent.id(), n);
        });

        // Calculate required Y-height (spread) for each node recursively (bottom-up)
        // A node's height is the MAX of its own grid height (if it's a leaf/grid) OR the sum of its children's heights
        const heightCache = {};
        const getRequiredHeight = (node) => {
            if (heightCache[node.id()]) return heightCache[node.id()];
            
            const children = childrenMap[node.id()] || [];
            if (children.length === 0) {
                heightCache[node.id()] = 180; // Base height of a leaf node
                return 180;
            }
            
            // If it has children, the children form a grid of max 10 rows.
            // The height of this node's children block is the sum of heights of the ROWS.
            // Since children can also have children, their heights vary!
            // We must pack the children into 10 rows. The height of a row is the MAX height of any cell in that row.
            const rows = 10;
            const rowHeights = new Array(rows).fill(0);
            
            children.forEach((c, idx) => {
                const r = idx % rows;
                const h = getRequiredHeight(c);
                rowHeights[r] = Math.max(rowHeights[r], h);
            });
            
            let totalHeight = rowHeights.reduce((sum, h) => sum + h, 0);
            // Add a little padding between rows
            totalHeight += (Math.min(children.length, rows) - 1) * 20;
            
            heightCache[node.id()] = Math.max(180, totalHeight);
            return heightCache[node.id()];
        };

        // Layout parameters
        const X_SPACINGS = {
            t1: 280,
            t2: 600,
            t3: 1000,
            t4: 1400,
            t5: 1700
        };

        // Top-down placement
        const placeChildren = (parentId, children, baseX, tierX) => {
            if (!children || children.length === 0) return;
            
            const rows = 10;
            const rowHeights = new Array(rows).fill(0);
            children.forEach((c, idx) => {
                const r = idx % rows;
                rowHeights[r] = Math.max(rowHeights[r], getRequiredHeight(c));
            });
            
            // Calculate starting Y so the whole grid is centered at the parent's Y
            const totalHeight = rowHeights.reduce((sum, h) => sum + h, 0) + (Math.min(children.length, rows) - 1) * 20;
            const parentY = positions[parentId] ? positions[parentId].y : 0;
            let currentY = parentY - (totalHeight / 2);
            
            // We need to track the Y coordinate for each row
            const rowStartYs = new Array(rows).fill(0);
            let yAccumulator = currentY;
            for(let r=0; r<rows; r++) {
                if (rowHeights[r] === 0) continue;
                // Center the row vertically within its allocated rowHeight
                rowStartYs[r] = yAccumulator + (rowHeights[r] / 2);
                yAccumulator += rowHeights[r] + 20;
            }
            
            children.forEach((c, idx) => {
                const cCol = Math.floor(idx / rows);
                const cRow = idx % rows;
                const x = tierX + (cCol * 350); // Column expansion depth
                const y = rowStartYs[cRow];
                
                positions[c.id()] = { x, y };
                
                // Recursively place this child's children
                let nextTierX = tierX + 400; // rough guess based on tier, we can refine
                if (tierX >= X_SPACINGS.t4) nextTierX = tierX + 300;
                placeChildren(c.id(), childrenMap[c.id()], x, nextTierX);
            });
        };

        // 1. Calculate heights for all T1 domains
        t1_domains.forEach(d => getRequiredHeight(d));
        
        // 2. Place T1 domains sequentially
        let globalY = 0;
        t1_domains.forEach(d => {
            const h = getRequiredHeight(d);
            const y = globalY + (h / 2);
            positions[d.id()] = { x: X_SPACINGS.t1, y };
            globalY += h + 100; // 100px padding between huge domain blocks
            
            // Place subtrees
            placeChildren(d.id(), childrenMap[d.id()], X_SPACINGS.t1, X_SPACINGS.t2);
        });

        // 3. Place any remaining orphans that weren't reached via T1 traversal
        [t2_subdomains, t3_ips, t4_services, t5_vulns].forEach((tierList, tierIdx) => {
            const defaultX = Object.values(X_SPACINGS)[tierIdx + 1];
            tierList.forEach(node => {
                if (!positions[node.id()]) {
                    const h = getRequiredHeight(node);
                    positions[node.id()] = { x: defaultX, y: globalY + (h / 2) };
                    globalY += h + 50;
                    placeChildren(node.id(), childrenMap[node.id()], defaultX, defaultX + 400);
                }
            });
        });

        // Top-Down Swap
        const topDownPositions = {};
        for (const [nodeId, pos] of Object.entries(positions)) {
            topDownPositions[nodeId] = { x: pos.y, y: pos.x };
        }
        
        return topDownPositions;
    }"""

import re
if re.search(pattern, content):
    new_content = re.sub(pattern, new_func, content)
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Replaced layout with ultra-compact perfect bounding-box DAG!")
else:
    print("Regex failed to find function")
