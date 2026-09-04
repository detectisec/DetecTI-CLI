
    class EASMDashboard {
        computeSemanticHierarchicalPositions(visibleElements) {
            
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

        const getParentId = (node, edgeLabels) => {
            let parent = node.incomers(`edge[label="${edgeLabels.join('"], edge[label="')}"]`).sources().first();
            if (parent.length === 0) parent = node.incomers('node').first();
            return parent.length > 0 ? parent.id() : null;
        };

        const childrenMap = {}; 
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

        const heightCache = {};
        const visitedHeights = new Set();
        const getRequiredHeight = (node) => {
            if (heightCache[node.id()]) return heightCache[node.id()];
            if (visitedHeights.has(node.id())) return 180;
            visitedHeights.add(node.id());
            
            const children = childrenMap[node.id()] || [];
            if (children.length === 0) {
                heightCache[node.id()] = 180;
                return 180;
            }
            
            const rows = 10;
            const rowHeights = new Array(rows).fill(0);
            children.forEach((c, idx) => {
                const r = idx % rows;
                rowHeights[r] = Math.max(rowHeights[r], getRequiredHeight(c));
            });
            
            let totalHeight = rowHeights.reduce((sum, h) => sum + h, 0);
            totalHeight += (Math.min(children.length, rows) - 1) * 20;
            
            heightCache[node.id()] = Math.max(180, totalHeight);
            return heightCache[node.id()];
        };

        // Calculate dynamic max columns to create STRICT global Tier X boundaries
        const getMaxCols = (nodes) => {
            let maxChildren = 0;
            nodes.forEach(n => {
                const cCount = childrenMap[n.id()] ? childrenMap[n.id()].length : 0;
                maxChildren = Math.max(maxChildren, cCount);
            });
            return Math.max(1, Math.ceil(maxChildren / 10));
        };
        
        const t1_cols = Math.max(1, Math.ceil(t1_domains.length / 10));
        const t2_cols = getMaxCols(t1_domains);
        const t3_cols = getMaxCols(t2_subdomains);
        const t4_cols = getMaxCols(t3_ips);

        const X_SPACINGS = {
            t1: 280,
            t2: 0,
            t3: 0, 
            t4: 0,
            t5: 0
        };
        X_SPACINGS.t2 = X_SPACINGS.t1 + (t1_cols * 350) + 150;
        X_SPACINGS.t3 = X_SPACINGS.t2 + (t2_cols * 350) + 150;
        X_SPACINGS.t4 = X_SPACINGS.t3 + (t3_cols * 350) + 150;
        X_SPACINGS.t5 = X_SPACINGS.t4 + (t4_cols * 350) + 150;

        const getNextTierX = (currentTierX) => {
            if (currentTierX === X_SPACINGS.t1) return X_SPACINGS.t2;
            if (currentTierX === X_SPACINGS.t2) return X_SPACINGS.t3;
            if (currentTierX === X_SPACINGS.t3) return X_SPACINGS.t4;
            if (currentTierX === X_SPACINGS.t4) return X_SPACINGS.t5;
            return currentTierX + 400;
        };

        const visitedPlace = new Set();
        const placeChildren = (parentId, children, baseX, tierX) => {
            if (!children || children.length === 0) return;
            if (visitedPlace.has(parentId)) return;
            visitedPlace.add(parentId);
            
            // Sort: unresolved first, resolved last
            children.sort((a, b) => {
                const countA = childrenMap[a.id()] ? childrenMap[a.id()].length : 0;
                const countB = childrenMap[b.id()] ? childrenMap[b.id()].length : 0;
                if (countA !== countB) return countA - countB;
                return a.id().localeCompare(b.id());
            });
            
            const rows = 10;
            const rowHeights = new Array(rows).fill(0);
            children.forEach((c, idx) => {
                const r = idx % rows;
                rowHeights[r] = Math.max(rowHeights[r], getRequiredHeight(c));
            });
            
            const totalHeight = rowHeights.reduce((sum, h) => sum + h, 0) + (Math.min(children.length, rows) - 1) * 20;
            const parentY = positions[parentId] ? positions[parentId].y : 0;
            let currentY = parentY - (totalHeight / 2);
            
            const rowStartYs = new Array(rows).fill(0);
            let yAccumulator = currentY;
            for(let r=0; r<rows; r++) {
                if (rowHeights[r] === 0) continue;
                rowStartYs[r] = yAccumulator + (rowHeights[r] / 2);
                yAccumulator += rowHeights[r] + 20;
            }
            
            const nextGlobalTierX = getNextTierX(tierX);
            const maxCol = Math.floor(Math.max(0, children.length - 1) / rows);

            children.forEach((c, idx) => {
                let cCol = Math.floor(idx / rows);
                const cRow = idx % rows;
                
                const hasChildren = childrenMap[c.id()] && childrenMap[c.id()].length > 0;
                let x = tierX + (cCol * 350);
                
                // FORCE RESOLVED NODES TO ANCHOR NEAR THE NEXT TIER!
                if (hasChildren && tierX === X_SPACINGS.t2) {
                    // Right-align by shifting relative to the max columns, preserving cCol spacing to prevent overlaps!
                    const rightAlignedX = nextGlobalTierX - 350 - ((maxCol - cCol) * 350);
                    x = Math.max(x, rightAlignedX);
                }
                
                const y = rowStartYs[cRow];
                
                if (!positions[c.id()]) {
                    positions[c.id()] = { x, y };
                    placeChildren(c.id(), childrenMap[c.id()], x, nextGlobalTierX);
                }
            });
        };

        let globalY = 0;
        t1_domains.forEach(d => getRequiredHeight(d));
        t1_domains.forEach(d => {
            const h = getRequiredHeight(d);
            const y = globalY + (h / 2);
            positions[d.id()] = { x: X_SPACINGS.t1, y };
            globalY += h + 100;
            placeChildren(d.id(), childrenMap[d.id()], X_SPACINGS.t1, X_SPACINGS.t2);
        });

        // Orphans
        [t2_subdomains, t3_ips, t4_services, t5_vulns].forEach((tierList, tierIdx) => {
            const defaultX = Object.values(X_SPACINGS)[tierIdx + 1] || (X_SPACINGS.t5 + 400);
            const nextX = Object.values(X_SPACINGS)[tierIdx + 2] || (defaultX + 400);
            tierList.forEach(node => {
                if (!positions[node.id()]) {
                    const h = getRequiredHeight(node);
                    positions[node.id()] = { x: defaultX, y: globalY + (h / 2) };
                    globalY += h + 50;
                    placeChildren(node.id(), childrenMap[node.id()], defaultX, nextX);
                }
            });
        });

        // TARGET_ROOT CENTERING
        let minY = Infinity;
        let maxY = -Infinity;
        Object.values(positions).forEach(p => {
            minY = Math.min(minY, p.y);
            maxY = Math.max(maxY, p.y);
        });
        const centerY = (minY === Infinity) ? 0 : (minY + maxY) / 2;

        t0_root.forEach((node) => {
            positions[node.id()] = { x: 0, y: centerY };
        });

        const topDownPositions = {};
        for (const [nodeId, pos] of Object.entries(positions)) {
            topDownPositions[nodeId] = { x: pos.y, y: pos.x };
        }
        
        return topDownPositions;
    
        }
    }
    module.exports = new EASMDashboard();
