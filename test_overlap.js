const fs = require('fs');

// We will mock cytoscape elements and test the layout function
const code = fs.readFileSync('/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js', 'utf8');

// We need to extract computeSemanticHierarchicalPositions
const match = code.match(/computeSemanticHierarchicalPositions\s*\([^)]*\)\s*{([\s\S]*?)}\s*(applyLeadFilter|getLayoutOptions)/);
if (!match) {
    console.log("Could not find function");
    process.exit(1);
}

// We will simulate 1 Domain, 63 Subdomains, 63 IPs
const nodes = [];
const edges = [];

nodes.push({ id: () => 'target_root', data: () => ({ id: 'target_root', type: 'target' }) });
nodes.push({ id: () => 'dom_1', data: () => ({ id: 'dom_1', type: 'domain' }) });
edges.push({ source: () => 'target_root', target: () => 'dom_1', data: () => ({ label: 'MATCHES_DOMAIN' }) });

for (let i = 1; i <= 63; i++) {
    nodes.push({ id: () => 'sub_'+i, data: () => ({ id: 'sub_'+i, type: 'subdomain' }) });
    edges.push({ source: () => 'dom_1', target: () => 'sub_'+i, data: () => ({ label: 'HAS_SUBDOMAIN' }) });
    
    nodes.push({ id: () => 'ip_'+i, data: () => ({ id: 'ip_'+i, type: 'ip' }) });
    edges.push({ source: () => 'sub_'+i, target: () => 'ip_'+i, data: () => ({ label: 'RESOLVES_TO' }) });
}

const cyMock = {
    edges: () => ({
        filter: (fn) => edges.filter(e => fn(e))
    })
};

// Add incomers/outgoers mock to nodes
nodes.forEach(n => {
    n.incomers = (selector) => {
        const typeMatch = selector.match(/type="([^"]+)"/);
        const edgeMatch = selector.match(/edge\[label="([^"]+)"\]/g);
        
        const incomingEdges = edges.filter(e => e.target() === n.id());
        
        return {
            sources: () => {
                const srcIds = incomingEdges.map(e => e.source());
                return {
                    first: () => {
                        if (srcIds.length === 0) return { length: 0 };
                        const found = nodes.find(nn => nn.id() === srcIds[0]);
                        return found ? Object.assign({ length: 1 }, found) : { length: 0 };
                    }
                }
            },
            first: () => {
                const srcIds = incomingEdges.map(e => e.source());
                if (srcIds.length === 0) return { length: 0 };
                const found = nodes.find(nn => nn.id() === srcIds[0]);
                return found ? Object.assign({ length: 1 }, found) : { length: 0 };
            }
        };
    };
});

// Since the function is complex, let's just create an instance of EASMDashboard and call it
const scriptContext = `
    class EASMDashboard {
        computeSemanticHierarchicalPositions(visibleElements) {
            ${match[1]}
        }
    }
    module.exports = new EASMDashboard();
`;

fs.writeFileSync('temp_test.js', scriptContext);
