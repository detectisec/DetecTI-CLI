const fs = require('fs');

const code = fs.readFileSync('/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js', 'utf8');

// The easiest way is to just inject the nodes and run the function
let funcBody = code.substring(code.indexOf('computeSemanticHierarchicalPositions(visibleElements) {') + 53);
funcBody = funcBody.substring(0, funcBody.indexOf('applyFilters() {'));
// Remove the trailing "}"
funcBody = funcBody.substring(0, funcBody.lastIndexOf('}'));

const nodes = [];
const edges = [];

nodes.push({ id: () => 'target_root', data: () => ({ id: 'target_root', type: 'target', is_root: true }) });
nodes.push({ id: () => 'dom_1', data: () => ({ id: 'dom_1', type: 'domain' }) });

for (let i = 1; i <= 63; i++) {
    nodes.push({ id: () => 'sub_'+i, data: () => ({ id: 'sub_'+i, type: 'subdomain' }) });
    nodes.push({ id: () => 'ip_'+i, data: () => ({ id: 'ip_'+i, type: 'ip' }) });
}

// Mock incomers
nodes.forEach(n => {
    n.incomers = (selector) => {
        let parentId = null;
        if (n.id() === 'dom_1') parentId = 'target_root';
        else if (n.id().startsWith('sub_')) parentId = 'dom_1';
        else if (n.id().startsWith('ip_')) parentId = 'sub_' + n.id().split('_')[1];
        
        return {
            sources: () => ({
                first: () => {
                    if (!parentId) return { length: 0 };
                    const found = nodes.find(nn => nn.id() === parentId);
                    return Object.assign({ length: 1 }, found);
                }
            }),
            first: () => {
                if (!parentId) return { length: 0 };
                const found = nodes.find(nn => nn.id() === parentId);
                return Object.assign({ length: 1 }, found);
            }
        };
    };
});

const getNextTierX = (currentTierX) => {
    return currentTierX + 400; // Mock this if needed, but it's inside funcBody
};

const context = `
    const nodes = arguments[0];
    const visibleElements = { nodes: { jsons: () => nodes } };
    ${funcBody}
`;

try {
    const fn = new Function(context);
    const pos = fn(nodes);
    
    // Check for overlaps
    const seen = new Set();
    let overlaps = 0;
    for (const [id, p] of Object.entries(pos)) {
        const key = p.x + ',' + p.y;
        if (seen.has(key)) {
            overlaps++;
            console.log("OVERLAP:", id, "at", key);
        }
        seen.add(key);
    }
    console.log("Total nodes:", Object.keys(pos).length);
    console.log("Total overlaps:", overlaps);
} catch (e) {
    console.error(e);
}
