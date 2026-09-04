import re

with open("web/static/js/graph.js", "r") as f:
    js = f.read()

target1 = """        // Rule: When NO leads are selected (default upon DB load), render NOTHING!
        if (selectedLeadIds.length === 0) {
            this.cy.nodes().hide();
            this.cy.edges().hide();
            this.visibleLeadNodes = new Set();
            return;
        }"""
        
replacement1 = """        // Rule: When NO leads are selected (default upon DB load), render NOTHING except target_root!
        if (selectedLeadIds.length === 0) {
            this.cy.nodes().hide();
            this.cy.edges().hide();
            const rootNode = this.cy.getElementById('target_root');
            if (rootNode.length > 0) rootNode.show();
            this.visibleLeadNodes = new Set(['target_root']);
            return;
        }"""

js = js.replace(target1, replacement1)

target2 = """        // Fifth pass: Actually hide nodes not in visible set
        this.cy.nodes().forEach(node => {
            if (!visibleNodes.has(node.id())) {
                node.hide();
            }
        });"""

replacement2 = """        // Fifth pass: Actually hide nodes not in visible set
        this.cy.nodes().forEach(node => {
            if (node.id() === 'target_root') {
                node.show(); // Always persistent
            } else if (!visibleNodes.has(node.id())) {
                node.hide();
            }
        });"""

js = js.replace(target2, replacement2)

with open("web/static/js/graph.js", "w") as f:
    f.write(js)
