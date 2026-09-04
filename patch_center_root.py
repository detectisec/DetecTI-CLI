import re

with open("web/static/js/graph.js", "r") as f:
    js = f.read()

target = """        // Rule: When NO leads are selected (default upon DB load), render NOTHING except target_root!
        if (selectedLeadIds.length === 0) {
            this.cy.nodes().hide();
            this.cy.edges().hide();
            const rootNode = this.cy.getElementById('target_root');
            if (rootNode.length > 0) rootNode.show();
            this.visibleLeadNodes = new Set(['target_root']);
            return;
        }"""

replacement = """        // Rule: When NO leads are selected (default upon DB load), render NOTHING except target_root!
        if (selectedLeadIds.length === 0) {
            this.cy.nodes().hide();
            this.cy.edges().hide();
            const rootNode = this.cy.getElementById('target_root');
            if (rootNode.length > 0) {
                rootNode.show();
                if (options.relayout !== false) {
                    this.cy.animate({
                        center: { eles: rootNode },
                        zoom: 1.2
                    }, { duration: 500 });
                }
            }
            this.visibleLeadNodes = new Set(['target_root']);
            return;
        }"""

js = js.replace(target, replacement)

with open("web/static/js/graph.js", "w") as f:
    f.write(js)
