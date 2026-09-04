import re

with open("web/static/js/graph.js", "r") as f:
    js = f.read()

target1 = """        // Background click handler (close inspector, context menu & unselect nodes)
        this.cy.on('tap', (event) => {
            this.hideContextMenu();
            if (event.target === this.cy) {
                this.cy.edges('edge[label="RESOLVES_TO"]').removeClass('ghost-active');
                this.cy.nodes().removeClass('cy-selected').unselect();
                this.closeInspector();
            }
        });"""

replacement1 = """        // Background click handler (close inspector, context menu & unselect nodes)
        this.cy.on('tap', (event) => {
            this.hideContextMenu();
            
            // Close the floating leads modal if clicking anywhere on the graph
            const floatingModal = document.getElementById('floating-leads-modal');
            if (floatingModal) floatingModal.style.display = 'none';

            if (event.target === this.cy) {
                this.cy.edges('edge[label="RESOLVES_TO"]').removeClass('ghost-active');
                this.cy.nodes().removeClass('cy-selected').unselect();
                this.closeInspector();
            }
        });"""

js = js.replace(target1, replacement1)

with open("web/static/js/graph.js", "w") as f:
    f.write(js)

target2 = """        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideContextMenu();
                this.closeInspector();
                this.cy.nodes().removeClass('cy-selected').unselect();
            }
        });"""

replacement2 = """        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideContextMenu();
                this.closeInspector();
                this.cy.nodes().removeClass('cy-selected').unselect();
                const floatingModal = document.getElementById('floating-leads-modal');
                if (floatingModal) floatingModal.style.display = 'none';
            }
        });"""

with open("web/static/js/graph.js", "r") as f:
    js = f.read()

js = js.replace(target2, replacement2)

with open("web/static/js/graph.js", "w") as f:
    f.write(js)
