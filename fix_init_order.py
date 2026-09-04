import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_init = r'''            // Load and render graph
            console\.log\('Loading graph data\.\.\.'\);
            await this\.loadGraph\(\);
            
            // Setup event listeners
            console\.log\('Setting up event listeners\.\.\.'\);
            this\.setupEventListeners\(\);

            // Setup Target Management & Load Targets
            console\.log\('Setting up Target Management\.\.\.'\);
            this\.setupTargetManagement\(\);
            await this\.loadTargets\(\);'''

new_init = '''            // Setup Target Management & Load Targets FIRST so markedTargets is populated
            console.log('Setting up Target Management...');
            this.setupTargetManagement();
            await this.loadTargets();

            // Load and render graph (now populateLeadSelector will see markedTargets)
            console.log('Loading graph data...');
            await this.loadGraph();
            
            // Setup event listeners
            console.log('Setting up event listeners...');
            this.setupEventListeners();'''

content = re.sub(old_init, new_init, content)
with open(path, "w") as f:
    f.write(content)
