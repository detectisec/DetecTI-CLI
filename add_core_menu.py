import re

path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

# 1. Add core context menu event listener
old_cxttap = r'''        // Node Right-Click Handler: Custom Context Menu
        this\.cy\.on\('cxttap', 'node', \(event\) => \{'''

new_cxttap = '''        // Core (Canvas) Right-Click Handler
        this.cy.on('cxttap', 'core', (event) => {
            const originalEvent = event.originalEvent;
            if (originalEvent) {
                originalEvent.preventDefault();
                originalEvent.stopPropagation();
            }

            const cyContainer = document.getElementById('cy');
            const containerRect = cyContainer ? cyContainer.getBoundingClientRect() : { left: 0, top: 0 };
            const renderedPos = event.renderedPosition;
            const clientX = containerRect.left + (renderedPos ? renderedPos.x : (originalEvent ? originalEvent.clientX : 100));
            const clientY = containerRect.top + (renderedPos ? renderedPos.y : (originalEvent ? originalEvent.clientY : 100));

            this.showCoreContextMenu(clientX, clientY);
        });

        // Node Right-Click Handler: Custom Context Menu
        this.cy.on('cxttap', 'node', (event) => {'''

content = re.sub(old_cxttap, new_cxttap, content)

# 2. Add showCoreContextMenu method right before showContextMenu
old_method = r'''    showContextMenu\(node, x, y\) \{
        const menu = document\.getElementById\('cy-context-menu'\);'''

new_method = '''    showCoreContextMenu(x, y) {
        const menu = document.getElementById('cy-context-menu');
        if (!menu) return;

        // Build HTML for core context menu
        menu.innerHTML = `
            <div class="cy-context-menu-header" style="justify-content: center; background: rgba(15, 23, 42, 0.95); border-bottom: 1px solid rgba(255,255,255,0.05); border-radius: 6px 6px 0 0; padding: 10px;">
                <span class="node-title" style="font-size: 0.8rem; color: #94a3b8; font-weight: 500; letter-spacing: 0.5px;">CANVAS MENU</span>
            </div>
            
            <button type="button" class="cy-context-menu-item ctx-collapse-btn" data-action-id="ctx-action-explore-leads">
                <i data-lucide="compass" class="ui-icon" style="color: #60a5fa;"></i>
                <span style="color: #f8fafc; font-weight: 500;">Explore Leads...</span>
            </button>
            
            <div class="cy-context-menu-divider"></div>

            <button type="button" class="cy-context-menu-item ctx-collapse-btn" data-action-id="ctx-action-expand-all">
                <i data-lucide="layers" class="ui-icon" style="color: #4ecdc4;"></i>
                <span style="color: #f8fafc;">Target All Leads</span>
            </button>

            <button type="button" class="cy-context-menu-item ctx-collapse-btn" data-action-id="ctx-action-fit-graph">
                <i data-lucide="maximize" class="ui-icon" style="color: #a78bfa;"></i>
                <span style="color: #f8fafc;">Fit Graph to Screen</span>
            </button>
        `;

        // Wire actions
        menu.querySelectorAll('.ctx-collapse-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.hideContextMenu();
                
                const actId = btn.getAttribute('data-action-id');
                if (actId === 'ctx-action-explore-leads') {
                    const modal = document.getElementById('floating-leads-modal');
                    if (modal) modal.style.display = 'flex';
                } else if (actId === 'ctx-action-expand-all') {
                    this.selectAllLeads();
                } else if (actId === 'ctx-action-fit-graph') {
                    if (this.cy) this.cy.fit(null, 50);
                }
            });
        });

        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }

        // Adjust position
        menu.style.display = 'flex';
        menu.style.visibility = 'hidden';

        requestAnimationFrame(() => {
            const menuRect = menu.getBoundingClientRect();
            const maxX = window.innerWidth - menuRect.width - 12;
            const maxY = window.innerHeight - menuRect.height - 12;

            const posX = Math.max(10, Math.min(x, maxX));
            const posY = Math.max(10, Math.min(y, maxY));

            menu.style.left = `${posX}px`;
            menu.style.top = `${posY}px`;
            menu.style.visibility = 'visible';
        });

        this.contextMenuVisible = true;
    }

    showContextMenu(node, x, y) {
        const menu = document.getElementById('cy-context-menu');'''

content = re.sub(old_method, new_method, content)

with open(path, "w") as f:
    f.write(content)
