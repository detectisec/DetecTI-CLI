import re

with open("web/static/index.html", "r") as f:
    html = f.read()

modal_html = """
    <!-- Floating Leads Modal -->
    <div id="floating-leads-modal" class="modal" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 450px; max-height: 80vh; background: #1e1e2d; border: 1px solid #333; border-radius: 8px; z-index: 10000; box-shadow: 0 10px 30px rgba(0,0,0,0.5); flex-direction: column;">
        <div style="padding: 15px; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; background: #252536; border-radius: 8px 8px 0 0;">
            <h3 style="margin: 0; color: #fff; font-size: 1.1rem; display: flex; align-items: center; gap: 8px;">
                <i data-lucide="compass" style="width: 18px; height: 18px; color: #00f0ff;"></i> Explore Leads
            </h3>
            <button id="close-floating-leads" style="background: none; border: none; color: #999; cursor: pointer; font-size: 1.5rem; line-height: 1;">&times;</button>
        </div>
        <div style="padding: 15px; border-bottom: 1px solid #333; display: flex; gap: 10px; background: #2a2a3c;">
            <button onclick="window.dashboard.selectAllLeads()" style="flex: 1; padding: 8px; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 4px; cursor: pointer; font-weight: bold;">Expand All Leads</button>
            <button onclick="window.dashboard.deselectAllLeads()" style="flex: 1; padding: 8px; background: rgba(255, 255, 255, 0.05); color: #ccc; border: 1px solid #444; border-radius: 4px; cursor: pointer;">Collapse All</button>
        </div>
        <div id="floating-leads-content" style="padding: 15px; overflow-y: auto; flex: 1;">
            <!-- Leads will be cloned here -->
        </div>
    </div>
    
    <!-- Scripts -->"""

html = html.replace("    <!-- Scripts -->", modal_html)

with open("web/static/index.html", "w") as f:
    f.write(html)


with open("web/static/js/graph.js", "r") as f:
    js = f.read()

target_ctx = """        if (data.is_cluster || nodeType === 'cluster_services' || nodeType === 'cluster_vulns') {"""
replacement_ctx = """        if (nodeId === 'target_root') {
            collapseActions.push({
                id: 'ctx-action-explore-leads',
                label: 'Explore Leads...',
                icon: 'compass',
                disabled: false,
                action: () => {
                    const modal = document.getElementById('floating-leads-modal');
                    const content = document.getElementById('floating-leads-content');
                    const originalList = document.getElementById('lead-list');
                    if (modal && content && originalList) {
                        content.innerHTML = '';
                        // Clone the original lead list to show in the modal
                        const clone = originalList.cloneNode(true);
                        clone.id = 'modal-lead-list';
                        
                        // Fix checkboxes in the clone to update the original selection
                        const checkboxes = clone.querySelectorAll('.lead-checkbox-input');
                        checkboxes.forEach(cb => {
                            cb.addEventListener('change', (e) => {
                                window.toggleLeadVisibility(e.target.dataset.id, e.target.checked);
                                // Also update the original sidebar checkbox to keep them in sync
                                const originalCb = originalList.querySelector(`.lead-checkbox-input[data-id="${e.target.dataset.id}"]`);
                                if (originalCb) originalCb.checked = e.target.checked;
                            });
                        });
                        
                        content.appendChild(clone);
                        modal.style.display = 'flex';
                        this.hideContextMenu();
                    }
                }
            });
            collapseActions.push({
                id: 'ctx-action-expand-all',
                label: 'Expand All Leads',
                icon: 'layers',
                disabled: false,
                action: () => {
                    this.selectAllLeads();
                    this.hideContextMenu();
                }
            });
        }
        
        if (data.is_cluster || nodeType === 'cluster_services' || nodeType === 'cluster_vulns') {"""
js = js.replace(target_ctx, replacement_ctx)

target_init = """        const closeInspectorBtn = document.getElementById('close-inspector');"""
replacement_init = """        const closeFloatingLeads = document.getElementById('close-floating-leads');
        if (closeFloatingLeads) {
            closeFloatingLeads.addEventListener('click', () => {
                document.getElementById('floating-leads-modal').style.display = 'none';
            });
        }

        const closeInspectorBtn = document.getElementById('close-inspector');"""
js = js.replace(target_init, replacement_init)

with open("web/static/js/graph.js", "w") as f:
    f.write(js)
