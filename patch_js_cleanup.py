import re

with open("web/static/js/graph.js", "r") as f:
    js = f.read()

target = """                action: () => {
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
                            if (cb.id) cb.id = 'modal_' + cb.id;
                            
                            cb.addEventListener('change', (e) => {
                                const leadItem = e.target.closest('.lead-item');
                                if (!leadItem) return;
                                const leadId = leadItem.dataset.leadId;
                                window.toggleLeadVisibility(leadId, e.target.checked);
                                // Also update the original sidebar checkbox to keep them in sync
                                const originalCb = originalList.querySelector(`[data-lead-id="${leadId}"] .lead-checkbox-input`);
                                if (originalCb) originalCb.checked = e.target.checked;
                            });
                        });
                        
                        // Make entire items clickable
                        const leadItems = clone.querySelectorAll('.lead-item');
                        leadItems.forEach(item => {
                            item.addEventListener('click', (e) => {
                                if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'LABEL') {
                                    const cb = item.querySelector('.lead-checkbox-input');
                                    if (cb) {
                                        cb.checked = !cb.checked;
                                        window.toggleLeadVisibility(item.dataset.leadId, cb.checked);
                                        const originalCb = originalList.querySelector(`[data-lead-id="${item.dataset.leadId}"] .lead-checkbox-input`);
                                        if (originalCb) originalCb.checked = cb.checked;
                                    }
                                }
                            });
                        });
                        
                        content.appendChild(clone);
                        modal.style.display = 'flex';
                        this.hideContextMenu();
                    }
                }"""

replacement = """                action: () => {
                    const modal = document.getElementById('floating-leads-modal');
                    if (modal) {
                        modal.style.display = 'flex';
                        this.hideContextMenu();
                    }
                }"""

js = js.replace(target, replacement)

with open("web/static/js/graph.js", "w") as f:
    f.write(js)
