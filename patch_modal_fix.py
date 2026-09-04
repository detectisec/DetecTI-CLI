import re

with open("web/static/js/graph.js", "r") as f:
    js = f.read()

target = """                        // Fix checkboxes in the clone to update the original selection
                        const checkboxes = clone.querySelectorAll('.lead-checkbox-input');
                        checkboxes.forEach(cb => {
                            cb.addEventListener('change', (e) => {
                                window.toggleLeadVisibility(e.target.dataset.id, e.target.checked);
                                // Also update the original sidebar checkbox to keep them in sync
                                const originalCb = originalList.querySelector(`.lead-checkbox-input[data-id="${e.target.dataset.id}"]`);
                                if (originalCb) originalCb.checked = e.target.checked;
                            });
                        });"""

replacement = """                        // Fix checkboxes in the clone to update the original selection
                        const checkboxes = clone.querySelectorAll('.lead-checkbox-input');
                        checkboxes.forEach(cb => {
                            // Fix duplicate IDs
                            if (cb.id) cb.id = 'modal_' + cb.id;
                            
                            cb.addEventListener('change', (e) => {
                                const leadItem = e.target.closest('.lead-item');
                                if (!leadItem) return;
                                const leadId = leadItem.dataset.leadId;
                                window.toggleLeadVisibility(leadId, e.target.checked);
                            });
                        });
                        
                        // Also make the whole item clickable in the modal
                        const leadItems = clone.querySelectorAll('.lead-item');
                        leadItems.forEach(item => {
                            item.addEventListener('click', (e) => {
                                if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'LABEL') {
                                    const cb = item.querySelector('.lead-checkbox-input');
                                    if (cb) {
                                        cb.checked = !cb.checked;
                                        window.toggleLeadVisibility(item.dataset.leadId, cb.checked);
                                    }
                                }
                            });
                        });"""

js = js.replace(target, replacement)

with open("web/static/js/graph.js", "w") as f:
    f.write(js)
