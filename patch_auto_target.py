import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

target = """            console.log(`✓ Created ${this.leads.length} leads total (preserveSelection: ${preserveSelection})`);
            console.log('=== LEAD SELECTOR DEBUG END ===');
            
            // Always try to render, even if we have 0 leads
            this.renderLeadSelector();
            
        } catch (error) {"""

replacement = """            console.log(`✓ Created ${this.leads.length} leads total (preserveSelection: ${preserveSelection})`);
            console.log('=== LEAD SELECTOR DEBUG END ===');
            
            // Auto-Target Logic for small datasets:
            // Exactly matching what is listed in the Lead Selector!
            if (!this._hasAutoTargeted && this.leads.length > 0 && this.leads.length <= 50) {
                console.log(`Auto-targeting ${this.leads.length} leads...`);
                this._hasAutoTargeted = true;
                const leadNames = this.leads.map(l => l.name || l.display_name).filter(Boolean);
                
                // We shouldn't wait for this here since we're in the middle of a render cycle,
                // so we just fire and forget. setTargetsBulk will reload the graph.
                setTimeout(() => {
                    if (typeof this.setTargetsBulk === 'function') {
                        this.setTargetsBulk(leadNames).catch(e => console.error('Auto-target failed', e));
                    }
                }, 100);
            } else {
                // If it's over 50, or 0, or we already auto-targeted, just mark as done so we don't try again
                this._hasAutoTargeted = true;
            }
            
            // Always try to render, even if we have 0 leads
            this.renderLeadSelector();
            
        } catch (error) {"""

content = content.replace(target, replacement)

# Bump version in index.html
with open("web/static/index.html", "r") as f:
    index_content = f.read()
    
index_content = re.sub(r"graph\.js\?v=\d+", "graph.js?v=64", index_content)

with open("web/static/index.html", "w") as f:
    f.write(index_content)
    
with open("web/static/js/graph.js", "w") as f:
    f.write(content)
