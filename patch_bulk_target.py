import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

# 1. Domains
target1 = """                const allDoms = Array.isArray(data.all_domains) ? data.all_domains : [];
                if (allDoms.length > 0) {
                    const domNames = allDoms.map(d => d.name);
                    const domListHtml = allDoms.map(d => {"""
replacement1 = """                const allDoms = Array.isArray(data.all_domains) ? data.all_domains : [];
                if (allDoms.length > 0) {
                    const domNames = allDoms.map(d => d.name);
                    const allMarked = domNames.length > 0 && domNames.every(name => this.isTargetMarked(name));
                    const domListHtml = allDoms.map(d => {"""
content = content.replace(target1, replacement1)

target1b = """<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(domNames).replace(/"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i></button>"""
replacement1b = """<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; color: ${allMarked ? '#ef4444' : '#00f0ff'}; border-color: ${allMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${allMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="event.stopPropagation(); window.dashboard.${allMarked ? 'removeTargetsBulk' : 'setTargetsBulk'}(${JSON.stringify(domNames).replace(/\"/g, '&quot;')})" title="${allMarked ? 'Remove all from Targets' : 'Set all items as Target'}"><i data-lucide="crosshair" class="badge-icon"></i></button>"""
content = content.replace(target1b, replacement1b)


# 2. Subdomains
target2 = """                const allSubs = Array.isArray(data.all_subdomains) ? data.all_subdomains : [];
                if (allSubs.length > 0) {
                    const subNames = allSubs.map(s => s.name);
                    const subListHtml = allSubs.map(s => {"""
replacement2 = """                const allSubs = Array.isArray(data.all_subdomains) ? data.all_subdomains : [];
                if (allSubs.length > 0) {
                    const subNames = allSubs.map(s => s.name);
                    const allMarked = subNames.length > 0 && subNames.every(name => this.isTargetMarked(name));
                    const subListHtml = allSubs.map(s => {"""
content = content.replace(target2, replacement2)

target2b = """<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(subNames).replace(/"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i></button>"""
replacement2b = """<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; color: ${allMarked ? '#ef4444' : '#00f0ff'}; border-color: ${allMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${allMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="event.stopPropagation(); window.dashboard.${allMarked ? 'removeTargetsBulk' : 'setTargetsBulk'}(${JSON.stringify(subNames).replace(/\"/g, '&quot;')})" title="${allMarked ? 'Remove all from Targets' : 'Set all items as Target'}"><i data-lucide="crosshair" class="badge-icon"></i></button>"""
content = content.replace(target2b, replacement2b)


# 3. IPs
target3 = """                const allIps = Array.isArray(data.all_ips) ? data.all_ips : [];
                if (allIps.length > 0) {
                    const ipStrings = allIps.map(item => item.ip);
                    const ipListHtml = allIps.map(item => {"""
replacement3 = """                const allIps = Array.isArray(data.all_ips) ? data.all_ips : [];
                if (allIps.length > 0) {
                    const ipStrings = allIps.map(item => item.ip);
                    const allMarked = ipStrings.length > 0 && ipStrings.every(ip => this.isTargetMarked(ip));
                    const ipListHtml = allIps.map(item => {"""
content = content.replace(target3, replacement3)

target3b = """<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(ipStrings).replace(/"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i></button>"""
replacement3b = """<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; color: ${allMarked ? '#ef4444' : '#00f0ff'}; border-color: ${allMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${allMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="event.stopPropagation(); window.dashboard.${allMarked ? 'removeTargetsBulk' : 'setTargetsBulk'}(${JSON.stringify(ipStrings).replace(/\"/g, '&quot;')})" title="${allMarked ? 'Remove all from Targets' : 'Set all items as Target'}"><i data-lucide="crosshair" class="badge-icon"></i></button>"""
content = content.replace(target3b, replacement3b)


# 4. Related Subdomains
target4 = """                if (relatedSubs.length > 0) {
                    const subNamesList = relatedSubs.map(s => s.name || s.label);
                    const subListHtml = relatedSubs.map((sub) => {"""
replacement4 = """                if (relatedSubs.length > 0) {
                    const subNamesList = relatedSubs.map(s => s.name || s.label);
                    const allMarked = subNamesList.length > 0 && subNamesList.every(name => this.isTargetMarked(name));
                    const subListHtml = relatedSubs.map((sub) => {"""
content = content.replace(target4, replacement4)

target4b = """<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(subNamesList).replace(/"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i></button>"""
replacement4b = """<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; color: ${allMarked ? '#ef4444' : '#00f0ff'}; border-color: ${allMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${allMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="event.stopPropagation(); window.dashboard.${allMarked ? 'removeTargetsBulk' : 'setTargetsBulk'}(${JSON.stringify(subNamesList).replace(/\"/g, '&quot;')})" title="${allMarked ? 'Remove all from Targets' : 'Set all items as Target'}"><i data-lucide="crosshair" class="badge-icon"></i></button>"""
content = content.replace(target4b, replacement4b)

with open("web/static/js/graph.js", "w") as f:
    f.write(content)

