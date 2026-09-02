import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

# Replace Root Domains Accordion
content = content.replace(
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 180, 216, 0.2); color: #00b4d8; border-color: rgba(0, 180, 216, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(domNames).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>''',
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(domNames).replace(/\"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i> Target All</button>\n                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 180, 216, 0.2); color: #00b4d8; border-color: rgba(0, 180, 216, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(domNames).replace(/\"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>'''
)

# Replace Root Subdomains Accordion
content = content.replace(
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(78, 205, 196, 0.2); color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(subNames).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>''',
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(subNames).replace(/\"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i> Target All</button>\n                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(78, 205, 196, 0.2); color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(subNames).replace(/\"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>'''
)

# Replace Root IPs Accordion
content = content.replace(
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(59, 130, 246, 0.2); color: #60a5fa; border-color: rgba(59, 130, 246, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(ipStrings).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>''',
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(ipStrings).replace(/\"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i> Target All</button>\n                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(59, 130, 246, 0.2); color: #60a5fa; border-color: rgba(59, 130, 246, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(ipStrings).replace(/\"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>'''
)

# Replace Domain Subdomains Accordion
content = content.replace(
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(78, 205, 196, 0.2); color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(subNamesList).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>''',
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(subNamesList).replace(/\"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i> Target All</button>\n                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(78, 205, 196, 0.2); color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(subNamesList).replace(/\"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>'''
)

# Replace Domain Resolved IPs Accordion (If it exists, check line 4709)
content = content.replace(
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(59, 130, 246, 0.2); color: #60a5fa; border-color: rgba(59, 130, 246, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(resIpStrings).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>''',
    '''<button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border-color: rgba(0, 240, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.setTargetsBulk(${JSON.stringify(resIpStrings).replace(/\"/g, '&quot;')})" title="Set all items as Target"><i data-lucide="crosshair" class="badge-icon"></i> Target All</button>\n                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(59, 130, 246, 0.2); color: #60a5fa; border-color: rgba(59, 130, 246, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(resIpStrings).replace(/\"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i> Copy</button>'''
)

with open("web/static/js/graph.js", "w") as f:
    f.write(content)
