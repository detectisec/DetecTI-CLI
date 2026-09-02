import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

# Root Domain Item
target1 = """                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${d.name}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i> ${isMarked ? 'Target' : 'Set Target'}
                                    </button>"""
replacement1 = """                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${d.name}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>
                                    </button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: #00b4d8; border-color: rgba(0, 180, 216, 0.4); background: rgba(0, 180, 216, 0.15);" onclick="event.stopPropagation(); window.dashboard.copyTextList('${d.name}', this)" title="Copy Domain">
                                        <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                                    </button>"""
content = content.replace(target1, replacement1)

# Root Subdomain Item
target2 = """                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${s.name}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i> ${isMarked ? 'Target' : 'Set Target'}
                                    </button>"""
replacement2 = """                                <div style="display: flex; gap: 4px; align-items: center;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${s.name}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>
                                    </button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4); background: rgba(78, 205, 196, 0.15);" onclick="event.stopPropagation(); window.dashboard.copyTextList('${s.name}', this)" title="Copy Subdomain">
                                        <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                                    </button>
                                </div>"""
# Note: For subdomains, the original didn't have the <div style="display: flex; gap: 4px; align-items: center;"> wrapping the button alone.
# Wait, let's check what the original sub_domain item looks like.
# It had <div style="display: flex; align-items: center; justify-content: space-between;"> wrapping the span and the button!
# So replacing just the button with a div wrapping the two buttons is correct.
content = content.replace(target2, replacement2)

# Root IP Item
target3 = """                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${item.ip}')" title="${isMarked ? 'Remove Target' : 'Set as Target (IP)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i> ${isMarked ? 'Target' : 'Set Target'}
                                    </button>"""
replacement3 = """                                <div style="display: flex; gap: 4px; align-items: center;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${item.ip}')" title="${isMarked ? 'Remove Target' : 'Set as Target (IP)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>
                                    </button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: #60a5fa; border-color: rgba(59, 130, 246, 0.4); background: rgba(59, 130, 246, 0.15);" onclick="event.stopPropagation(); window.dashboard.copyTextList('${item.ip}', this)" title="Copy IP">
                                        <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                                    </button>
                                </div>"""
content = content.replace(target3, replacement3)

# Domain Subdomain Item
target4 = """                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${subName}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i> ${isMarked ? 'Target' : 'Set Target'}
                                    </button>"""
replacement4 = """                                <div style="display: flex; gap: 4px; align-items: center;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${subName}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>
                                    </button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4); background: rgba(78, 205, 196, 0.15);" onclick="event.stopPropagation(); window.dashboard.copyTextList('${subName}', this)" title="Copy Subdomain">
                                        <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                                    </button>
                                </div>"""
content = content.replace(target4, replacement4)

with open("web/static/js/graph.js", "w") as f:
    f.write(content)

