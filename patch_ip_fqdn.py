import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

target = """                    const isTarget = this.isTargetMarked(item.name);
                    const targetBtnStyle = isTarget 
                        ? 'background: rgba(0, 240, 255, 0.25); color: #00f0ff; border-color: #00f0ff;' 
                        : 'background: rgba(255, 255, 255, 0.05); color: var(--text-muted); border-color: rgba(255, 255, 255, 0.15);';
                    const targetBtnText = isTarget ? 'Targeted' : 'Target';

                    let focusBtn = '';"""

replacement = """                    const isTarget = this.isTargetMarked(item.name);
                    const targetBtnStyle = isTarget 
                        ? 'background: rgba(0, 240, 255, 0.25); color: #00f0ff; border-color: #00f0ff;' 
                        : 'background: rgba(255, 255, 255, 0.05); color: var(--text-muted); border-color: rgba(255, 255, 255, 0.15);';
                    const targetBtnText = '<i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>';

                    let focusBtn = '';"""

content = content.replace(target, replacement)
with open("web/static/js/graph.js", "w") as f:
    f.write(content)
