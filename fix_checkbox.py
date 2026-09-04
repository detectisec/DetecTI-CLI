file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

# We need to remove the DOM sync loop at the end of applyLeadFilter.
import re
pattern = r"// Sync visual checkbox states for the modal based on what actually survived the rendering passes[\s\S]*?if \(!this\.searchTerm\) \{"

replacement = r"""if (!this.searchTerm) {"""

new_content = re.sub(pattern, replacement, content)

# Also ensure renderLeadSelector uses this.selectedLeads correctly.
with open(file_path, "w") as f:
    f.write(new_content)
print("Removed DOM sync loop")
