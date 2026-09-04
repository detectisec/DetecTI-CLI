import re

def patch():
    with open("AGY_CONTEXT.md", "r") as f:
        content = f.read()

    # Update Target Root line
    old_target_root = "| **Target Root** | Round-Rectangle | Purple (`#8C52FF`) • White border 2.5px | Root target query / anchor of scan. Embeds full DNS inventory (`all_domains`, `all_subdomains`). Protected from being set as direct scan target. |"
    new_target_root = "| **Target Root** | Squircle (1:1) w/ Terminal Icon | Purple (`#8C52FF`) • Neon Cyan border 3px | The root of the entire graph tree and the origin point from which the initial query was launched. Acts as the central scope anchor, synthesizing the entire attack surface structure in its metadata. Right-click to orchestrate Leads. |"
    content = content.replace(old_target_root, new_target_root)

    # Update Lead Selector section
    old_lead_selector = """- **Unchecked by Default (Clean Load):** When a database is loaded or switched, all checkboxes in the Lead Selector remain unchecked (`this.selectedLeads.clear()`) and canvas starts completely clean."""
    new_lead_selector = """- **Graph-First UX & Floating Modal:** The Lead Selector is no longer in the sidebar. It is now an interactive, translucent floating modal triggered by right-clicking the `target_root` node ("Explore Leads...").
- **Intelligent Auto-Select (< 50):** If the initial scan discovers a very small footprint (50 leads or less), the engine will preemptively select and render them all upon the first dashboard load, avoiding unnecessary manual clicks.
- **Unchecked by Default (> 50):** For larger footprints, the modal starts completely clean to prevent canvas clutter, allowing granular selection."""
    content = content.replace(old_lead_selector, new_lead_selector)

    # Update Search Nodes Indexing to mention HUD
    old_search = """### 8. 🔍 Search Nodes Indexing & FQDN Match Flow"""
    new_search = """### 8. 🔍 Search Nodes Indexing & FQDN Match Flow
- **Canvas HUD:** The Search component is now a floating HUD in the top-left of the canvas, maximizing tactical screen real estate."""
    content = content.replace(old_search, new_search)
    
    # Add note about Target Root persistence and Auto-Centering to Layout section
    old_layout = """### 10. 🌲 Hierarchical Left-to-Right (LR) Layout Engine"""
    new_layout = """### 10. 🌲 Hierarchical Left-to-Right (LR) Layout Engine
- **Target Root Persistence & Auto-Centering:** The `target_root` is permanently anchored to the canvas. If it becomes the only visible node (e.g. via "Collapse All" or unchecking all leads), the camera automatically zooms (1.2x) and animates smoothly to center it."""
    content = content.replace(old_layout, new_layout)

    with open("AGY_CONTEXT.md", "w") as f:
        f.write(content)

patch()
