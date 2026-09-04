import re

with open("web/static/index.html", "r") as f:
    html = f.read()

# 1. Remove search panel and lead selector panel from sidebar
search_and_lead_regex = re.compile(
    r"<!-- Search Box \(Above Lead Selector\) -->.*?<!-- Filters Accordion Panel -->",
    re.DOTALL
)
html = search_and_lead_regex.sub("<!-- Filters Accordion Panel -->", html)

# 2. Insert search box into canvas top left
graph_container_regex = re.compile(r'(<main class="graph-container">)')
search_in_canvas = """<main class="graph-container">
                <div class="canvas-search-container" style="position: absolute; top: 20px; left: 20px; z-index: 100; width: 350px; background: #1e1e2d; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); border: 1px solid #333; padding: 5px;">
                    <div class="search-group" style="margin: 0; background: transparent; border: none; box-shadow: none;">
                        <i data-lucide="search" class="ui-icon search-lead-icon"></i>
                        <input type="text" id="search-input" placeholder="Search nodes (IP, domain, CVE, port...)" class="search-input" style="background: rgba(0,0,0,0.2); color: #fff;">
                        <button id="clear-search" class="clear-btn" aria-label="Clear Search"><i data-lucide="x" class="ui-icon"></i></button>
                    </div>
                </div>"""
html = graph_container_regex.sub(search_in_canvas, html)

# 3. Modify floating-leads-modal to host the lead-list
old_modal_content = "<!-- Leads will be cloned here -->"
new_modal_content = """<div id="lead-list" class="lead-list">
                <div class="lead-loading">Fetching leads...</div>
            </div>"""
html = html.replace(old_modal_content, new_modal_content)

html = html.replace("v=72", "v=73")

with open("web/static/index.html", "w") as f:
    f.write(html)
