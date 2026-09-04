with open("web/static/index.html", "r") as f:
    html = f.read()

modal_html = """
    <!-- Floating Leads Modal -->
    <div id="floating-leads-modal" class="modal" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 450px; max-height: 80vh; background: #1e1e2d; border: 1px solid #333; border-radius: 8px; z-index: 10000; box-shadow: 0 10px 30px rgba(0,0,0,0.5); flex-direction: column;">
        <div style="padding: 15px; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; background: #252536; border-radius: 8px 8px 0 0;">
            <h3 style="margin: 0; color: #fff; font-size: 1.1rem; display: flex; align-items: center; gap: 8px;">
                <i data-lucide="compass" style="width: 18px; height: 18px; color: #00f0ff;"></i> Explore Leads
            </h3>
            <button id="close-floating-leads" style="background: none; border: none; color: #999; cursor: pointer; font-size: 1.5rem; line-height: 1;">&times;</button>
        </div>
        <div style="padding: 15px; border-bottom: 1px solid #333; display: flex; gap: 10px; background: #2a2a3c;">
            <button onclick="window.dashboard.selectAllLeads()" style="flex: 1; padding: 8px; background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 4px; cursor: pointer; font-weight: bold;">Expand All Leads</button>
            <button onclick="window.dashboard.deselectAllLeads()" style="flex: 1; padding: 8px; background: rgba(255, 255, 255, 0.05); color: #ccc; border: 1px solid #444; border-radius: 4px; cursor: pointer;">Collapse All</button>
        </div>
        <div id="floating-leads-content" style="padding: 15px; overflow-y: auto; flex: 1;">
            <!-- Leads will be cloned here -->
        </div>
    </div>
"""

# Inject before </body>
html = html.replace("</body>", modal_html + "\n</body>")
html = html.replace("v=70", "v=71")

with open("web/static/index.html", "w") as f:
    f.write(html)
