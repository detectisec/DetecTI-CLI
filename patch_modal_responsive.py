import re

with open("web/static/index.html", "r") as f:
    html = f.read()

target = """<div id="floating-leads-modal" class="modal" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 450px; max-height: 80vh; background: #1e1e2d; border: 1px solid #333; border-radius: 8px; z-index: 10000; box-shadow: 0 10px 30px rgba(0,0,0,0.5); flex-direction: column;">"""

replacement = """<div id="floating-leads-modal" class="modal" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 450px; max-width: 95vw; max-height: 80vh; background: #1e1e2d; border: 1px solid #333; border-radius: 8px; z-index: 10000; box-shadow: 0 10px 30px rgba(0,0,0,0.5); flex-direction: column;">"""

html = html.replace(target, replacement)
html = html.replace("v=74", "v=75")

with open("web/static/index.html", "w") as f:
    f.write(html)
