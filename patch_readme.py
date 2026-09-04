import re

path = "README.md"
with open(path, "r") as f:
    content = f.read()

# 1. Update Setup
setup_target = r'''# Run automated setup \(verifies prerequisites, directories, dependencies, and capabilities\)
\./detecti-cli setup'''
setup_replacement = '''# Run automated setup
# (Verifies prerequisites, installs dependencies, configures capabilities, 
# and sets up your secure Web Dashboard admin credentials)
./detecti-cli setup'''
content = re.sub(setup_target, setup_replacement, content)

# 2. Update Dashboard highlights
dashboard_target = r'''#### 🌟 Web Dashboard & Cytoscape Graph Highlights:'''
dashboard_replacement = '''#### 🌟 Web Dashboard & Cytoscape Graph Highlights:
- **🔒 Secure Authentication (JWT)**: Fully protected dashboard interface. The initial `./detecti-cli setup` step prompts for an admin password and derives a unique, persistent `JWT_SECRET_KEY` into your local `.env`. Features automatic 30-minute session expiration, HttpOnly secure cookies, and full backend API route protection.
- **Dynamic Database Switcher**:'''
# Need to make sure we replace the right section
if '- **Dynamic Database Switcher**:' not in dashboard_replacement:
    pass # handled below

content = content.replace("#### 🌟 Web Dashboard & Cytoscape Graph Highlights:", "#### 🌟 Web Dashboard & Cytoscape Graph Highlights:\n- **🔒 Secure Authentication (JWT)**: Fully protected dashboard access. The `./detecti-cli setup` securely generates a persistent `JWT_SECRET_KEY` in your `.env` derived from your admin password. Includes 30-minute HttpOnly cookie expiration and explicit Session Termination controls.")

with open(path, "w") as f:
    f.write(content)
