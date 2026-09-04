import re

path = "web/static/index.html"
with open(path, "r") as f:
    content = f.read()

# Remove the logout block from before sidebar-footer
logout_block = r'''                <div class="sidebar-logout" style="padding: 0 15px 15px 15px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); margin-bottom: 10px;">
                    <button id="btn-logout" class="action-btn" style="width: 100%; justify-content: center; background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3);">
                        <i data-lucide="log-out" class="ui-icon"></i> Terminate Session
                    </button>
                </div>\n\n'''
content = content.replace(logout_block, '')

# Inject it inside the sidebar footer instead
old_footer = r'''                <!-- Sidebar Footer -->
                <div class="sidebar-footer">'''

new_footer = '''                <!-- Sidebar Footer -->
                <div class="sidebar-footer">
                    <div class="sidebar-logout" style="padding-bottom: 15px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); margin-bottom: 15px;">
                        <button id="btn-logout" class="action-btn" style="width: 100%; justify-content: center; background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3);">
                            <i data-lucide="log-out" class="ui-icon"></i> Terminate Session
                        </button>
                    </div>'''

content = re.sub(old_footer, new_footer, content)

with open(path, "w") as f:
    f.write(content)
