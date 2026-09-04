import re

path = "web/static/index.html"
with open(path, "r") as f:
    content = f.read()

# Add logout button above sidebar-footer
old_footer = r'                <!-- Sidebar Footer -->'
new_footer = '''                <div class="sidebar-logout" style="padding: 0 15px 15px 15px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); margin-bottom: 10px;">
                    <button id="btn-logout" class="action-btn" style="width: 100%; justify-content: center; background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3);">
                        <i data-lucide="log-out" class="ui-icon"></i> Terminate Session
                    </button>
                </div>

                <!-- Sidebar Footer -->'''

content = re.sub(old_footer, new_footer, content)

# Add inline script for logout logic before </body>
script = '''
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const logoutBtn = document.getElementById('btn-logout');
            if (logoutBtn) {
                logoutBtn.addEventListener('click', async () => {
                    logoutBtn.style.opacity = '0.5';
                    logoutBtn.innerHTML = '<i data-lucide="loader" class="ui-icon" style="animation: spin 1s linear infinite;"></i> Terminating...';
                    if (window.lucide) window.lucide.createIcons();
                    
                    try {
                        const response = await fetch('/api/v1/auth/logout', { method: 'POST' });
                        if (response.ok) {
                            window.location.reload();
                        } else {
                            alert('Failed to terminate session properly. Check backend.');
                        }
                    } catch (e) {
                        alert('Network error during logout.');
                    }
                    logoutBtn.style.opacity = '1';
                });
            }
        });
    </script>
'''

content = content.replace("</body>", script + "\n</body>")

with open(path, "w") as f:
    f.write(content)

