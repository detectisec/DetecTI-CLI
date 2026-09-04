import re

path = "utils/setup.py"
with open(path, "r") as f:
    content = f.read()

# Add a helper function inside try block or just above the prompt
helper = '''
            def update_env_jwt(password: str):
                import hashlib
                import re
                jwt_secret = hashlib.sha256(password.encode('utf-8')).hexdigest()
                env_path = self.root_dir / ".env"
                if env_path.exists():
                    with open(env_path, "r") as f:
                        env_content = f.read()
                    if "JWT_SECRET_KEY=" in env_content:
                        env_content = re.sub(r'JWT_SECRET_KEY=.*', f'JWT_SECRET_KEY={jwt_secret}', env_content)
                    else:
                        if env_content and not env_content.endswith("\\n"):
                            env_content += "\\n"
                        env_content += f'JWT_SECRET_KEY={jwt_secret}\\n'
                    with open(env_path, "w") as f:
                        f.write(env_content)
                else:
                    with open(env_path, "w") as f:
                        f.write(f'JWT_SECRET_KEY={jwt_secret}\\n')
'''

# We need to insert this helper inside the `try:` block of Step 0.
old_try = r'''        try:
            import getpass
            import sys'''
new_try = '''        try:
            import getpass
            import sys''' + helper

content = re.sub(old_try, new_try, content)

# Now, we need to call `update_env_jwt(pwd1)` right after `update_user_password` or `create_user`.
content = content.replace(
    'config_db.update_user_password("admin", get_password_hash(pwd1))',
    'config_db.update_user_password("admin", get_password_hash(pwd1))\n                            update_env_jwt(pwd1)'
)
content = content.replace(
    'config_db.create_user("admin", get_password_hash(pwd1))',
    'config_db.create_user("admin", get_password_hash(pwd1))\n                        update_env_jwt(pwd1)'
)

with open(path, "w") as f:
    f.write(content)
