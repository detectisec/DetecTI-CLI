path = "utils/setup.py"
with open(path, "r") as f:
    content = f.read()

content = content.replace('endswith("\\n"):', "endswith('\\n'):")
content = content.replace('endswith("', "endswith('\\n'")
# It's a mess. I'll just rewrite the helper properly.

import re
old_helper = re.search(r'def update_env_jwt.*?with open.*?\\n\'\)', content, re.DOTALL)
if old_helper:
    new_helper = """def update_env_jwt(password: str):
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
                        if env_content and not env_content.endswith('\\n'):
                            env_content += '\\n'
                        env_content += f'JWT_SECRET_KEY={jwt_secret}\\n'
                    with open(env_path, "w") as f:
                        f.write(env_content)
                else:
                    with open(env_path, "w") as f:
                        f.write(f'JWT_SECRET_KEY={jwt_secret}\\n')"""
    content = content.replace(old_helper.group(0), new_helper)

with open(path, "w") as f:
    f.write(content)
