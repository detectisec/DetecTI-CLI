import re
with open("utils/setup.py", "r") as f:
    lines = f.readlines()

new_lines = []
skip = False
for line in lines:
    if "def update_env_jwt" in line:
        skip = True
        new_lines.append(line)
        new_lines.append("                import hashlib\n")
        new_lines.append("                import re\n")
        new_lines.append("                jwt_secret = hashlib.sha256(password.encode('utf-8')).hexdigest()\n")
        new_lines.append("                env_path = self.root_dir / '.env'\n")
        new_lines.append("                if env_path.exists():\n")
        new_lines.append("                    with open(env_path, 'r') as f:\n")
        new_lines.append("                        env_content = f.read()\n")
        new_lines.append("                    if 'JWT_SECRET_KEY=' in env_content:\n")
        new_lines.append("                        env_content = re.sub(r'JWT_SECRET_KEY=.*', f'JWT_SECRET_KEY={jwt_secret}', env_content)\n")
        new_lines.append("                    else:\n")
        new_lines.append("                        if env_content and not env_content.endswith('\\n'):\n")
        new_lines.append("                            env_content += '\\n'\n")
        new_lines.append("                        env_content += f'JWT_SECRET_KEY={jwt_secret}\\n'\n")
        new_lines.append("                    with open(env_path, 'w') as f:\n")
        new_lines.append("                        f.write(env_content)\n")
        new_lines.append("                else:\n")
        new_lines.append("                    with open(env_path, 'w') as f:\n")
        new_lines.append("                        f.write(f'JWT_SECRET_KEY={jwt_secret}\\n')\n")
        continue
    
    if skip:
        if line.strip() == "import os":
            skip = False
            new_lines.append(line)
    else:
        new_lines.append(line)

with open("utils/setup.py", "w") as f:
    f.writelines(new_lines)
