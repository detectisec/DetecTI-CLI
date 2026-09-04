import re

path = "web/api/auth.py"
with open(path, "r") as f:
    content = f.read()

new_secret = '''from dotenv import load_dotenv
load_dotenv()

# Secret key for JWT
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    # Emite um aviso ou falha se não houver chave (força rodar o setup)
    raise ValueError("JWT_SECRET_KEY is missing from environment/ .env file. Please run the setup command.")
'''

content = re.sub(r'# Secret key for JWT[\s\S]*?ALGORITHM = "HS256"', new_secret + 'ALGORITHM = "HS256"', content)

with open(path, "w") as f:
    f.write(content)
