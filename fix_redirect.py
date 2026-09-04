import re

path = "web/static/login.html"
with open(path, "r") as f:
    content = f.read()

content = content.replace("window.location.href = '/';", "window.location.reload();")

with open(path, "w") as f:
    f.write(content)
