path = "utils/setup.py"
with open(path, "r") as f:
    content = f.read()

content = content.replace(
    'self.console.print("\n[bold cyan]🚀 Starting DetecTI-CLI Automated Environment Setup...[/bold cyan]\n")',
    'self.console.print("\\n[bold cyan]🚀 Starting DetecTI-CLI Automated Environment Setup...[/bold cyan]\\n")'
)

with open(path, "w") as f:
    f.write(content)
