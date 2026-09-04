import re

path = "utils/setup.py"
with open(path, "r") as f:
    content = f.read()

old_code = r'''        self\.console\.print\("\\n\[bold cyan\]🚀 Starting DetecTI-CLI Automated Environment Setup\.\.\.\[/bold cyan\]\\n"\)

        all_success = True

        # Step 1: Create Directories'''

new_code = '''        self.console.print("\\n[bold cyan]🚀 Starting DetecTI-CLI Automated Environment Setup...[/bold cyan]\\n")

        all_success = True

        # Step 0: Dashboard Admin Password Setup
        self.console.print("🔐 [bold white]Step 0/7: Configuring DetecTIHound Dashboard Admin...[/bold white]")
        try:
            import getpass
            import sys
            import os
            sys.path.insert(0, str(self.root_dir))
            from core.database.config_db import ConfigDBManager, get_password_hash
            
            db_dir = self.root_dir / "data" / "dbs"
            db_dir.mkdir(parents=True, exist_ok=True)
            config_db = ConfigDBManager(db_dir / "config.sqlite")
            
            if config_db.user_exists("admin"):
                change = self.console.input("  [yellow]Admin user already exists. Do you want to change the password? (y/N): [/yellow]").strip().lower()
                if change == 'y':
                    while True:
                        pwd1 = getpass.getpass("  Enter new password for 'admin': ")
                        pwd2 = getpass.getpass("  Confirm new password: ")
                        if pwd1 == pwd2 and len(pwd1) >= 4:
                            config_db.update_user_password("admin", get_password_hash(pwd1))
                            self.console.print("  [green]✔ Admin password updated successfully.[/green]")
                            break
                        elif len(pwd1) < 4:
                            self.console.print("  [red]Password must be at least 4 characters.[/red]")
                        else:
                            self.console.print("  [red]Passwords do not match. Try again.[/red]")
                else:
                    self.console.print("  [green]✔ Admin configuration skipped.[/green]")
            else:
                self.console.print("  [cyan]Creating default 'admin' user for the web dashboard.[/cyan]")
                while True:
                    pwd1 = getpass.getpass("  Enter password for 'admin': ")
                    pwd2 = getpass.getpass("  Confirm password: ")
                    if pwd1 == pwd2 and len(pwd1) >= 4:
                        config_db.create_user("admin", get_password_hash(pwd1))
                        self.console.print("  [green]✔ Admin user created successfully.[/green]")
                        break
                    elif len(pwd1) < 4:
                        self.console.print("  [red]Password must be at least 4 characters.[/red]")
                    else:
                        self.console.print("  [red]Passwords do not match. Try again.[/red]")
        except Exception as e:
            self.console.print(f"  [red]⚠ Failed to configure admin: {e}[/red]")
            import traceback
            traceback.print_exc()

        # Step 1: Create Directories'''

content = re.sub(old_code, new_code, content)

# Also update the step counts from 6 to 7
content = content.replace("Step 1/6", "Step 1/7")
content = content.replace("Step 2/6", "Step 2/7")
content = content.replace("Step 3/6", "Step 3/7")
content = content.replace("Step 4/6", "Step 4/7")
content = content.replace("Step 5/6", "Step 5/7")
content = content.replace("Step 6/6", "Step 6/7")

with open(path, "w") as f:
    f.write(content)
