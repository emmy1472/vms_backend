# myproject/settings/__init__.py

import subprocess
import sys

def get_current_git_branch():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            text=True
        )
        return result.stdout.strip()
    except Exception:
        return None

branch = get_current_git_branch()

if branch == "prod":
    from .prod import *
elif branch == "dev":
    from .dev import *
else:
    print("⚠️  Unknown branch. Defaulting to development settings.")
    from .dev import *
