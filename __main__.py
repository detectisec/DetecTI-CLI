"""Entry point for executing detecti-cli directly via `python -m detecti-cli` or `python /path/to/detecti-cli`."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
_pkg_root = str(Path(__file__).resolve().parent)
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

from cli import main

if __name__ == "__main__":
    main()
