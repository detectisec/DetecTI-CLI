"""Pytest configuration and environment setup."""

import os
import sys
from pathlib import Path

# Add project root and detecti-cli to sys.path
_root = Path(__file__).resolve().parent.parent
_detecti_cli = _root / "detecti-cli"

for path in [_detecti_cli, _root]:
    p_str = str(path)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)
