"""DetecTI Intelligence: Modern Attack Surface Management & Threat Intelligence Engine."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure detecti-cli directory is always in sys.path
_pkg_root = str(Path(__file__).resolve().parent)
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

__version__ = "2.0.0"
__author__ = "Lucas S. (Ls4ss)"
