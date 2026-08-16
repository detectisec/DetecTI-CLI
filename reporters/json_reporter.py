"""JSON Reporter for structured export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional
from core.models import ScanResult


class JSONReporter:
    """Exports ScanResult to structured JSON."""

    @staticmethod
    def generate(result: ScanResult, indent: int = 2) -> str:
        """Serialize ScanResult to formatted JSON string."""
        return result.model_dump_json(indent=indent)

    @classmethod
    def save(cls, result: ScanResult, output_path: Path | str, indent: int = 2) -> Path:
        """Save formatted JSON report to disk."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(result, indent=indent)
        path.write_text(content, encoding="utf-8")
        return path
