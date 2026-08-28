"""Base module interface definition for DetecTI data collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from core.models import Finding
from utils.http import AsyncHTTPClient, http_client


class BaseModule(ABC):
    """Abstract Base Class for all DetecTI collection and enrichment modules."""

    name: str = "base_module"
    description: str = "Base collector module"
    category: str = "general"  # recon, osint, vuln, exploit

    def __init__(
        self,
        client: Optional[AsyncHTTPClient] = None,
        progress_callback: Optional[Any] = None,
    ):
        self.http_client = client or http_client
        self.progress_callback = progress_callback

    def notify(self, message: str) -> None:
        """Send notification via progress callback if registered."""
        if self.progress_callback:
            self.progress_callback(self.name, message)

    @abstractmethod
    async def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute the module logic against the target and return list of findings.

        Args:
            target: The input value (IP, domain, CIDR, query, CVE, or organization)
            context: Shared scan context or metadata passed between modules

        Returns:
            List of standardized Finding objects
        """
        pass

    def is_configured(self) -> bool:
        """Check if the module has all required configurations (e.g. API keys)."""
        return True

    async def health_check(self) -> bool:
        """Verify that the external data source is reachable and operational."""
        return True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} category={self.category}>"
