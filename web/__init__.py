"""DetecTI-CLI Web Server and Dashboard."""

from .server import create_app
from .process_manager import WebServerManager

__all__ = ["create_app", "WebServerManager"]
