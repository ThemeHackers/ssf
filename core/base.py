from abc import ABC, abstractmethod
import httpx
from rich.console import Console
from typing import Dict, Any
class BaseScanner(ABC):
    def __init__(self, client: httpx.AsyncClient, verbose: bool = False, context: Dict[str, Any] = None):
        self.client = client
        self.verbose = verbose
        self.console = Console()
        self.context = context if context is not None else {}
    @abstractmethod
    async def scan(self) -> Any:
        """
        Execute the scan logic and return the results.
        The return type can be a Dict, List, or any structure suitable for the report.
        """
        pass
    def log(self, message: str, style: str = ""):
        """Helper for verbose logging"""
        if self.verbose:
            self.console.print(f"[{style}]{message}[/{style}]" if style else message)
