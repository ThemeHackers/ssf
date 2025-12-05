from typing import Dict, Any
from ssf.core.base import BaseScanner

class TemplateScanner(BaseScanner):
    """
    Template for creating new plugins.
    Rename this class and file to create your own scanner.
    """
    async def scan(self) -> Dict[str, Any]:

        return {"template_scan": "completed"}
