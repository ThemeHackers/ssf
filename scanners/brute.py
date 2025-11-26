import asyncio
from typing import List
from core.base import BaseScanner

from core.config import Wordlists

class BruteScanner(BaseScanner):
    def __init__(self, client, verbose=False, context=None):
        super().__init__(client, verbose, context)
        self.common_tables = Wordlists.tables

    async def scan(self) -> List[str]:
        self.log("[*] Starting table bruteforce...", "cyan")
        tasks = [self._check(t) for t in self.common_tables]
        results = [t for t in await asyncio.gather(*tasks) if t]
        if results:
            self.log(f"    [+] Discovered hidden tables: {', '.join(results)}", "bold red")
        return results

    async def _check(self, table: str) -> str:
        try:
            r = await self.client.head(f"/rest/v1/{table}")
            if r.status_code != 404: return table
        except Exception as e:
            self.log_error(e)
        return None