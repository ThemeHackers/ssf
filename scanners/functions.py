import asyncio
from typing import List, Dict
from core.base import BaseScanner
class EdgeFunctionScanner(BaseScanner):
    def __init__(self, client, verbose=False, context=None):
        super().__init__(client, verbose, context)
        self.common_functions = [
            "hello", "test", "auth", "user", "payment", "stripe", "webhook", 
            "email", "send-email", "notify", "openai", "ai", "search", "cron"
        ]
    async def scan(self) -> List[Dict]:
        self.log("[*] Enumerating Edge Functions...", "cyan")
        tasks = [self._check_function(name) for name in self.common_functions]
        results = await asyncio.gather(*tasks)
        found = [r for r in results if r]
        if found:
            names = ", ".join([f['name'] for f in found])
            self.log(f"    [!] Found Edge Functions: {names}", "bold red")
        return found
    async def _check_function(self, name: str) -> Dict:
        url = f"/functions/v1/{name}"
        try:
            r = await self.client.post(url, json={})
            if r.status_code != 404:
                return {
                    "name": name,
                    "status": r.status_code,
                    "url": url
                }
        except:
            pass
        return None
