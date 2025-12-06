from ssf.core.base import BaseScanner
from typing import Dict, Any
import httpx

class AuthMisconfigScanner(BaseScanner):
    async def scan(self) -> Dict[str, Any]:
        result = {"risk": "Low", "open_redirects": []}
        self.log("[*] Checking for Open Redirects in Auth...", "cyan")
        
        providers = ["google", "github", "gitlab", "bitbucket", "facebook", "azure"]
        evil_host = "http://evil.com"
        
        for provider in providers:
            url = f"/auth/v1/authorize?provider={provider}&redirect_to={evil_host}"
            try:
                r = await self.client.get(url, follow_redirects=False, timeout=5.0)
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get('location', '')
                    if evil_host in loc:
                         self.log(f"    [!!!] OPEN REDIRECT via {provider}: {loc}", "bold red on white")
                         result["open_redirects"].append({"provider": provider, "target": loc})
                         result["risk"] = "High"
            except Exception:
                pass
                
        return result
