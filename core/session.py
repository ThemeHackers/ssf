import httpx
from .config import TargetConfig
class SessionManager:
    def __init__(self, config: TargetConfig):
        self.config = config
        self.headers = {
            "apikey": config.key,
            "Authorization": f"Bearer {config.key}",
            "User-Agent": "SupabaseAudit/3.0",
            "Content-Type": "application/json"
        }
    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            base_url=self.config.url,
            headers=self.headers,
            timeout=self.config.timeout,
            verify=False
        )
        return self.client
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()