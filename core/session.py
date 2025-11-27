import httpx
from .config import TargetConfig
class SessionManager:
    def __init__(self, config: TargetConfig):
        self.config = config
        user_agent = "SupabaseAudit/3.0"
        
        if config.random_agent:
            import random
            import os
            
            ua_file = os.path.join(os.path.dirname(__file__), "data", "user_agents.txt")
            if os.path.exists(ua_file):
                with open(ua_file, "r") as f:
                    user_agents = [line.strip() for line in f if line.strip()]
            else:
                user_agents = [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
                ]
            user_agent = random.choice(user_agents)

        self.headers = {
            "apikey": config.key,
            "Authorization": f"Bearer {config.key}",
            "User-Agent": user_agent,
            "Content-Type": "application/json"
        }
    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            base_url=self.config.url,
            headers=self.headers,
            timeout=self.config.timeout,
            verify=False,
            proxy=self.config.proxy
        )
        self.client.config = self.config
        return self.client
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()