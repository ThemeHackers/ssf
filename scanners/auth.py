from typing import Dict, Any
from core.base import BaseScanner
class AuthScanner(BaseScanner):
    async def scan(self) -> Dict[str, Any]:
        self.log("[*] Checking for Auth Leaks...", "cyan")
        leaked_users = []
        try:
            r = await self.client.get("/rest/v1/auth/users", params={"select": "*", "limit": 10})
            if r.status_code == 200:
                users = r.json()
                if users:
                    leaked_users.extend(users)
                    self.log(f"    [!] LEAKED: auth.users table is public! ({len(users)} users found)", "bold red")
        except: pass
        try:
            r = await self.client.get("/rest/v1/auth/identities", params={"select": "*", "limit": 10})
            if r.status_code == 200:
                identities = r.json()
                if identities:
                    leaked_users.extend(identities) 
                    self.log(f"    [!] LEAKED: auth.identities table is public! ({len(identities)} identities found)", "bold red")
        except: pass
        if leaked_users:
            user_ids = set()
            for u in leaked_users:
                if "id" in u: user_ids.add(u["id"])
                if "user_id" in u: user_ids.add(u["user_id"])
            self.context["users"] = list(user_ids)
            if self.context["users"]:
                self.log(f"    [+] Captured {len(self.context['users'])} User IDs for context.", "green")
        return {
            "leaked": len(leaked_users) > 0,
            "count": len(leaked_users),
            "details": leaked_users[:5] 
        }