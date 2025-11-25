from typing import Dict, Any
from core.base import BaseScanner
class GraphQLScanner(BaseScanner):
    async def scan(self) -> Dict[str, Any]:
        self.log("[*] Checking GraphQL Introspection...", "cyan")
        query = """
        query {
          __schema {
            types {
              name
              kind
            }
          }
        }
        """
        result = {"enabled": False, "risk": "SAFE", "details": None}
        try:
            r = await self.client.post("/graphql/v1", json={"query": query})
            if r.status_code == 200 and "__schema" in r.text:
                result["enabled"] = True
                result["risk"] = "MEDIUM" 
                result["details"] = "Introspection Enabled (Schema Leak)"
                self.log("    [!] GraphQL Introspection is ENABLED!", "bold yellow")
        except Exception as e:
            self.log(f"    [!] GraphQL check error: {e}", "red")
        return result
