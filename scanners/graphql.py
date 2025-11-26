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
            self.log_error(e)
        if result["enabled"]:
            await self._test_query_depth(result)
            await self._test_field_fuzzing(result)
        return result
    async def _test_query_depth(self, result: Dict):
        self.log("    [*] Testing GraphQL Query Depth...", "cyan")
        depth = 10
        query = "query { __schema { types { " * depth + "name" + " } } }" * depth + " }" * depth
        deep_query = """
        query {
          __schema {
            types {
              fields {
                type {
                  fields {
                    type {
                      fields {
                        type {
                          name
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        try:
            r = await self.client.post("/graphql/v1", json={"query": deep_query})
            if r.status_code == 200 and "errors" not in r.text:
                self.log("    [!] WARNING: Deep GraphQL query accepted (Potential DoS risk)", "yellow")
                result["risk"] = "HIGH"
                result["details"] += " | Deep Query Allowed"
        except Exception as e:
            self.log_error(e)
    async def _test_field_fuzzing(self, result: Dict):
        self.log("    [*] Testing GraphQL Field Fuzzing...", "cyan")
        fuzz_query = """
        query {
          __schema(name: "' OR 1=1 --") {
            types { name }
          }
        }
        """
        try:
            r = await self.client.post("/graphql/v1", json={"query": fuzz_query})
            if "syntax error" in r.text.lower() or "internal server error" in r.text.lower():
                 self.log("    [!] Potential Injection/Error in GraphQL arguments", "bold red")
                 result["risk"] = "HIGH"
        except Exception as e:
            self.log_error(e)