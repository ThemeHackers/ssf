from typing import Dict, Any
from core.base import BaseScanner
class GraphQLScanner(BaseScanner):
    async def scan(self) -> Dict[str, Any]:
        self.log_info("[*] Checking GraphQL Introspection...")
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
                self.log_warn("    [!] GraphQL Introspection is ENABLED!")
        except Exception as e:
            self.log_error(e)
        if result["enabled"]:
            await self._test_query_depth(result)
            await self._test_field_fuzzing(result)
        return result
    async def _test_query_depth(self, result: Dict):
        self.log_info("[*] Testing GraphQL Query Depth & Complexity...")
        
        queries = {
            "Deep Nested": """
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
            """,
            "Alias Overloading": """
            query {
              a: __schema { types { name } }
              b: __schema { types { name } }
              c: __schema { types { name } }
              d: __schema { types { name } }
              e: __schema { types { name } }
            }
            """,
            "Circular Fragment": """
            query {
              __schema {
                ...RecursiveFragment
              }
            }
            fragment RecursiveFragment on __Schema {
              types {
                ...RecursiveFragment
              }
            }
            """
        }

        for name, query in queries.items():
            try:
                r = await self.client.post("/graphql/v1", json={"query": query})
                if r.status_code == 200 and "errors" not in r.text:
                    self.log_risk(f"    [!] WARNING: {name} query accepted (Potential DoS risk)", "HIGH")
                    result["risk"] = "HIGH"
                    result["details"] += f" | {name} Allowed"
            except Exception as e:
                self.log_error(e)
    async def _test_field_fuzzing(self, result: Dict):
        self.log_info("[*] Testing GraphQL Field Fuzzing...")
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
                 self.log_risk("    [!] Potential Injection/Error in GraphQL arguments", "HIGH")
                 result["risk"] = "HIGH"
        except Exception as e:
            self.log_error(e)